#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <atomic>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <filesystem>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <map>
#include <set>
#include <sqlite3.h>
#include <xxhash.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace fs = std::filesystem;

struct FileInfo {
    std::string path;
    std::string hash;
    std::int64_t size;
    std::int64_t mtime;
    bool operator==(const FileInfo& other) const {
        return path == other.path && 
               hash == other.hash && 
               size == other.size && 
               mtime == other.mtime;
    }
};

struct DirectoryMapping {
    std::string path;
    std::vector<std::string> exclude_patterns;
};

struct ManagedHost {
    std::string host;
    std::vector<DirectoryMapping> directories;
    std::chrono::seconds backoff_time{1};
    std::chrono::system_clock::time_point next_retry;
    bool is_responsive{true};
    bool slow_retry_mode{false};
    std::map<std::string, std::vector<FileInfo>> file_inventory;
    std::mutex inventory_mutex;
    static constexpr int MAX_BACKOFF_SECONDS = 3600;
    static constexpr int INITIAL_BACKOFF_SECONDS = 1;
    static constexpr int SLOW_RETRY_INTERVAL = 3600;
};

struct Config {
    std::vector<ManagedHost> hosts;
    std::string rsync_options = "-az --delete";
    std::string log_level = "info";
    bool daemon = false;
    std::string pid_file = "/var/run/sync_daemon.pid";
    std::string db_path = "/var/lib/sync_daemon/inventory.db";
    int poll_interval = 300;  // 5 minutes
    int consistency_check_interval = 3600;  // 1 hour
};

std::atomic<bool> g_running{true};

class InventoryDatabase {
public:
    InventoryDatabase(const std::string& db_path) {
        if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }
        init_tables();
    }

    ~InventoryDatabase() {
        if (db_) sqlite3_close(db_);
    }

    void update_inventory(const std::string& host, const std::string& dir,
                         const std::vector<FileInfo>& files) {
        const char* sql = "INSERT OR REPLACE INTO inventory "
                         "(host, directory, path, hash, size, mtime) "
                         "VALUES (?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement");
        }

        sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
        
        // First, delete old entries
        const char* del_sql = "DELETE FROM inventory WHERE host = ? AND directory = ?";
        sqlite3_stmt* del_stmt;
        sqlite3_prepare_v2(db_, del_sql, -1, &del_stmt, nullptr);
        sqlite3_bind_text(del_stmt, 1, host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(del_stmt, 2, dir.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(del_stmt);
        sqlite3_finalize(del_stmt);

        // Insert new entries
        for (const auto& file : files) {
            sqlite3_bind_text(stmt, 1, host.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, dir.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, file.path.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, file.hash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 5, file.size);
            sqlite3_bind_int64(stmt, 6, file.mtime);
            
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
                sqlite3_finalize(stmt);
                throw std::runtime_error("Failed to insert inventory");
            }
            sqlite3_reset(stmt);
        }

        sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
        sqlite3_finalize(stmt);
    }

    std::vector<FileInfo> get_inventory(const std::string& host, const std::string& dir) {
        std::vector<FileInfo> result;
        const char* sql = "SELECT path, hash, size, mtime FROM inventory "
                         "WHERE host = ? AND directory = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement");
        }

        sqlite3_bind_text(stmt, 1, host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, dir.c_str(), -1, SQLITE_STATIC);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            FileInfo info;
            info.path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            info.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            info.size = sqlite3_column_int64(stmt, 2);
            info.mtime = sqlite3_column_int64(stmt, 3);
            result.push_back(info);
        }

        sqlite3_finalize(stmt);
        return result;
    }

private:
    sqlite3* db_;

    void init_tables() {
        const char* sql = 
            "CREATE TABLE IF NOT EXISTS inventory ("
            "host TEXT,"
            "directory TEXT,"
            "path TEXT,"
            "hash TEXT,"
            "size INTEGER,"
            "mtime INTEGER,"
            "PRIMARY KEY (host, directory, path))";
        
        char* err_msg = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
            std::string error = err_msg;
            sqlite3_free(err_msg);
            throw std::runtime_error("Failed to create tables: " + error);
        }
    }
};

std::vector<FileInfo> get_remote_inventory(const std::string& host, 
                                         const DirectoryMapping& dir) {
    std::vector<FileInfo> inventory;
    
    // Build find command to get file list with metadata
    std::string exclude_patterns;
    for (const auto& pattern : dir.exclude_patterns) {
        exclude_patterns += " -not -path '" + pattern + "'";
    }
    
    std::string cmd = "ssh " + host + " \"cd '" + dir.path + "' && "
                     "find . -type f" + exclude_patterns + 
                     " -printf '%P\\t%s\\t%T@\\n'\"";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to execute remote command");
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        std::string path, size_str, mtime_str;
        std::istringstream iss(line);
        
        if (std::getline(iss, path, '\t') && 
            std::getline(iss, size_str, '\t') && 
            std::getline(iss, mtime_str)) {
            
            FileInfo info;
            info.path = path;
            info.size = std::stoll(size_str);
            info.mtime = std::stoll(mtime_str);
            
            // Get file hash
            std::string hash_cmd = "ssh " + host + " \"cd '" + dir.path + 
                                 "' && xxh64sum '" + path + "'\"";
            FILE* hash_pipe = popen(hash_cmd.c_str(), "r");
            if (hash_pipe) {
                char hash_buffer[128];
                if (fgets(hash_buffer, sizeof(hash_buffer), hash_pipe)) {
                    info.hash = std::string(hash_buffer, 16);  // First 16 chars are the hash
                }
                pclose(hash_pipe);
            }
            
            inventory.push_back(info);
        }
    }
    
    pclose(pipe);
    return inventory;
}

void sync_directories(ManagedHost& source, ManagedHost& target,
                     const DirectoryMapping& source_dir,
                     const DirectoryMapping& target_dir) {
    std::string cmd = "ssh " + source.host + " rsync " + 
                     Config::rsync_options + " '" + source_dir.path + "/' " +
                     target.host + ":'" + target_dir.path + "/'";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to execute sync command");
    }
    
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    
    int status = pclose(pipe);
    if (status != 0) {
        throw std::runtime_error("Sync failed: " + output);
    }
}

void check_and_sync_changes(ManagedHost& host, InventoryDatabase& db) {
    if (!host.is_responsive) {
        return;
    }

    for (const auto& dir : host.directories) {
        try {
            auto new_inventory = get_remote_inventory(host.host, dir);
            
            std::lock_guard<std::mutex> lock(host.inventory_mutex);
            auto& old_inventory = host.file_inventory[dir.path];
            
            // Compare inventories
            std::set<std::string> changed_files;
            for (const auto& file : new_inventory) {
                auto it = std::find_if(old_inventory.begin(), old_inventory.end(),
                    [&file](const FileInfo& old_file) {
                        return old_file.path == file.path;
                    });
                
                if (it == old_inventory.end() || !(*it == file)) {
                    changed_files.insert(file.path);
                }
            }
            
            if (!changed_files.empty()) {
                spdlog::info("Detected {} changed files on {}", 
                           changed_files.size(), host.host);
                
                // Update inventory in memory and database
                host.file_inventory[dir.path] = new_inventory;
                db.update_inventory(host.host, dir.path, new_inventory);
                
                // Sync changes to other hosts
                for (auto& other_host : Config::hosts) {
                    if (&other_host != &host && other_host.is_responsive) {
                        for (const auto& other_dir : other_host.directories) {
                            if (other_dir.path == dir.path) {
                                sync_directories(host, other_host, dir, other_dir);
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to check changes on {}: {}", host.host, e.what());
            host.is_responsive = false;
        }
    }
}

void consistency_check(std::vector<ManagedHost>& hosts, InventoryDatabase& db) {
    spdlog::info("Starting consistency check");
    
    for (auto& host : hosts) {
        if (!host.is_responsive) continue;
        
        for (const auto& dir : host.directories) {
            try {
                auto inventory = get_remote_inventory(host.host, dir);
                
                // Compare with other hosts
                for (auto& other_host : hosts) {
                    if (&other_host != &host && other_host.is_responsive) {
                        for (const auto& other_dir : other_host.directories) {
                            if (other_dir.path == dir.path) {
                                auto other_inventory = get_remote_inventory(
                                    other_host.host, other_dir);
                                
                                if (inventory != other_inventory) {
                                    spdlog::warn("Inconsistency detected between {} and {}", 
                                               host.host, other_host.host);
                                    sync_directories(host, other_host, dir, other_dir);
                                }
                            }
                        }
                    }
                }
                
                // Update inventory
                std::lock_guard<std::mutex> lock(host.inventory_mutex);
                host.file_inventory[dir.path] = inventory;
                db.update_inventory(host.host, dir.path, inventory);
                
            } catch (const std::exception& e) {
                spdlog::error("Consistency check failed for {}: {}", 
                            host.host, e.what());
            }
        }
    }
    
    spdlog::info("Consistency check completed");
}

int main(int argc, char* argv[]) {
    try {
        Config config = parse_arguments(argc, argv);
        
        if (config.daemon) {
            daemonize();
        }

        setup_logging();
        set_resource_limits();
        
        InventoryDatabase db(config.db_path);
        
        std::vector<std::thread> host_threads;
        auto last_consistency_check = std::chrono::steady_clock::now();
        
        for (auto& host : config.hosts) {
            // Start heartbeat/polling thread for each host
            host_threads.emplace_back([&host, &db, &config]() {
                while (g_running) {
                    if (host.is_responsive) {
                        check_and_sync_changes(host, db);
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(config.poll_interval));
                }
            });
        }
        
        // Start consistency check thread
        host_threads.emplace_back([&config, &db]() {
            while (g_running) {
                consistency_check(config.hosts, db);
                std::this_thread::sleep_for(
                    std::chrono::seconds(config.consistency_check_interval));
            }
        });
        
        for (auto& thread : host_threads) {
            thread.join();
        }
        
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }
} 
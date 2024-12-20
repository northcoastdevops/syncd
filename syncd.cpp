// sync_daemon.cpp

/*
Sample Configuration (sync_daemon.yaml):

'''yaml
# Host groups define sets of hosts that should be kept in sync with each other
host_groups:  # Required: List of host groups
  - hosts:    # Required: List of hosts in this group (minimum 1)
      - user@server1.example.com
      - user@server2.example.com
    
    directories:  # Required: List of directories to sync within this group (minimum 1)
      - local: /path/to/local/dir1    # Required: Path to local directory
        remote: /path/to/remote/dir1   # Required: Path on remote hosts
        sync_type: batch              # Optional: 'batch' or 'event' (default: batch)
        batch_interval: 300           # Optional: Seconds between batch syncs (default: 300)
        exclude:                      # Optional: Patterns to exclude
          - "*.tmp"
          - ".git"
          - "node_modules"
      
      - local: /path/to/local/dir2
        remote: /path/to/remote/dir2
        sync_type: event             # Use event-based (real-time) sync
        exclude:
          - "*.log"
          - "build/\*"

  # Another host group example
  - hosts:
      - user@server3.example.com
      - user@server4.example.com
    directories:
      - local: /path/to/local/dir3
        remote: /path/to/remote/dir3

# Global Settings (all optional)
unison_options: "-batch -prefer newer -times -perms 0 -auto -ui text"  # Default unison options
log_level: info       # Logging level: trace, debug, info, warn, error (default: info)
log_file: /var/log/sync_daemon.log  # Log file path
daemon: false         # Run as daemon (default: false)
noop: false          # Dry-run mode (default: false)
pid_file: /var/run/sync_daemon.pid  # PID file location

# Advanced Settings (all optional)
host_check_interval: 300            # Host connectivity check interval in seconds (default: 300)
consistency_check_interval: 3600   # Full consistency check interval in seconds (default: 3600)
'''

Configuration Notes:
1. sync_type options:
   - batch: Changes are synced periodically based on batch_interval (default)
   - event: Changes are synced in near real-time with a small batching window

2. batch_interval:
   - Only applies when sync_type is 'batch'
   - Default is 300 seconds (5 minutes)
   - Minimum recommended value is 60 seconds

3. Host Groups:
   - Each group maintains sync between all its hosts
   - A host can be in multiple groups
   - Each group must have at least one host and one directory

4. Security:
   - SSH keys should be properly configured for all hosts
   - Unison must be installed on all hosts
   - Remote paths must be accessible to the SSH user
*/

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
#include <cxxopts.hpp>
#include <filesystem>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <map>
#include <set>

// Platform-specific includes
#ifdef __APPLE__
    #include <CoreServices/CoreServices.h>
    #include <UserNotifications/UserNotifications.h>
#else
    #include <sys/inotify.h>
    #include <sqlite3.h>
    #include <xxhash.h>
    #include <nlohmann/json.hpp>
    using json = nlohmann::json;
#endif

namespace fs = std::filesystem;

// Add before RemoteDirectory struct
enum class SyncType {
    EVENT,  // Real-time event-based sync
    BATCH   // Batch-based periodic sync
};

// Common structures for both platforms
struct RemoteDirectory {
    std::string path;
    std::vector<std::string> exclude_patterns;
    SyncType sync_type{SyncType::BATCH};  // Default to batch-based
    std::chrono::seconds batch_interval{300};  // Default 5 minutes for batch mode
};

struct HostGroup {
    std::vector<std::string> hosts;
    std::vector<RemoteDirectory> directories;
    std::map<std::string, bool> host_responsive;  // Track responsiveness per host
    std::map<std::string, std::chrono::seconds> host_backoff_time;
    std::map<std::string, std::chrono::system_clock::time_point> host_next_retry;
    std::map<std::string, bool> host_slow_retry_mode;
    static constexpr int MAX_BACKOFF_SECONDS = 3600;  // 1 hour
    static constexpr int INITIAL_BACKOFF_SECONDS = 1;
    static constexpr int SLOW_RETRY_INTERVAL = 3600;  // 1 hour

#ifndef __APPLE__
    std::map<std::string, std::vector<FileInfo>> file_inventory;
    std::mutex inventory_mutex;
#endif

    // Initialize a new host in the group
    void add_host(const std::string& host) {
        hosts.push_back(host);
        host_responsive[host] = true;
        host_backoff_time[host] = std::chrono::seconds(INITIAL_BACKOFF_SECONDS);
        host_next_retry[host] = std::chrono::system_clock::now();
        host_slow_retry_mode[host] = false;
    }

    // Check if any host is responsive
    bool has_responsive_host() const {
        return std::any_of(hosts.begin(), hosts.end(),
            [this](const std::string& host) { return host_responsive.at(host); });
    }
};

struct Config {
    std::string config_path;
    bool daemon_mode;
    std::vector<HostGroup> host_groups;  // Changed from remote_hosts to host_groups
    std::string unison_options;
    std::string log_level;
    bool daemon{false};
    bool noop{false};
    std::string pid_file;
    std::string db_path;
    std::string log_file;
    std::chrono::seconds host_check_interval{300};  // Renamed from poll_interval
    std::chrono::seconds consistency_check_interval{3600};
};

// Platform-specific structures
#ifdef __APPLE__
struct FSEventContext {
    std::string path;
    std::mutex mutex;
    std::condition_variable cv;
    std::set<std::string> changed_paths;
    std::chrono::steady_clock::time_point last_event;
    std::chrono::steady_clock::time_point last_sync;
    bool has_changes{false};
    SyncType sync_type;
    std::chrono::seconds batch_interval;

    explicit FSEventContext(const std::string& dir, SyncType st, std::chrono::seconds bi) 
        : path(dir), sync_type(st), batch_interval(bi) {}
};
#else
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

class InventoryDatabase {
private:
    sqlite3* db;
    std::string db_path;
    std::mutex db_mutex;

public:
    explicit InventoryDatabase(const std::string& path) : db_path(path) {
        int rc = sqlite3_open(db_path.c_str(), &db);
        if (rc) {
            std::string error = sqlite3_errmsg(db);
            sqlite3_close(db);
            throw std::runtime_error("Can't open database: " + error);
        }

        // Create tables if they don't exist
        const char* sql = 
            "CREATE TABLE IF NOT EXISTS file_inventory ("
            "path TEXT PRIMARY KEY,"
            "hash TEXT NOT NULL,"
            "size INTEGER NOT NULL,"
            "mtime INTEGER NOT NULL"
            ");";

        char* err_msg = nullptr;
        rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::string error = err_msg;
            sqlite3_free(err_msg);
            sqlite3_close(db);
            throw std::runtime_error("SQL error: " + error);
        }
    }

    ~InventoryDatabase() {
        sqlite3_close(db);
    }

    void update_file(const FileInfo& file) {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        const char* sql = 
            "INSERT OR REPLACE INTO file_inventory (path, hash, size, mtime) "
            "VALUES (?, ?, ?, ?);";

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement: " + 
                                   std::string(sqlite3_errmsg(db)));
        }

        sqlite3_bind_text(stmt, 1, file.path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, file.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, file.size);
        sqlite3_bind_int64(stmt, 4, file.mtime);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            throw std::runtime_error("Failed to update file: " + 
                                   std::string(sqlite3_errmsg(db)));
        }
    }

    std::vector<FileInfo> get_all_files() {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::vector<FileInfo> files;
        
        const char* sql = "SELECT path, hash, size, mtime FROM file_inventory;";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement: " + 
                                   std::string(sqlite3_errmsg(db)));
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            FileInfo file;
            file.path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            file.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            file.size = sqlite3_column_int64(stmt, 2);
            file.mtime = sqlite3_column_int64(stmt, 3);
            files.push_back(file);
        }

        sqlite3_finalize(stmt);
        return files;
    }

    void remove_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        const char* sql = "DELETE FROM file_inventory WHERE path = ?;";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement: " + 
                                   std::string(sqlite3_errmsg(db)));
        }

        sqlite3_bind_text(stmt, 1, path.c_str(), -1, SQLITE_STATIC);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            throw std::runtime_error("Failed to remove file: " + 
                                   std::string(sqlite3_errmsg(db)));
        }
    }

    void clear() {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        const char* sql = "DELETE FROM file_inventory;";
        
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::string error = err_msg;
            sqlite3_free(err_msg);
            throw std::runtime_error("SQL error: " + error);
        }
    }
};
#endif

std::atomic<bool> g_running{true};

// Forward declarations
void execute_unison(const std::string& cmd, bool noop);
void manage_host_connectivity(HostGroup& host_group, const std::string& host);
void sync_to_remote(const RemoteDirectory& dir, HostGroup& host_group, 
                   const std::string& unison_options, bool noop);
Config parse_arguments(int argc, char* argv[]);
std::string expand_path(const std::string& path);
std::string resolve_path(const std::string& path, const std::string& config_path);

#ifdef __APPLE__
void FSEventsCallback(ConstFSEventStreamRef streamRef,
                     void* clientCallBackInfo,
                     size_t numEvents,
                     void* eventPaths,
                     const FSEventStreamEventFlags eventFlags[],
                     const FSEventStreamEventId eventIds[]) {
    try {
        auto* context = static_cast<FSEventContext*>(clientCallBackInfo);
        char** paths = static_cast<char**>(eventPaths);
        
        std::lock_guard<std::mutex> lock(context->mutex);
        bool significant_changes = false;
        
        for (size_t i = 0; i < numEvents; i++) {
            std::string path(paths[i]);
            
            // Filter out system files and temporary files
            if (path.find("/tmp/") != std::string::npos ||
                path.find("/.") != std::string::npos ||
                path.find("/.Trash") != std::string::npos ||
                path.find("/node_modules/") != std::string::npos ||
                path.find("/.git/") != std::string::npos) {
                continue;
            }
            
            // Check if the event is relevant
            if (eventFlags[i] & (kFSEventStreamEventFlagItemCreated |
                               kFSEventStreamEventFlagItemRemoved |
                               kFSEventStreamEventFlagItemRenamed |
                               kFSEventStreamEventFlagItemModified)) {
                context->changed_paths.insert(path);
                significant_changes = true;
            }
        }
        
        if (significant_changes) {
            context->has_changes = true;
            context->last_event = std::chrono::steady_clock::now();
            context->cv.notify_one();
        }
    } catch (const std::exception& e) {
        spdlog::error("Exception in FSEvents callback: {}", e.what());
    }
}

void monitor_directories(HostGroup& host_group, const std::string& unison_options, bool noop) {
    spdlog::info("Starting directory monitoring for host group ({} hosts, {} directories)", 
                 host_group.hosts.size(), host_group.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(host_group.directories.size());
    
    for (const auto& dir : host_group.directories) {
        if (!fs::exists(dir.path)) {
            spdlog::error("Directory does not exist: {}", dir.path);
            continue;
        }
        
        monitor_threads.emplace_back([&]() {
            try {
                FSEventContext context{dir.path, dir.sync_type, dir.batch_interval};
                context.last_sync = std::chrono::steady_clock::now();
                
                CFStringRef path = CFStringCreateWithCString(nullptr, dir.path.c_str(),
                                                           kCFStringEncodingUTF8);
                if (!path) {
                    throw std::runtime_error("Failed to create CFString for path");
                }
                
                CFArrayRef pathsToWatch = CFArrayCreate(nullptr,
                    reinterpret_cast<const void**>(&path), 1,
                    &kCFTypeArrayCallBacks);
                
                if (!pathsToWatch) {
                    CFRelease(path);
                    throw std::runtime_error("Failed to create paths array");
                }
                
                FSEventStreamContext streamContext = {0, &context, nullptr, nullptr, nullptr};
                
                FSEventStreamRef stream = FSEventStreamCreate(nullptr,
                    &FSEventsCallback,
                    &streamContext,
                    pathsToWatch,
                    kFSEventStreamEventIdSinceNow,
                    1.0,  // Increased latency for better batching (1 second)
                    kFSEventStreamCreateFlagFileEvents | 
                    kFSEventStreamCreateFlagNoDefer |
                    kFSEventStreamCreateFlagIgnoreSelf
                );
                
                if (!stream) {
                    CFRelease(pathsToWatch);
                    CFRelease(path);
                    throw std::runtime_error("Failed to create FSEvents stream");
                }
                
                FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
                
                if (!FSEventStreamStart(stream)) {
                    FSEventStreamInvalidate(stream);
                    FSEventStreamRelease(stream);
                    CFRelease(pathsToWatch);
                    CFRelease(path);
                    throw std::runtime_error("Failed to start FSEvents stream");
                }
                
                while (g_running) {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, true);
                    
                    std::unique_lock<std::mutex> lock(context.mutex);
                    auto now = std::chrono::steady_clock::now();
                    bool should_sync = false;
                    std::string sync_reason;

                    if (context.has_changes) {
                        if (context.sync_type == SyncType::EVENT &&
                            now - context.last_event >= std::chrono::seconds(2)) {
                            should_sync = true;
                            sync_reason = "event batch window reached";
                        } else if (context.sync_type == SyncType::BATCH &&
                                 now - context.last_sync >= context.batch_interval) {
                            should_sync = true;
                            sync_reason = "batch interval reached";
                        }
                    } else if (context.sync_type == SyncType::BATCH &&
                             now - context.last_sync >= context.batch_interval) {
                        should_sync = true;
                        sync_reason = "periodic batch check";
                    }

                    if (should_sync && host_group.has_responsive_host()) {
                        spdlog::debug("Processing sync ({}) with {} changes", 
                                    sync_reason, context.changed_paths.size());
                        sync_to_remote(dir, host_group, unison_options, noop);
                        context.last_sync = now;
                        context.changed_paths.clear();
                        context.has_changes = false;
                    }
                }
                
                FSEventStreamStop(stream);
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                CFRelease(pathsToWatch);
                CFRelease(path);
                
            } catch (const std::exception& e) {
                spdlog::error("Exception in directory monitoring thread: {}", e.what());
            }
        });
    }
    
    for (auto& thread : monitor_threads) {
        thread.join();
    }
}
#else
struct SyncBatch {
    std::chrono::steady_clock::time_point last_event;
    std::chrono::steady_clock::time_point last_sync;
    std::set<std::string> changed_paths;
    bool has_changes{false};
    static constexpr auto EVENT_BATCH_WINDOW = std::chrono::seconds(2); // Window for event-based
    std::mutex batch_mutex;  // Mutex for protecting batch data
};

void monitor_directories(HostGroup& host_group, const std::string& unison_options, bool noop) {
    spdlog::info("Starting directory monitoring for host group ({} hosts, {} directories)", 
                 host_group.hosts.size(), host_group.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(host_group.directories.size());
    
    for (const auto& dir : host_group.directories) {
        if (!fs::exists(dir.path)) {
            spdlog::error("Directory does not exist: {}", dir.path);
            continue;
        }
        
        monitor_threads.emplace_back([&]() {
            try {
                int inotify_fd = inotify_init1(IN_NONBLOCK);
                if (inotify_fd == -1) {
                    throw std::runtime_error("Failed to initialize inotify: " + 
                                          std::string(strerror(errno)));
                }
                
                std::map<int, std::string> watch_descriptors;
                std::map<std::string, int> path_to_wd;
                SyncBatch batch;
                batch.last_sync = std::chrono::steady_clock::now();
                
                // Add watches recursively for the directory
                std::function<void(const fs::path&)> add_watches = 
                [&](const fs::path& path) {
                    try {
                        for (const auto& entry : fs::recursive_directory_iterator(path)) {
                            if (fs::is_directory(entry)) {
                                int wd = inotify_add_watch(inotify_fd, 
                                                         entry.path().string().c_str(),
                                                         IN_MODIFY | IN_CREATE | IN_DELETE |
                                                         IN_MOVE | IN_MOVE_SELF);
                                if (wd == -1) {
                                    spdlog::warn("Failed to add watch for {}: {}", 
                                               entry.path().string(), strerror(errno));
                                    continue;
                                }
                                watch_descriptors[wd] = entry.path().string();
                                path_to_wd[entry.path().string()] = wd;
                            }
                        }
                    } catch (const fs::filesystem_error& e) {
                        spdlog::error("Failed to traverse directory {}: {}", 
                                    path.string(), e.what());
                    }
                };
                
                // Add initial watches
                add_watches(dir.path);
                
                const int BUF_LEN = (10 * (sizeof(struct inotify_event) + NAME_MAX + 1));
                std::vector<char> buffer(BUF_LEN);
                
                while (g_running) {
                    int length = read(inotify_fd, buffer.data(), buffer.size());
                    if (length > 0) {
                        int i = 0;
                        while (i < length) {
                            struct inotify_event* event = 
                                reinterpret_cast<struct inotify_event*>(&buffer[i]);
                            
                            if (event->len) {
                                std::string dir_path = watch_descriptors[event->wd];
                                if (!dir_path.empty()) {
                                    // Handle directory creation
                                    if (event->mask & IN_CREATE && (event->mask & IN_ISDIR)) {
                                        std::string new_dir = dir_path + "/" + event->name;
                                        add_watches(new_dir);
                                    }
                                    
                                    // Handle directory deletion
                                    if (event->mask & IN_DELETE && (event->mask & IN_ISDIR)) {
                                        std::string deleted_dir = dir_path + "/" + event->name;
                                        auto it = path_to_wd.find(deleted_dir);
                                        if (it != path_to_wd.end()) {
                                            watch_descriptors.erase(it->second);
                                            path_to_wd.erase(it);
                                        }
                                    }
                                    
                                    // Add to batch
                                    std::lock_guard<std::mutex> batch_lock(batch.batch_mutex);
                                    batch.changed_paths.insert(dir_path + "/" + event->name);
                                    batch.has_changes = true;
                                    batch.last_event = std::chrono::steady_clock::now();
                                }
                            }
                            i += sizeof(struct inotify_event) + event->len;
                        }
                    }
                    
                    auto now = std::chrono::steady_clock::now();
                    bool should_sync = false;
                    std::string sync_reason;

                    if (batch.has_changes) {
                        if (dir.sync_type == SyncType::EVENT &&
                            now - batch.last_event >= SyncBatch::EVENT_BATCH_WINDOW) {
                            should_sync = true;
                            sync_reason = "event batch window reached";
                        } else if (dir.sync_type == SyncType::BATCH &&
                                 now - batch.last_sync >= dir.batch_interval) {
                            should_sync = true;
                            sync_reason = "batch interval reached";
                        }
                    } else if (dir.sync_type == SyncType::BATCH &&
                             now - batch.last_sync >= dir.batch_interval) {
                        should_sync = true;
                        sync_reason = "periodic batch check";
                    }

                    if (should_sync) {
                        std::lock_guard<std::mutex> lock(host_group.inventory_mutex);
                        if (host_group.has_responsive_host()) {
                            spdlog::debug("Processing sync ({}) with {} changes", 
                                        sync_reason, batch.changed_paths.size());
                            sync_to_remote(dir, host_group, unison_options, noop);
                            batch.changed_paths.clear();
                            batch.has_changes = false;
                            batch.last_sync = now;
                        }
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                
                // Cleanup
                for (const auto& [wd, _] : watch_descriptors) {
                    inotify_rm_watch(inotify_fd, wd);
                }
                close(inotify_fd);
                
            } catch (const std::exception& e) {
                spdlog::error("Exception in directory monitoring thread: {}", e.what());
            }
        });
    }
    
    for (auto& thread : monitor_threads) {
        thread.join();
    }
}
#endif

// Common functions for both platforms
void sync_to_remote(const RemoteDirectory& dir, HostGroup& host_group, 
                   const std::string& unison_options, bool noop) {
    // Build exclude patterns for Unison
    std::string ignore_opts;
    for (const auto& pattern : dir.exclude_patterns) {
        ignore_opts += " -ignore 'Path " + pattern + "'";
    }

    // For each responsive host, sync with other responsive hosts
    for (size_t i = 0; i < host_group.hosts.size(); i++) {
        const std::string& source_host = host_group.hosts[i];
        if (!host_group.host_responsive[source_host]) {
            continue;
        }

        for (size_t j = i + 1; j < host_group.hosts.size(); j++) {
            const std::string& target_host = host_group.hosts[j];
            if (!host_group.host_responsive[target_host]) {
                continue;
            }

            // Construct Unison command for this pair of hosts
            std::string cmd = "unison " + dir.path + " ssh://" + target_host + 
                            "/" + dir.path + 
                            " " + unison_options +
                            ignore_opts;
            
            try {
                execute_unison(cmd, noop);
                if (!noop) {
                    spdlog::info("Bidirectional sync completed successfully between {} and {}:{}",
                                source_host, target_host, dir.path);
                }
            } catch (const std::exception& e) {
                spdlog::error("Failed to sync between {} and {}:{}: {}", 
                             source_host, target_host, dir.path, e.what());
                host_group.host_responsive[target_host] = false;
                manage_host_connectivity(host_group, target_host);
            }
        }
    }
}

// Common functions
namespace {
    bool is_valid_hostname(const std::string& hostname) {
        // Basic hostname validation
        if (hostname.empty() || hostname.length() > 255) return false;
        
        // Check for valid characters
        const std::string valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
        if (hostname.find_first_not_of(valid_chars) != std::string::npos) return false;
        
        // Check for valid start/end characters
        if (hostname[0] == '.' || hostname[hostname.length()-1] == '.') return false;
        
        return true;
    }

    std::string sanitize_path(const std::string& path) {
        std::string sanitized = path;
        // Remove potentially dangerous characters
        const std::string invalid_chars = ";&|`$(){}[]<>\\\"'";
        for (char c : invalid_chars) {
            sanitized.erase(std::remove(sanitized.begin(), sanitized.end(), c), sanitized.end());
        }
        return sanitized;
    }

    void validate_unison_options(const std::string& options) {
        // Check for potentially dangerous options
        const std::vector<std::string> dangerous_options = {
            "shell", "servercmd", "rshcmd", "sshcmd", "rsync", "rsrc"
        };
        
        for (const auto& opt : dangerous_options) {
            if (options.find(opt) != std::string::npos) {
                throw std::runtime_error("Potentially dangerous unison option detected: " + opt);
            }
        }
    }

    SyncType parse_sync_type(const std::string& type_str) {
        if (type_str == "batch") return SyncType::BATCH;
        if (type_str == "event") return SyncType::EVENT;
        spdlog::warn("Unknown sync type '{}', defaulting to event", type_str);
        return SyncType::EVENT;
    }
}

void execute_unison(const std::string& cmd, bool noop) {
    // Validate and sanitize the command components
    validate_unison_options(cmd);
    std::string sanitized_cmd = sanitize_path(cmd);
    
    std::string actual_cmd = sanitized_cmd;
    if (noop) {
        actual_cmd += " -testonly";
        spdlog::info("[NOOP] Would execute: {}", sanitized_cmd);
    }

    // Use more secure command execution
    std::array<char, 4096> buffer;
    std::string output;
    
    FILE* pipe = popen(actual_cmd.c_str(), "r");
    if (!pipe) {
        spdlog::error("Failed to execute unison command: {}", sanitized_cmd);
        throw std::runtime_error("Failed to execute unison command");
    }

    while (fgets(buffer.data(), buffer.size(), pipe)) {
        output += buffer.data();
    }

    int status = pclose(pipe);
    if (status != 0) {
        if (noop) {
            spdlog::warn("[NOOP] Unison would have failed: {}", output);
        } else {
            if (status == 1) {
                spdlog::error("Unison reported non-fatal errors: {}", output);
            } else {
                spdlog::error("Unison failed with fatal error: {}", output);
                throw std::runtime_error("Unison failed with fatal error: " + output);
            }
        }
    } else if (noop && !output.empty()) {
        spdlog::info("[NOOP] Unison would perform these changes:\n{}", output);
    }
}

void manage_host_connectivity(HostGroup& host_group, const std::string& host) {
    if (!is_valid_hostname(host)) {
        spdlog::error("Invalid hostname: {}", host);
        return;
    }

    std::string sanitized_host = sanitize_path(host);
    std::string check_cmd = "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes " + 
                           sanitized_host + " exit";
    
    int result = system(check_cmd.c_str());
    
    if (result == 0) {
        if (!host_group.host_responsive[host]) {
            spdlog::info("Connection restored to host {}", host);
            host_group.host_responsive[host] = true;
            host_group.host_backoff_time[host] = std::chrono::seconds(HostGroup::INITIAL_BACKOFF_SECONDS);
            host_group.host_slow_retry_mode[host] = false;
        }
    } else {
        if (host_group.host_responsive[host]) {
            spdlog::error("Lost connection to host {}", host);
            host_group.host_responsive[host] = false;
        }
        
        if (!host_group.host_slow_retry_mode[host]) {
            auto new_backoff = host_group.host_backoff_time[host] * 2;
            if (new_backoff.count() > HostGroup::MAX_BACKOFF_SECONDS) {
                host_group.host_slow_retry_mode[host] = true;
            } else {
                host_group.host_backoff_time[host] = new_backoff;
            }
        }
    }
}

void signal_handler(int signum) {
    std::string signal_name;
    switch (signum) {
        case SIGTERM: signal_name = "SIGTERM"; break;
        case SIGINT: signal_name = "SIGINT"; break;
        case SIGHUP: signal_name = "SIGHUP"; break;
        default: signal_name = std::to_string(signum);
    }
    
    spdlog::info("Received signal {}, initiating shutdown...", signal_name);
    g_running = false;
}

std::string expand_path(const std::string& path) {
    if (path.empty() || path[0] != '~') return path;
    
    const char* home = std::getenv("HOME");
    if (!home) return path;
    
    return std::string(home) + path.substr(1);
}

void setup_logging(const Config& config) {
    try {
        // Create console sink with color support
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

        std::vector<spdlog::sink_ptr> sinks {console_sink};
        
        // Set up file logging if configured
        if (!config.log_file.empty()) {
            try {
                // Expand ~ in path and ensure log directory exists
                std::string expanded_log_file = expand_path(config.log_file);
                auto log_path = fs::path(expanded_log_file);
                fs::create_directories(log_path.parent_path());
                
                // Create rotating file sink
                auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    expanded_log_file,
                    5 * 1024 * 1024,  // 5MB max file size
                    3                  // Keep 3 rotated files
                );
                file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");
                sinks.push_back(file_sink);
                
                spdlog::info("Log file: {}", expanded_log_file);
            } catch (const std::exception& e) {
                std::cerr << "Failed to initialize file logging: " << e.what() << std::endl;
                std::cerr << "Continuing with console logging only" << std::endl;
            }
        }
        
        // Create and register logger
        auto logger = std::make_shared<spdlog::logger>("sync_daemon", sinks.begin(), sinks.end());
        
        // Set log level
        if (config.log_level == "trace") logger->set_level(spdlog::level::trace);
        else if (config.log_level == "debug") logger->set_level(spdlog::level::debug);
        else if (config.log_level == "info") logger->set_level(spdlog::level::info);
        else if (config.log_level == "warn") logger->set_level(spdlog::level::warn);
        else if (config.log_level == "error") logger->set_level(spdlog::level::err);
        else logger->set_level(spdlog::level::info);
        
        // Set as default logger
        spdlog::set_default_logger(logger);
        
        // Log startup information
        spdlog::info("Logging initialized at level: {}", config.log_level);
        spdlog::info("Running on {}", 
#ifdef __APPLE__
            "macOS"
#else
            "Linux"
#endif
        );
        
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        throw std::runtime_error("Failed to initialize logging: " + std::string(ex.what()));
    }
}

void daemonize(Config& config) {
    spdlog::info("Daemonizing process");
    
    // Create PID file directory if it doesn't exist
    if (!config.pid_file.empty()) {
        fs::path pid_path = fs::path(config.pid_file);
        fs::path pid_dir = pid_path.parent_path();
        if (!pid_dir.empty() && !fs::exists(pid_dir)) {
            try {
                fs::create_directories(pid_dir);
            } catch (const std::exception& e) {
                throw std::runtime_error("Failed to create PID file directory: " + std::string(e.what()));
            }
        }
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("Failed to fork process");
    }
    if (pid > 0) {
        // Write PID to file before parent exits
        if (!config.pid_file.empty()) {
            std::ofstream pid_file(config.pid_file);
            if (pid_file) {
                pid_file << pid;
            } else {
                throw std::runtime_error("Failed to write PID file: " + config.pid_file);
            }
        }
        exit(0);  // Parent exits
    }
    
    if (setsid() < 0) {
        throw std::runtime_error("Failed to create new session");
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect standard file descriptors to /dev/null
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2) {
            close(null_fd);
        }
    }
}

void handle_uninstall(bool purge) {
    const char* home = std::getenv("HOME");
    if (!home) {
        throw std::runtime_error("Could not determine home directory");
    }

    // Define paths
    std::string bin_path = "/usr/local/bin/syncd";
    std::string service_path = std::string(home) + "/.config/systemd/user/syncd.service";
    std::string config_dir = std::string(home) + "/.config/syncd";

    // Remove binary
    if (fs::exists(bin_path)) {
        fs::remove(bin_path);
        std::cout << "Removed binary: " << bin_path << std::endl;
    }

    // Remove service file
    if (fs::exists(service_path)) {
        fs::remove(service_path);
        std::cout << "Removed service file: " << service_path << std::endl;
    }

    if (purge) {
        // Remove config directory and all contents
        if (fs::exists(config_dir)) {
            fs::remove_all(config_dir);
            std::cout << "Removed configuration directory: " << config_dir << std::endl;
        }
        std::cout << "Syncd has been completely removed including configuration files" << std::endl;
    } else {
        std::cout << "Syncd has been uninstalled. Configuration files preserved in: " << config_dir << std::endl;
    }
}

Config parse_arguments(int argc, char* argv[]) {
    Config config;
    
    try {
        cxxopts::Options options("sync_daemon", "File synchronization daemon");
        
        options.add_options()
            ("c,config", "Path to configuration file", cxxopts::value<std::string>())
            ("d,daemon", "Run as daemon", cxxopts::value<bool>()->default_value("false"))
            ("l,log-level", "Log level (trace, debug, info, warn, error)", 
             cxxopts::value<std::string>()->default_value("info"))
            ("log-file", "Log file path", cxxopts::value<std::string>())
            ("p,pid-file", "PID file path", cxxopts::value<std::string>())
            ("n,noop", "Dry-run mode", cxxopts::value<bool>()->default_value("false"))
            ("uninstall", "Uninstall syncd application", cxxopts::value<bool>()->default_value("false"))
            ("purge", "Remove all traces including configuration files when uninstalling", cxxopts::value<bool>()->default_value("false"))
            ("check-config", "Check configuration file for errors", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        // Handle uninstall command
        if (result.count("uninstall")) {
            bool purge = result.count("purge") > 0;
            handle_uninstall(purge);
            exit(0);
        }

        // Handle check-config command
        if (result.count("check-config")) {
            try {
                // Try to load and parse the config file
                YAML::Node yaml = YAML::LoadFile(result["config"].as<std::string>());
                
                // Basic validation
                if (!yaml["host_groups"]) {
                    throw std::runtime_error("Configuration must contain 'host_groups' section");
                }

                for (const auto& group : yaml["host_groups"]) {
                    if (!group["hosts"] || !group["hosts"].IsSequence()) {
                        throw std::runtime_error("Each host group must have a 'hosts' list");
                    }
                    if (!group["directories"] || !group["directories"].IsSequence()) {
                        throw std::runtime_error("Each host group must have a 'directories' list");
                    }

                    for (const auto& dir : group["directories"]) {
                        if (!dir["path"]) {
                            throw std::runtime_error("Each directory must have a 'path' defined");
                        }
                    }
                }

                // Only print the message once and exit with success
                exit(0);
            } catch (const std::exception& e) {
                std::cerr << "Configuration error: " << e.what() << std::endl;
                exit(1);
            }
        }

        if (!result.count("config")) {
            throw std::runtime_error("Configuration file path is required");
        }

        config.config_path = result["config"].as<std::string>();
        config.daemon = result["daemon"].as<bool>();
        config.log_level = result["log-level"].as<std::string>();
        config.noop = result["noop"].as<bool>();

        if (result.count("log-file")) {
            config.log_file = result["log-file"].as<std::string>();
        }

        if (result.count("pid-file")) {
            config.pid_file = result["pid-file"].as<std::string>();
        }

        // Load and parse YAML configuration
        YAML::Node yaml = YAML::LoadFile(config.config_path);

        // Parse host groups
        if (!yaml["host_groups"]) {
            throw std::runtime_error("Configuration must contain 'host_groups' section");
        }

        // Parse host groups
        for (const auto& group : yaml["host_groups"]) {
            HostGroup host_group;

            // Parse hosts
            if (!group["hosts"] || !group["hosts"].IsSequence()) {
                throw std::runtime_error("Each host group must have a 'hosts' list");
            }

            for (const auto& host : group["hosts"]) {
                host_group.add_host(host.as<std::string>());
            }

            // Parse directories
            if (!group["directories"] || !group["directories"].IsSequence()) {
                throw std::runtime_error("Each host group must have a 'directories' list");
            }

            for (const auto& dir : group["directories"]) {
                RemoteDirectory remote_dir;

                if (!dir["path"]) {
                    throw std::runtime_error("Each directory must have a 'path' defined");
                }

                remote_dir.path = resolve_path(dir["path"].as<std::string>(), config.config_path);

                // Parse optional settings
                if (dir["sync_type"]) {
                    remote_dir.sync_type = parse_sync_type(dir["sync_type"].as<std::string>());
                }

                if (dir["batch_interval"]) {
                    remote_dir.batch_interval = std::chrono::seconds(
                        dir["batch_interval"].as<int>()
                    );
                }

                if (dir["exclude"] && dir["exclude"].IsSequence()) {
                    for (const auto& pattern : dir["exclude"]) {
                        remote_dir.exclude_patterns.push_back(pattern.as<std::string>());
                    }
                }

                host_group.directories.push_back(remote_dir);
            }

            config.host_groups.push_back(host_group);
        }

        // Parse global settings
        if (yaml["unison_options"]) {
            config.unison_options = yaml["unison_options"].as<std::string>();
        } else {
            config.unison_options = "-batch -prefer newer -times -perms 0 -auto -ui text";
        }

        if (yaml["host_check_interval"]) {
            config.host_check_interval = std::chrono::seconds(
                yaml["host_check_interval"].as<int>()
            );
        }

        if (yaml["consistency_check_interval"]) {
            config.consistency_check_interval = std::chrono::seconds(
                yaml["consistency_check_interval"].as<int>()
            );
        }

        // If PID file wasn't set by command line, try to get it from config
        if (config.pid_file.empty() && yaml["pid_file"]) {
            config.pid_file = yaml["pid_file"].as<std::string>();
        }

        // If log file wasn't set by command line, try to get it from config
        if (config.log_file.empty() && yaml["log_file"]) {
            config.log_file = yaml["log_file"].as<std::string>();
        }

        return config;

    } catch (const cxxopts::exceptions::parsing& e) {
        throw std::runtime_error("Error parsing command line options: " + std::string(e.what()));
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Error parsing configuration file: " + std::string(e.what()));
    }
}

std::string detect_user_shell() {
    const char* shell = std::getenv("SHELL");
    if (!shell) return "";
    
    std::string shell_path(shell);
    if (shell_path.find("bash") != std::string::npos) return "bash";
    if (shell_path.find("zsh") != std::string::npos) return "zsh";
    if (shell_path.find("fish") != std::string::npos) return "fish";
    return "";
}

std::string get_rc_file(const std::string& shell, const char* home) {
    if (shell == "bash") return std::string(home) + "/.bashrc";
    if (shell == "zsh") return std::string(home) + "/.zshrc";
    if (shell == "fish") return std::string(home) + "/.config/fish/config.fish";
    return "";
}

int main(int argc, char* argv[]) {
    try {
        // Set up initial console-only logging
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logger = std::make_shared<spdlog::logger>("sync_daemon", console_sink);
        spdlog::set_default_logger(logger);
        
        // Parse arguments and load config
        Config config = parse_arguments(argc, argv);

        // Now set up full logging with file
        setup_logging(config);
        
        // Set up signal handling
        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);
        signal(SIGHUP, signal_handler);
        
        spdlog::info("Starting sync daemon in {} mode on {}", 
                     config.daemon ? "daemon" : "foreground",
                     #ifdef __APPLE__
                     "macOS"
                     #else
                     "Linux"
                     #endif
        );
        
        if (config.daemon) {
            daemonize(config);
        }
        
        std::vector<std::thread> host_threads;
        host_threads.reserve(config.host_groups.size() * 2);  // 2 threads per group
        
        for (auto& host_group : config.host_groups) {
            // Start heartbeat threads for each host in the group
            for (const auto& host : host_group.hosts) {
                host_threads.emplace_back([&host_group, &host]() {
                    while (g_running) {
                        manage_host_connectivity(host_group, host);
                        std::this_thread::sleep_for(
                            host_group.host_slow_retry_mode[host] ? 
                            std::chrono::seconds(HostGroup::SLOW_RETRY_INTERVAL) : 
                            std::chrono::seconds(30)
                        );
                    }
                });
            }
            
            // Start directory monitoring thread for the group
            host_threads.emplace_back([&host_group, &config]() {
                monitor_directories(host_group, config.unison_options, config.noop);
            });
        }
        
        for (auto& thread : host_threads) {
            thread.join();
        }
        
        return 0;
    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }
}

std::string resolve_path(const std::string& path, const std::string& config_path) {
    // First expand any ~ in the path
    std::string expanded = expand_path(path);
    
    // If path is absolute, return it as is
    if (fs::path(expanded).is_absolute()) {
        return expanded;
    }
    
    // Make relative paths relative to the config file's directory
    fs::path config_dir = fs::path(config_path).parent_path();
    return (config_dir / expanded).string();
}
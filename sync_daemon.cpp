// sync_daemon.cpp
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
    #include <sqlite3.h>
    #include <xxhash.h>
    #include <nlohmann/json.hpp>
    #include <sys/inotify.h>
    using json = nlohmann::json;
#endif

namespace fs = std::filesystem;

// Common structures for both platforms
struct RemoteDirectory {
    std::string local_dir;
    std::string remote_dir;
    std::vector<std::string> exclude_patterns;
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
    std::chrono::seconds poll_interval{300};
    std::chrono::seconds consistency_check_interval{3600};
};

// Platform-specific structures
#ifdef __APPLE__
struct FSEventContext {
    std::string local_dir;
    std::mutex mutex;
    std::condition_variable cv;
    std::set<std::string> changed_paths;
    std::chrono::steady_clock::time_point last_sync;
    bool has_changes{false};

    explicit FSEventContext(const std::string& dir) : local_dir(dir) {}
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
    // ... Linux-specific inventory database implementation ...
};
#endif

std::atomic<bool> g_running{true};

// Forward declarations
void execute_unison(const std::string& cmd, bool noop);
void manage_host_connectivity(HostGroup& host_group, const std::string& host);
void sync_to_remote(const RemoteDirectory& dir, HostGroup& host_group, 
                   const std::string& unison_options, bool noop);
Config parse_arguments(int argc, char* argv[]);

#ifdef __APPLE__
void FSEventsCallback(ConstFSEventStreamRef streamRef,
                     void* clientCallBackInfo,
                     size_t numEvents,
                     void* eventPaths,
                     const FSEventStreamEventFlags eventFlags[],
                     const FSEventStreamEventId eventIds[]);
#endif

// Helper function to find config file
std::string find_config_file() {
    std::vector<std::string> config_paths = {
        "./sync_daemon.yaml",
        "~/.config/sync_daemon/config.yaml",
        "/etc/sync_daemon/config.yaml"
    };

    for (const auto& path : config_paths) {
        std::string expanded_path = path;
        if (path.length() >= 2 && path.substr(0, 2) == "~/") {
            const char* home = getenv("HOME");
            if (home) {
                expanded_path = std::string(home) + path.substr(1);
            }
        }
        if (fs::exists(expanded_path)) {
            return expanded_path;
        }
    }
    
    throw std::runtime_error("No config file found in standard locations");
}

// Load configuration from YAML file
Config load_config(const std::string& config_path) {
    try {
        YAML::Node yaml = YAML::LoadFile(config_path);
        Config config;
        config.config_path = config_path;
        
        if (yaml["unison_options"]) {
            config.unison_options = yaml["unison_options"].as<std::string>();
        } else {
            config.unison_options = "-batch -prefer newer -times -perms 0 -auto -ui text";
        }
        
        if (yaml["log_level"]) {
            config.log_level = yaml["log_level"].as<std::string>();
        }
        
        if (yaml["daemon"]) {
            config.daemon = yaml["daemon"].as<bool>();
        }
        
        if (yaml["noop"]) {
            config.noop = yaml["noop"].as<bool>();
        }
        
        if (yaml["pid_file"]) {
            config.pid_file = yaml["pid_file"].as<std::string>();
        }
        
        if (yaml["poll_interval"]) {
            config.poll_interval = std::chrono::seconds(yaml["poll_interval"].as<int>());
        }
        
        if (yaml["consistency_check_interval"]) {
            config.consistency_check_interval = 
                std::chrono::seconds(yaml["consistency_check_interval"].as<int>());
        }
        
        if (yaml["host_groups"]) {
            for (const auto& host_group_node : yaml["host_groups"]) {
                HostGroup host_group;
                
                for (const auto& host_node : host_group_node["hosts"]) {
                    host_group.add_host(host_node.as<std::string>());
                }
                
                for (const auto& dir_node : host_group_node["directories"]) {
                    RemoteDirectory dir;
                    dir.local_dir = dir_node["local"].as<std::string>();
                    dir.remote_dir = dir_node["remote"].as<std::string>();
                    
                    if (dir_node["exclude"]) {
                        dir.exclude_patterns = dir_node["exclude"].as<std::vector<std::string>>();
                    }
                    
                    host_group.directories.push_back(dir);
                }
                
                config.host_groups.push_back(host_group);
            }
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Error parsing config file: " + std::string(e.what()));
    }
}

// Parse command line arguments
Config parse_arguments(int argc, char* argv[]) {
    try {
        cxxopts::Options options("sync_daemon", "File synchronization daemon");
        
        options.add_options()
            ("c,config", "Config file path", cxxopts::value<std::string>())
            ("d,daemon", "Run as daemon", cxxopts::value<bool>()->default_value("false"))
            ("n,noop", "No-op mode (dry run)", cxxopts::value<bool>()->default_value("false"))
            ("l,log-level", "Log level (trace, debug, info, warn, error)", 
             cxxopts::value<std::string>()->default_value("info"))
            ("p,pid-file", "PID file location", 
             cxxopts::value<std::string>()->default_value("/var/run/sync_daemon.pid"))
            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        Config config = load_config(result.count("config") ? 
            result["config"].as<std::string>() : find_config_file());

        // Override config with command line arguments
        if (result.count("daemon")) {
            config.daemon = result["daemon"].as<bool>();
        }
        if (result.count("noop")) {
            config.noop = result["noop"].as<bool>();
            if (config.noop) {
                spdlog::info("Running in no-op mode (dry run)");
            }
        }
        if (result.count("log-level")) {
            config.log_level = result["log-level"].as<std::string>();
        }
        if (result.count("pid-file")) {
            config.pid_file = result["pid-file"].as<std::string>();
        }

        return config;
    } catch (const std::exception& e) {
        throw std::runtime_error("Error parsing command line arguments: " + std::string(e.what()));
    }
}

// Platform-specific file monitoring implementation
#ifdef __APPLE__
void monitor_directories(HostGroup& host_group, const std::string& unison_options, bool noop) {
    spdlog::info("Starting directory monitoring for host group ({} hosts, {} directories)", 
                 host_group.hosts.size(), host_group.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(host_group.directories.size());
    
    for (const auto& dir : host_group.directories) {
        if (!fs::exists(dir.local_dir)) {
            spdlog::error("Directory does not exist: {}", dir.local_dir);
            continue;
        }
        
        monitor_threads.emplace_back([&]() {
            FSEventContext context{dir.local_dir};
            context.last_sync = std::chrono::steady_clock::now();
            
            CFStringRef path = CFStringCreateWithCString(nullptr, dir.local_dir.c_str(),
                                                       kCFStringEncodingUTF8);
            CFArrayRef pathsToWatch = CFArrayCreate(nullptr, (const void **)&path, 1, nullptr);
            FSEventStreamContext streamContext = {0, &context, nullptr, nullptr, nullptr};
            
            FSEventStreamRef stream = FSEventStreamCreate(nullptr,
                &FSEventsCallback,
                &streamContext,
                pathsToWatch,
                kFSEventStreamEventIdSinceNow,
                0.5,  // 500ms latency for better batching
                kFSEventStreamCreateFlagFileEvents | 
                kFSEventStreamCreateFlagNoDefer |
                kFSEventStreamCreateFlagIgnoreSelf
            );
            
            if (!stream) {
                spdlog::error("Failed to create FSEvents stream for {}", dir.local_dir);
                CFRelease(pathsToWatch);
                CFRelease(path);
                return;
            }
            
            FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
            
            if (!FSEventStreamStart(stream)) {
                spdlog::error("Failed to start FSEvents stream for {}", dir.local_dir);
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                CFRelease(pathsToWatch);
                CFRelease(path);
                return;
            }
            
            while (g_running) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, true);
                if (context.has_changes && host_group.has_responsive_host()) {
                    sync_to_remote(dir, host_group, unison_options, noop);
                    context.has_changes = false;
                }
            }
            
            FSEventStreamStop(stream);
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            CFRelease(pathsToWatch);
            CFRelease(path);
        });
    }
    
    for (auto& thread : monitor_threads) {
        thread.join();
    }
}
#else
void monitor_directories(HostGroup& host_group, const std::string& unison_options, bool noop) {
    spdlog::info("Starting directory monitoring for host group ({} hosts, {} directories)", 
                 host_group.hosts.size(), host_group.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(host_group.directories.size());
    
    for (const auto& dir : host_group.directories) {
        if (!fs::exists(dir.local_dir)) {
            spdlog::error("Directory does not exist: {}", dir.local_dir);
            continue;
        }
        
        monitor_threads.emplace_back([&]() {
            int inotify_fd = inotify_init1(IN_NONBLOCK);
            if (inotify_fd == -1) {
                throw std::runtime_error("Failed to initialize inotify");
            }
            
            std::map<int, std::string> watch_descriptors;
            
            // Set up watches for each directory
            int wd = inotify_add_watch(inotify_fd, dir.local_dir.c_str(), 
                                      IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE);
            if (wd == -1) {
                spdlog::error("Failed to add watch for {}", dir.local_dir);
                close(inotify_fd);
                return;
            }
            watch_descriptors[wd] = dir.local_dir;
            
            // Buffer for reading events
            const int BUF_LEN = (10 * (sizeof(struct inotify_event) + NAME_MAX + 1));
            char buffer[BUF_LEN];
            
            while (g_running) {
                int length = read(inotify_fd, buffer, BUF_LEN);
                if (length > 0) {
                    int i = 0;
                    while (i < length) {
                        struct inotify_event* event = (struct inotify_event*)&buffer[i];
                        if (event->len) {
                            std::string dir_path = watch_descriptors[event->wd];
                            if (!dir_path.empty()) {
                                for (const auto& dir : host_group.directories) {
                                    if (dir.local_dir == dir_path) {
                                        sync_to_remote(dir, host_group, unison_options, noop);
                                        break;
                                    }
                                }
                            }
                        }
                        i += sizeof(struct inotify_event) + event->len;
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            // Cleanup
            for (const auto& [wd, _] : watch_descriptors) {
                inotify_rm_watch(inotify_fd, wd);
            }
            close(inotify_fd);
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
            std::string cmd = "unison " + dir.local_dir + " ssh://" + target_host + 
                            "/" + dir.remote_dir + 
                            " " + unison_options +
                            ignore_opts;
            
            try {
                execute_unison(cmd, noop);
                if (!noop) {
                    spdlog::info("Bidirectional sync completed successfully between {} and {}:{}",
                                source_host, target_host, dir.remote_dir);
                }
            } catch (const std::exception& e) {
                spdlog::error("Failed to sync between {} and {}:{}: {}", 
                             source_host, target_host, dir.remote_dir, e.what());
                host_group.host_responsive[target_host] = false;
                manage_host_connectivity(host_group, target_host);
            }
        }
    }
}

// Common functions
void execute_unison(const std::string& cmd, bool noop) {
    std::string actual_cmd = cmd;
    if (noop) {
        actual_cmd += " -testonly";
        spdlog::info("[NOOP] Would execute: {}", cmd);
    }

    FILE* pipe = popen(actual_cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to execute unison command");
    }

    std::array<char, 4096> buffer;
    std::string output;
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
                throw std::runtime_error("Unison failed with fatal error: " + output);
            }
        }
    } else if (noop && !output.empty()) {
        spdlog::info("[NOOP] Unison would perform these changes:\n{}", output);
    }
}

void manage_host_connectivity(HostGroup& host_group, const std::string& host) {
    std::string check_cmd = "ssh -o BatchMode=yes -o ConnectTimeout=5 " + host + " exit";
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
        
        // Update retry timing
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

void setup_logging(const Config& config) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        config.log_file.empty() ? "sync_daemon.log" : config.log_file, 
        5 * 1024 * 1024, 3);
    
    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("sync_daemon", sinks.begin(), sinks.end());
    
    if (config.log_level == "debug") logger->set_level(spdlog::level::debug);
    else if (config.log_level == "info") logger->set_level(spdlog::level::info);
    else if (config.log_level == "warn") logger->set_level(spdlog::level::warn);
    else if (config.log_level == "error") logger->set_level(spdlog::level::err);
    else logger->set_level(spdlog::level::info);
    
    spdlog::set_default_logger(logger);
}

void daemonize(Config& config) {
    spdlog::info("Daemonizing process");
    
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("Failed to fork process");
    }
    if (pid > 0) {
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

#ifdef __APPLE__
void FSEventsCallback(ConstFSEventStreamRef streamRef,
                     void* clientCallBackInfo,
                     size_t numEvents,
                     void* eventPaths,
                     const FSEventStreamEventFlags eventFlags[],
                     const FSEventStreamEventId eventIds[]) {
    auto* context = static_cast<FSEventContext*>(clientCallBackInfo);
    char** paths = static_cast<char**>(eventPaths);
    
    std::lock_guard<std::mutex> lock(context->mutex);
    for (size_t i = 0; i < numEvents; i++) {
        std::string path(paths[i]);
        context->changed_paths.insert(path);
    }
    context->has_changes = true;
    context->cv.notify_one();
}
#endif
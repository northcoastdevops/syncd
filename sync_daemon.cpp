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
#include <CoreServices/CoreServices.h>
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
#include <UserNotifications/UserNotifications.h>
#include <stdexcept>

namespace fs = std::filesystem;

// Global variables
std::atomic<bool> g_running{true};

// Move these struct definitions to the top, after includes but before any function declarations
struct RemoteDirectory {
    std::string local_dir;
    std::string remote_dir;
    std::vector<std::string> exclude_patterns;
};

struct RemoteHost {
    std::string host;
    std::vector<RemoteDirectory> directories;
    std::chrono::seconds backoff_time{1};
    std::chrono::system_clock::time_point next_retry;
    bool is_responsive{true};
    bool slow_retry_mode{false};
    static constexpr int MAX_BACKOFF_SECONDS = 3600;  // 1 hour
    static constexpr int INITIAL_BACKOFF_SECONDS = 1;
    static constexpr int SLOW_RETRY_INTERVAL = 3600;  // 1 hour
};

struct Config {
    std::string config_path;
    bool daemon_mode;
    std::vector<RemoteHost> remote_hosts;
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

// Custom error type for rsync operations
class RsyncError : public std::runtime_error {
public:
    explicit RsyncError(const std::string& message) : std::runtime_error(message) {}
};

// Context structure for FSEvents
struct FSEventContext {
    std::string local_dir;
    std::mutex mutex;
    std::condition_variable cv;
    std::set<std::string> changed_paths;
    std::chrono::steady_clock::time_point last_sync;
    bool has_changes{false};

    explicit FSEventContext(const std::string& dir) : local_dir(dir) {}
};

// Forward declarations
void execute_unison(const std::string& cmd, bool noop);
std::string find_config_file();
Config load_config(const std::string& config_path);
Config parse_arguments(int argc, char* argv[]);
void sync_to_remote(const RemoteDirectory& dir, RemoteHost& remote_host, 
                   const std::string& unison_options, bool noop);
void monitor_directories(RemoteHost& remote_host, const std::string& unison_options, bool noop);
void signal_handler(int signum);
void setup_logging(const Config& config);
void daemonize(Config& config);
void manage_host_connectivity(RemoteHost& host);
void FSEventsCallback(ConstFSEventStreamRef streamRef,
                     void* clientCallBackInfo,
                     size_t numEvents,
                     void* eventPaths,
                     const FSEventStreamEventFlags eventFlags[],
                     const FSEventStreamEventId eventIds[]);

// Function implementations
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
    // Unison exit codes: 0=success, 1=error, 2=fatal error
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

void sync_to_remote(const RemoteDirectory& dir, RemoteHost& remote_host, 
                   const std::string& unison_options, bool noop) {
    if (!remote_host.is_responsive) {
        manage_host_connectivity(remote_host);
        return;
    }
    
    // Build exclude patterns
    std::string ignore_opts;
    for (const auto& pattern : dir.exclude_patterns) {
        ignore_opts += " -ignore 'Path " + pattern + "'";
    }
    
    // Construct Unison command with proper options for newest-files-win strategy
    std::string cmd = "unison " + dir.local_dir + " ssh://" + remote_host.host + 
                     "/" + dir.remote_dir + 
                     " -batch" +  // Run without user interaction
                     " -prefer newer" +  // Keep newest version on conflict
                     " -times" +  // Preserve modification times
                     " -perms 0" +  // Don't sync permissions
                     " -auto" +  // Automatically accept actions
                     " -ui text" +  // Use text UI
                     " -repeat watch" +  // Keep running and watching for changes
                     ignore_opts;

    if (!unison_options.empty()) {
        cmd += " " + unison_options;
    }
    
    try {
        execute_unison(cmd, noop);
        if (!noop) {
            spdlog::info("Bidirectional sync completed successfully between {} and {}:{}",
                        dir.local_dir, remote_host.host, dir.remote_dir);
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to sync between {} and {}:{}: {}", 
                     dir.local_dir, remote_host.host, dir.remote_dir, e.what());
        remote_host.is_responsive = false;
        manage_host_connectivity(remote_host);
    }
}

void monitor_directories(RemoteHost& remote_host, const std::string& unison_options, bool noop) {
    spdlog::info("Starting FSEvents monitoring for host: {} ({} directories)", 
                 remote_host.host, remote_host.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(remote_host.directories.size());
    
    for (const auto& dir : remote_host.directories) {
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
                if (context.has_changes && remote_host.is_responsive) {
                    sync_to_remote(dir, remote_host, unison_options, noop);
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

// Signal handler implementation
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

// Logging setup implementation
void setup_logging(const Config& config) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        "sync_daemon.log", 5 * 1024 * 1024, 3);
    
    std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
    auto logger = std::make_shared<spdlog::logger>("sync_daemon", sinks.begin(), sinks.end());
    
    if (config.log_level == "debug") logger->set_level(spdlog::level::debug);
    else if (config.log_level == "info") logger->set_level(spdlog::level::info);
    else if (config.log_level == "warn") logger->set_level(spdlog::level::warn);
    else if (config.log_level == "error") logger->set_level(spdlog::level::err);
    else logger->set_level(spdlog::level::info);
    
    spdlog::set_default_logger(logger);
}

// Host connectivity management implementation
void manage_host_connectivity(RemoteHost& host) {
    std::string check_cmd = "ssh -o BatchMode=yes -o ConnectTimeout=5 " + host.host + " exit";
    int result = system(check_cmd.c_str());
    
    if (result == 0) {
        if (!host.is_responsive) {
            spdlog::info("Connection restored to host {}", host.host);
            host.is_responsive = true;
        }
    } else {
        if (host.is_responsive) {
            spdlog::error("Lost connection to host {}", host.host);
        }
        host.is_responsive = false;
    }
}

// FSEvents callback implementation
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

// Daemonize implementation
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

Config load_config(const std::string& config_path) {
    try {
        YAML::Node yaml = YAML::LoadFile(config_path);
        Config config;
        config.config_path = config_path;
        
        if (yaml["unison_options"]) {
            config.unison_options = yaml["unison_options"].as<std::string>();
        } else {
            // Default Unison options for bidirectional sync with newest-wins strategy
            config.unison_options = "-fastcheck true -confirmbigdel false -silent";
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
        
        if (yaml["remote_hosts"]) {
            for (const auto& host_node : yaml["remote_hosts"]) {
                RemoteHost host;
                host.host = host_node["host"].as<std::string>();
                
                for (const auto& dir_node : host_node["directories"]) {
                    RemoteDirectory dir;
                    dir.local_dir = dir_node["local"].as<std::string>();
                    dir.remote_dir = dir_node["remote"].as<std::string>();
                    
                    if (dir_node["exclude"]) {
                        dir.exclude_patterns = dir_node["exclude"].as<std::vector<std::string>>();
                    }
                    
                    host.directories.push_back(dir);
                }
                
                config.remote_hosts.push_back(host);
            }
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Error parsing config file: " + std::string(e.what()));
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
        
        spdlog::info("Starting sync daemon in {} mode", 
                     config.daemon ? "daemon" : "foreground");
        
        if (config.daemon) {
            daemonize(config);
        }
        
        std::vector<std::thread> host_threads;
        host_threads.reserve(config.remote_hosts.size() * 2);  // 2 threads per host
        
        for (auto& host : config.remote_hosts) {
            // Start heartbeat thread for the host
            host_threads.emplace_back([&host]() {
                while (g_running) {
                    manage_host_connectivity(host);
                    std::this_thread::sleep_for(
                        host.slow_retry_mode ? 
                        std::chrono::seconds(RemoteHost::SLOW_RETRY_INTERVAL) : 
                        std::chrono::seconds(30)
                    );
                }
            });
            
            // Start directory monitoring thread for the host
            host_threads.emplace_back([&host, &config]() {
                monitor_directories(host, config.unison_options, config.noop);
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
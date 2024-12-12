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

struct RemoteDirectory {
    std::string local_dir;
    std::string remote_dir;
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
    std::vector<RemoteHost> remote_hosts;
    std::string rsync_options;
    std::string log_level = "info";
    bool daemon = false;
    std::string pid_file = "/var/run/sync_daemon.pid";
};

std::atomic<bool> g_running{true};
namespace fs = std::filesystem;

void show_notification(const std::string& title, const std::string& message, 
                      const std::string& host, bool is_error = false) {
    NSString* script = [NSString stringWithFormat:
        @"display notification \"%@\" with title \"%@\" subtitle \"%@\" %@",
        [NSString stringWithUTF8String:message.c_str()],
        [NSString stringWithUTF8String:title.c_str()],
        [NSString stringWithUTF8String:host.c_str()],
        is_error ? @"sound name \"Basso\"" : @""];

    NSAppleScript* appleScript = [[NSAppleScript alloc] initWithSource:script];
    NSDictionary* error = nil;
    [appleScript executeAndReturnError:&error];
}

bool check_host_connectivity(const std::string& host) {
    std::string cmd = "ssh -o BatchMode=yes -o ConnectTimeout=5 " + host + " exit 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return false;
    
    std::array<char, 128> buffer;
    std::string result;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    int status = pclose(pipe);
    return status == 0;
}

void manage_host_connectivity(RemoteHost& host) {
    auto now = std::chrono::system_clock::now();
    
    if (now < host.next_retry) {
        return;  // Still in backoff period
    }
    
    if (check_host_connectivity(host.host)) {
        if (!host.is_responsive) {
            // Host is back online
            show_notification("Sync Daemon", "Connection restored", host.host);
            host.is_responsive = true;
            host.backoff_time = std::chrono::seconds(RemoteHost::INITIAL_BACKOFF_SECONDS);
            host.slow_retry_mode = false;
        }
    } else {
        host.is_responsive = false;
        
        if (host.slow_retry_mode) {
            host.next_retry = now + std::chrono::seconds(RemoteHost::SLOW_RETRY_INTERVAL);
        } else {
            // Exponential backoff (multiply by 2 each time)
            host.backoff_time *= 2;
            
            // Cap at MAX_BACKOFF_SECONDS
            if (host.backoff_time > std::chrono::seconds(RemoteHost::MAX_BACKOFF_SECONDS)) {
                show_notification("Sync Daemon", 
                    "Host unreachable after multiple retries. Click to continue hourly checks.",
                    host.host, true);
                host.slow_retry_mode = true;
                host.backoff_time = std::chrono::seconds(RemoteHost::SLOW_RETRY_INTERVAL);
            }
            
            host.next_retry = now + host.backoff_time;
        }
    }
}

void sync_to_remote(const RemoteDirectory& dir, RemoteHost& remote_host, 
                   const std::string& rsync_options) {
    if (!remote_host.is_responsive) {
        manage_host_connectivity(remote_host);
        return;
    }
    
    std::string cmd = "rsync " + rsync_options + " --update " + dir.local_dir + "/ " + 
                     remote_host.host + ":" + dir.remote_dir + "/";
    try {
        execute_rsync(cmd);
        spdlog::info("Sync of {} to {}:{} completed successfully", 
                    dir.local_dir, remote_host.host, dir.remote_dir);
    } catch (const RsyncError& e) {
        spdlog::error("Failed to sync {} to {}:{}: {}", 
                     dir.local_dir, remote_host.host, dir.remote_dir, e.what());
        remote_host.is_responsive = false;
        manage_host_connectivity(remote_host);
    }
}

void monitor_directories(RemoteHost& remote_host, const std::string& rsync_options) {
    spdlog::info("Starting FSEvents monitoring for host: {} ({} directories)", 
                 remote_host.host, remote_host.directories.size());
    
    std::vector<std::thread> monitor_threads;
    monitor_threads.reserve(remote_host.directories.size());
    
    for (const auto& dir : remote_host.directories) {
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
                    sync_to_remote(dir, remote_host, rsync_options);
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

Config parse_config(const std::string& config_path) {
    YAML::Node yaml_config = YAML::LoadFile(config_path);
    Config config;
    
    if (!yaml_config["remote_hosts"] || !yaml_config["remote_hosts"].IsSequence()) {
        throw std::runtime_error("Config must contain a 'remote_hosts' sequence");
    }
    
    for (const auto& host_node : yaml_config["remote_hosts"]) {
        if (!host_node["host"] || !host_node["directories"] || !host_node["directories"].IsSequence()) {
            throw std::runtime_error("Each remote host must specify 'host' and 'directories' sequence");
        }
        
        RemoteHost host;
        host.host = host_node["host"].as<std::string>();
        
        for (const auto& dir_node : host_node["directories"]) {
            if (!dir_node["local"] || !dir_node["remote"]) {
                throw std::runtime_error("Each directory mapping must specify 'local' and 'remote' paths");
            }
            
            RemoteDirectory dir;
            dir.local_dir = dir_node["local"].as<std::string>();
            dir.remote_dir = dir_node["remote"].as<std::string>();
            
            // Validate local directory exists and is readable
            if (!std::filesystem::exists(dir.local_dir)) {
                throw std::runtime_error("Local directory does not exist: " + dir.local_dir);
            }
            if (!std::filesystem::is_directory(dir.local_dir)) {
                throw std::runtime_error("Path is not a directory: " + dir.local_dir);
            }
            if (access(dir.local_dir.c_str(), R_OK) != 0) {
                throw std::runtime_error("Directory is not readable: " + dir.local_dir);
            }
            
            host.directories.push_back(dir);
        }
        
        config.remote_hosts.push_back(host);
    }
    
    config.rsync_options = yaml_config["rsync_options"] ? 
        yaml_config["rsync_options"].as<std::string>() : "-az --delete";
    
    if (yaml_config["log_level"]) {
        config.log_level = yaml_config["log_level"].as<std::string>();
    }
    
    if (yaml_config["daemon"]) {
        config.daemon = yaml_config["daemon"].as<bool>();
    }
    
    if (yaml_config["pid_file"]) {
        config.pid_file = yaml_config["pid_file"].as<std::string>();
    }
    
    return config;
}

void signal_handler(int signal) {
    spdlog::info("Received signal {}, initiating shutdown...", signal);
    g_running = false;
}

void setup_logging() {
    try {
        // Create console sink
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);

        // Create rotating file sink - 5MB size, 3 rotated files
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            "sync_daemon.log", 5 * 1024 * 1024, 3);
        file_sink->set_level(spdlog::level::debug);

        std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("sync_daemon", sinks.begin(), sinks.end());
        
        // Set global logging level to debug
        logger->set_level(spdlog::level::debug);
        
        // Set as default logger
        spdlog::set_default_logger(logger);
        spdlog::info("Logging system initialized");
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        exit(1);
    }
}

class RsyncError : public std::runtime_error {
public:
    RsyncError(const std::string& msg, int exit_code) 
        : std::runtime_error(msg), exit_code(exit_code) {}
    int get_exit_code() const { return exit_code; }
private:
    int exit_code;
};

bool should_retry_rsync(int exit_code) {
    // Rsync exit codes that warrant a retry
    static const std::vector<int> retry_codes = {
        1,  // Syntax or usage error
        11, // Error in file I/O
        23, // Partial transfer due to error
        30, // Timeout in data send/receive
        35  // Timeout waiting for daemon connection
    };
    return std::find(retry_codes.begin(), retry_codes.end(), exit_code) != retry_codes.end();
}

void execute_rsync(const std::string& cmd, int retry_count = 3, int retry_delay = 5) {
    int attempt = 0;
    while (attempt < retry_count) {
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            throw RsyncError("Failed to execute rsync command", -1);
        }

        std::array<char, 128> buffer;
        std::string output;
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            output += buffer.data();
        }

        int status = pclose(pipe);
        int exit_code = WEXITSTATUS(status);

        if (exit_code == 0) {
            spdlog::debug("Rsync command succeeded: {}", cmd);
            return;
        }

        if (!should_retry_rsync(exit_code) || attempt == retry_count - 1) {
            throw RsyncError("Rsync failed: " + output, exit_code);
        }

        attempt++;
        spdlog::warn("Rsync attempt {} failed with code {}. Retrying in {} seconds...", 
                     attempt, exit_code, retry_delay);
        std::this_thread::sleep_for(std::chrono::seconds(retry_delay));
    }
}

void write_pid_file(const std::string& pid_file) {
    std::ofstream ofs(pid_file);
    if (!ofs) {
        throw std::runtime_error("Cannot create PID file: " + pid_file);
    }
    ofs << getpid();
}

void remove_pid_file(const std::string& pid_file) {
    if (std::filesystem::exists(pid_file)) {
        std::filesystem::remove(pid_file);
    }
}

void daemonize() {
    // First fork (detaches from parent process)
    pid_t pid = fork();
    if (pid < 0) {
        throw std::runtime_error("First fork failed");
    }
    if (pid > 0) {
        exit(0);  // Parent process exits
    }

    // Create new session
    if (setsid() < 0) {
        throw std::runtime_error("setsid failed");
    }

    // Second fork (relinquishes session leadership)
    pid = fork();
    if (pid < 0) {
        throw std::runtime_error("Second fork failed");
    }
    if (pid > 0) {
        exit(0);
    }

    // Change working directory
    if (chdir("/") < 0) {
        throw std::runtime_error("chdir failed");
    }

    // Close all open file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    // Redirect standard file descriptors to /dev/null
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0) {
        throw std::runtime_error("Could not open /dev/null");
    }
    dup2(null_fd, STDIN_FILENO);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    if (null_fd > 2) {
        close(null_fd);
    }

    // Reset umask
    umask(0);
}

void set_resource_limits() {
    struct rlimit limit;
    
    // Set CPU limit (50% of one core)
    limit.rlim_cur = limit.rlim_max = 30;  // 30 seconds per minute
    if (setrlimit(RLIMIT_CPU, &limit) != 0) {
        spdlog::warn("Failed to set CPU limit");
    }

    // Set memory limit (50MB)
    limit.rlim_cur = limit.rlim_max = 50 * 1024 * 1024;
    if (setrlimit(RLIMIT_AS, &limit) != 0) {
        spdlog::warn("Failed to set memory limit");
    }

    // Set nice value for lower priority
    if (setpriority(PRIO_PROCESS, 0, 19) != 0) {
        spdlog::warn("Failed to set process priority");
    }
}

static void FSEventsCallback(ConstFSEventStreamRef streamRef,
                           void* clientCallBackInfo,
                           size_t numEvents,
                           void* eventPaths,
                           const FSEventStreamEventFlags eventFlags[],
                           const FSEventStreamEventId eventIds[]) {
    auto context = static_cast<FSEventContext*>(clientCallBackInfo);
    char** paths = static_cast<char**>(eventPaths);
    
    std::lock_guard<std::mutex> lock(context->mutex);
    
    // Add paths to the set (automatic deduplication)
    for (size_t i = 0; i < numEvents; ++i) {
        // Skip temporary files and system files
        std::string path(paths[i]);
        if (path.find(".tmp") != std::string::npos ||
            path.find(".swp") != std::string::npos ||
            path.find(".DS_Store") != std::string::npos) {
            continue;
        }
        
        // Only track if it's a real change
        if (eventFlags[i] & (kFSEventStreamEventFlagItemModified |
                           kFSEventStreamEventFlagItemCreated |
                           kFSEventStreamEventFlagItemRemoved |
                           kFSEventStreamEventFlagItemRenamed)) {
            context->changed_paths.insert(std::move(path));
        }
    }
    
    if (!context->changed_paths.empty()) {
        context->has_changes = true;
        context->cv.notify_one();
    }
}

int main(int argc, char* argv[]) {
    try {
        Config config = parse_arguments(argc, argv);
        
        if (config.daemon) {
            daemonize();
        }

        setup_logging();
        set_resource_limits();
        
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        write_pid_file(config.pid_file);
        
        spdlog::info("Starting sync daemon");
        
        std::vector<std::thread> host_threads;
        host_threads.reserve(config.remote_hosts.size());
        
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
                monitor_directories(host, config.rsync_options);
            });
        }
        
        for (auto& thread : host_threads) {
            thread.join();
        }
        
        remove_pid_file(config.pid_file);
        spdlog::info("Sync daemon shutting down");
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }
}

// Example YAML config:
/*
remote_hosts:
  - host: user@host1.example.com
    directories:
      - local: /path/to/local1
        remote: /path/on/remote1
      - local: /path/to/local2
        remote: /path/on/remote2
  - host: user@host2.example.com
    directories:
      - local: /path/to/local3
        remote: /path/on/remote3
      - local: /path/to/local4
        remote: /path/on/remote4
rsync_options: "-az --delete"
log_level: info
daemon: false
pid_file: /var/run/sync_daemon.pid
*/
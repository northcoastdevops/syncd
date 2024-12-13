cmake_minimum_required(VERSION 3.12)
project(sync_daemon)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Homebrew prefix to CMAKE_PREFIX_PATH for macOS
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
    include_directories(SYSTEM "/opt/homebrew/include")
    link_directories("/opt/homebrew/lib")
endif()

# Find common required packages
find_package(yaml-cpp REQUIRED)
find_package(spdlog REQUIRED)
find_package(cxxopts REQUIRED)

# Check for filesystem library requirements
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <filesystem>
    int main() {
        std::filesystem::path p;
        return 0;
    }"
    HAS_STD_FILESYSTEM
)

if(NOT HAS_STD_FILESYSTEM)
    link_libraries(stdc++fs)
endif()

# Platform specific configuration
if(APPLE)
    # Set Objective-C++ as the compiler for .cpp files on macOS
    set_source_files_properties(sync_daemon.cpp PROPERTIES 
        COMPILE_FLAGS "-x objective-c++ -Wno-deprecated-declarations"
    )
    
    find_library(CORE_SERVICES CoreServices REQUIRED)
    find_library(FOUNDATION Foundation REQUIRED)
    
    add_executable(sync_daemon sync_daemon.cpp)
    target_compile_definitions(sync_daemon PRIVATE
        USE_STD_FILESYSTEM=1
    )
    target_link_libraries(sync_daemon
        PRIVATE
        yaml-cpp
        spdlog::spdlog
        ${CORE_SERVICES}
        ${FOUNDATION}
        pthread
        cxxopts::cxxopts
    )
    install(TARGETS sync_daemon RUNTIME DESTINATION bin)
endif()

if(UNIX AND NOT APPLE)
    # Linux-specific packages
    find_package(SQLite3 REQUIRED)
    
    # Handle nlohmann_json
    find_package(nlohmann_json QUIET)
    if(NOT nlohmann_json_FOUND)
        include(FetchContent)
        FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
        FetchContent_MakeAvailable(json)
    endif()
    
    # Handle xxHash
    find_library(XXHASH_LIBRARY xxhash)
    find_path(XXHASH_INCLUDE_DIR xxhash.h)
    if(NOT XXHASH_LIBRARY OR NOT XXHASH_INCLUDE_DIR)
        message(FATAL_ERROR "xxHash library not found. Please install libxxhash-dev")
    endif()
    
    add_executable(sync_daemon_linux sync_daemon_linux.cpp)
    target_include_directories(sync_daemon_linux PRIVATE ${XXHASH_INCLUDE_DIR})
    target_compile_definitions(sync_daemon_linux PRIVATE
        USE_STD_FILESYSTEM=1
    )
    target_link_libraries(sync_daemon_linux
        PRIVATE
        yaml-cpp
        spdlog::spdlog
        SQLite3
        nlohmann_json::nlohmann_json
        ${XXHASH_LIBRARY}
        pthread
        cxxopts::cxxopts
    )
    install(TARGETS sync_daemon_linux RUNTIME DESTINATION bin)
endif()
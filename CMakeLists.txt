cmake_minimum_required(VERSION 3.12)
project(sync_daemon)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(yaml-cpp REQUIRED)
find_package(spdlog REQUIRED)
find_package(SQLite3)
find_package(nlohmann_json)
find_package(xxHash)

# macOS specific
if(APPLE)
    find_library(CORE_SERVICES CoreServices)
endif()

# Linux daemon
if(UNIX AND NOT APPLE)
    add_executable(sync_daemon_linux sync_daemon_linux.cpp)
    target_link_libraries(sync_daemon_linux
        PRIVATE
        yaml-cpp
        spdlog::spdlog
        SQLite::SQLite3
        nlohmann_json::nlohmann_json
        xxHash::xxHash
        pthread
    )
endif()

# macOS daemon
if(APPLE)
    add_executable(sync_daemon sync_daemon.cpp)
    target_link_libraries(sync_daemon
        PRIVATE
        yaml-cpp
        spdlog::spdlog
        ${CORE_SERVICES}
        pthread
    )
endif()

# Installation rules
install(TARGETS sync_daemon_linux sync_daemon
    RUNTIME DESTINATION bin
) 
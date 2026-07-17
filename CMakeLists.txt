cmake_minimum_required(VERSION 3.15)

project(
    NetworkThreatEngine
    VERSION 2.0.0
    DESCRIPTION "Real-Time Network Intrusion Detection System - 5-Layer Pipeline"
    LANGUAGES CXX
)

# Language Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build Type Default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler   : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Required Libraries
# libpcap
find_library(PCAP_LIBRARY
    NAMES pcap
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    REQUIRED
)
find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h pcap/pcap.h
    PATHS /usr/include /usr/local/include
    REQUIRED
)
message(STATUS "libpcap    : ${PCAP_LIBRARY}")

# SQLite3
find_package(SQLite3 REQUIRED)
message(STATUS "SQLite3    : ${SQLite3_LIBRARIES}")

# ncurses
find_package(Curses REQUIRED)
message(STATUS "ncurses    : ${CURSES_LIBRARIES}")

# POSIX Threads
find_package(Threads REQUIRED)

# Source Files
add_executable(packet_analyzer
    src/main.cpp
    src/CaptureLayer.cpp
    src/ProtocolDissector.cpp
    src/FlowTracker.cpp
    src/ThreatDetector.cpp
    src/DeliveryLayer.cpp
)

# Include Directories
target_include_directories(packet_analyzer
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
        ${CURSES_INCLUDE_DIR}
)

# Compiler Flags
target_compile_options(packet_analyzer
    PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Release>:-DNDEBUG>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -fstack-protector-strong
        -Wunused-parameter
        -Wunused-result
        -Wunused-function
)

# Linker
target_link_libraries(packet_analyzer
    PRIVATE
        ${PCAP_LIBRARY}
        SQLite::SQLite3
        ${CURSES_LIBRARIES}
        Threads::Threads
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# Preprocessor Definitions
target_compile_definitions(packet_analyzer
    PRIVATE
        _POSIX_C_SOURCE=200809L
        _GNU_SOURCE
        NTE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        NTE_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        NTE_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)

# Install
install(TARGETS packet_analyzer RUNTIME DESTINATION bin)

# Summary
message(STATUS "==================================================")
message(STATUS "  Target     : packet_analyzer")
message(STATUS "  C++ Std    : C++17")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  libpcap    : ${PCAP_LIBRARY}")
message(STATUS "  SQLite3    : ${SQLite3_LIBRARIES}")
message(STATUS "  ncurses    : ${CURSES_LIBRARIES}")
message(STATUS "  pthreads   : ${CMAKE_THREAD_LIBS_INIT}")
message(STATUS "===================================================")
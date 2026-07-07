cmake_minimum_required(VERSION 3.15)

project(NetworkThreatEngine
    VERSION 1.0
    DESCRIPTION "Real-Time Network Intrusion Detection System"
    LANGUAGES CXX)

# language standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type Default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Locate Required Libraries (libpcap)
find_library(PCAP_LIBRARY
    NAMES pcap
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
    REQUIRED
)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR
        "libpcap not found. Install it with: sudo apt install libpcap-dev"
    )
endif()
message(STATUS "Found libpcap: ${PCAP_LIBRARY}")

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h pcap/pcap.h
    PATHS /usr/include /usr/local/include
)
if(NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR
        "pcap.h not found. Install it with: sudo apt install libpcap-dev"
    )
endif()
message(STATUS "Found pcap.h: ${PCAP_INCLUDE_DIR}")

# Find Threads and SQLite3 for Week 3
find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED) 

if(NOT SQLite3_FOUND)
    message(FATAL_ERROR "SQLite3 not found. Install it with: sudo apt install libsqlite3-dev")
endif()
message(STATUS "Found SQLite3 Include : ${SQLite3_INCLUDE_DIRS}")
message(STATUS "Found SQLite3 Library : ${SQLite3_LIBRARIES}")

# Executable Target
add_executable(packet_analyzer
    src/main.cpp
    src/ProtocolDissector.cpp
    #src/ThreatEngine.cpp
)

# Include Directories
target_include_directories(packet_analyzer
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
        ${SQLite3_INCLUDE_DIRS}
)

# Compiler Flags
target_compile_options(packet_analyzer
    PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
 
        # Strict conformance and warning flags
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -fstack-protector-strong
)

# Linker Flags (Using direct variable ${SQLite3_LIBRARIES} for maximum compatibility)
target_link_libraries(packet_analyzer
    PRIVATE
        ${PCAP_LIBRARY}          
        Threads::Threads          
        ${SQLite3_LIBRARIES}      
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

# Install Rules
install(TARGETS packet_analyzer
    RUNTIME DESTINATION bin
)

# Summary
message(STATUS "=======================================")
message(STATUS "  Target     : packet_analyzer")
message(STATUS "  Standard   : C++17")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  libpcap    : ${PCAP_LIBRARY}")
message(STATUS "  SQLite3    : ${SQLite3_LIBRARIES}")
message(STATUS "  pthreads   : ${CMAKE_THREAD_LIBS_INIT}")
message(STATUS "=======================================")
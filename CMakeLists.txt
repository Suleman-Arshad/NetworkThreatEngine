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

# Locate Required Libraries
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
find_package(Threads REQUIRED)

# Executable Target
add_executable(packet_analyzer
    src/PacketRingBuffer.cpp
    src/ProtocolDissector.cpp
)

# Include Directories
target_include_directories(packet_analyzer
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${PCAP_INCLUDE_DIR}
)

# Compiler Flags
target_compile_options(packet_analyzer
    PRIVATE
        # Optimisation — full O3 for the hot capture and consumer path
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-march=native>
 
        # Debug build: no optimisation, full debug symbols, sanitisers
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g3>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
 
        # Strict conformance and warning flags (all build types)
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

# Linker Flags
target_link_libraries(packet_analyzer
    PRIVATE
        ${PCAP_LIBRARY}           # libpcap.so / libpcap.a
        Threads::Threads          # -lpthread (resolves platform correctly)
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# Preprocessor Definitions
target_compile_definitions(packet_analyzer
    PRIVATE
        # Expose the full POSIX API surface (required for pthread scheduling calls)
        _POSIX_C_SOURCE=200809L
        _GNU_SOURCE
        # Project version string available at runtime
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
message(STATUS "  pthreads   : ${CMAKE_THREAD_LIBS_INIT}")
message(STATUS "=======================================")
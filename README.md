# Real-Time Network Threat Detection Engine

[![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue?style=flat-square&logo=cplusplus)](https://isocpp.org/)
[![Build System](https://img.shields.io/badge/Build-CMake%203.15%2B-red?style=flat-square&logo=cmake)](https://cmake.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-yellow?style=flat-square&logo=linux)](https://kernel.org/)
[![Capture](https://img.shields.io/badge/Capture-libpcap-green?style=flat-square)](https://www.tcpdump.org/)
[![Database](https://img.shields.io/badge/Database-SQLite3-lightgrey?style=flat-square&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![Privileges](https://img.shields.io/badge/Execution-root%20required-critical?style=flat-square&logo=linux)](#execution)

> A high-performance, low-latency Network Intrusion Detection System (NIDS) built in Modern C++17 — capable of capturing, dissecting, tracking, and analysing live network traffic in real-time through a deterministic five-layer pipeline architecture.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture: The Five-Layer Pipeline](#2-system-architecture-the-five-layer-pipeline)
   - [Layer 1 — Capture Layer](#layer-1--capture-layer)
   - [Layer 2 — Protocol Dissection Layer](#layer-2--protocol-dissection-layer)
   - [Layer 3 — Flow Tracking Layer](#layer-3--flow-tracking-layer)
   - [Layer 4 — Analytics & Threat Detection Layer](#layer-4--analytics--threat-detection-layer)
   - [Layer 5 — Delivery & Visualization Layer](#layer-5--delivery--visualization-layer)
3. [High-Performance Design Principles](#3-high-performance-design-principles)
4. [Tech Stack](#4-tech-stack)
5. [Repository Directory Layout](#5-repository-directory-layout)
6. [System Prerequisites](#6-system-prerequisites)
7. [Installation of Dependencies](#7-installation-of-dependencies)
8. [Compilation and Build](#8-compilation-and-build)
9. [Execution](#9-execution)
10. [Runtime Behaviour: Example Terminal Output](#10-runtime-behaviour-example-terminal-output)
11. [Alert Schema and Database Structure](#11-alert-schema-and-database-structure)
12. [Threat Detection Rules](#12-threat-detection-rules)
13. [Development Roadmap](#13-development-roadmap)
14. [Security and Operational Notes](#14-security-and-operational-notes)
15. [Contributing](#15-contributing)
16. [License](#16-license)

---

## 1. Project Overview

The **Real-Time Network Threat Detection Engine** is a kernel-assisted, packet-level Network Intrusion Detection System (NIDS) engineered for deployment on Linux-based hosts and network appliances. The system captures every raw byte traversing a Network Interface Card (NIC) in promiscuous mode, reconstructs the full protocol stack from Layer 2 upward, and applies stateful, statistical anomaly-detection algorithms to identify active cyber attacks — all with sub-millisecond decision latency per packet.

The engine is designed around five discrete, independently optimised processing layers that form a strict unidirectional pipeline. Each layer has a single responsibility, a clearly defined input contract, and a well-typed output interface. This separation of concerns ensures the system remains maintainable as its ruleset scales and makes each layer independently testable and replaceable.

The primary attack surfaces targeted in the initial release are:

| Attack Type        | Detection Method                            | Layer Responsible |
|--------------------|---------------------------------------------|-------------------|
| Port Scan          | Per-host distinct-port counter + EWMA delta | Analytics (L4)    |
| SYN Flood (DoS)    | SYN-to-ACK ratio anomaly + EWMA velocity    | Analytics (L4)    |
| Half-Open Sessions | TCP state machine + timeout heuristics      | Flow (L3) + L4    |
| Abnormal Traffic Volume | EWMA baseline deviation per source IP | Analytics (L4)    |

The system is intentionally implemented without external rule-language dependencies (such as Snort rules or Suricata YAML configurations) in its core detection engine. All detection logic is expressed natively in C++17, granting full compiler optimisation access and removing interpreter overhead from the hot path.

---

## 2. System Architecture: The Five-Layer Pipeline

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                      LIVE NETWORK INTERFACE                      │
  │                    (NIC in Promiscuous Mode)                     │
  └───────────────────────────┬──────────────────────────────────────┘
                              │ Raw Ethernet Frames
                              ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 1 — CAPTURE LAYER                                         │
  │  libpcap + Raw Socket + 20MB Kernel Ring Buffer                  │
  │  ┌─────────────────────┐    ┌──────────────────────────────────┐ │
  │  │  Producer Thread    │───▶│  Thread-Safe Synchronized Queue  │ │
  │  │  (capture loop)     │    │  PacketRingBuffer                │ │
  │  └─────────────────────┘    └──────────────────────────────────┘ │
  └───────────────────────────┬──────────────────────────────────────┘
                              │ Raw Packet Bytes + Metadata
                              ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 2 — PROTOCOL DISSECTION LAYER                             │
  │  Ethernet → IP → TCP/UDP Header Parsing                         │
  │  Extracts: Src IP, Dst IP, Src Port, Dst Port, Flags, Payload   │
  └───────────────────────────┬──────────────────────────────────────┘
                              │ Parsed PacketInfo structs
                              ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 3 — FLOW TRACKING LAYER                                   │
  │  5-Tuple Hash → std::unordered_map<FlowKey, FlowRecord>          │
  │  Stateful bidirectional session accounting                       │
  └───────────────────────────┬──────────────────────────────────────┘
                              │ Enriched FlowRecord objects
                              ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 4 — ANALYTICS & THREAT DETECTION LAYER                    │
  │  EWMA Baseline Engine + Signature Rules                          │
  │  Port Scan Detector / SYN Flood Detector                        │
  └───────────────────────────┬──────────────────────────────────────┘
                              │ ThreatAlert objects
                              ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 5 — DELIVERY & VISUALIZATION LAYER                        │
  │  SQLite3 Persistence + ncurses Dashboard + REST API (SIEM)       │
  └──────────────────────────────────────────────────────────────────┘
```

---

### Layer 1 — Capture Layer

**Responsibility:** Acquire raw network frames from the NIC at wire speed with zero packet loss.

The Capture Layer is the entry point of the entire pipeline. It uses **libpcap** to open the target network interface in **promiscuous mode**, enabling the NIC to forward every frame on the wire to the host — including frames not addressed to the host's MAC address. This is essential for monitoring traffic on shared or spanned network segments.

The capture loop is permanently isolated in a dedicated **Producer Thread**. This design choice is architectural: the capture loop must never block waiting for downstream layers to process packets. If it did, the kernel's socket receive buffer would fill and the operating system would begin silently dropping frames — the most catastrophic failure mode for a NIDS.

To prevent this, all captured packets are immediately pushed into a **`PacketRingBuffer`** — a thread-safe, mutex-protected bounded queue implementing the Producer-Consumer concurrency pattern. The kernel-level receive socket buffer is tuned to **20 megabytes** via `SO_RCVBUF`, providing a large absorption window during traffic bursts.

**Key implementation characteristics:**
- Interface opened via `pcap_open_live()` with `PCAP_OPENFLAG_PROMISCUOUS`
- Kernel buffer size: `20 * 1024 * 1024` bytes (20 MB)
- Packet timestamping performed at kernel level (hardware timestamps when available)
- `PacketRingBuffer` uses `std::mutex` + `std::condition_variable` for zero-spin blocking handoff to consumer threads

---

### Layer 2 — Protocol Dissection Layer

**Responsibility:** Deserialise raw packet bytes into typed, named protocol structures.

The Dissection Layer receives a raw byte buffer and a length from the ring buffer and peels back the binary wire format of each protocol header, layer by layer:

```
Raw bytes → Ethernet Frame (14 bytes)
             └─ EtherType check (0x0800 = IPv4)
                └─ IP Header (20+ bytes)
                   ├─ Source IP (4 bytes, offset 12)
                   ├─ Destination IP (4 bytes, offset 16)
                   ├─ Protocol field (1 byte, offset 9) → TCP=6 / UDP=17
                   └─ TCP Header (20+ bytes, if Protocol == 6)
                      ├─ Source Port (2 bytes, offset 0)
                      ├─ Destination Port (2 bytes, offset 2)
                      └─ Flags byte (offset 13): SYN, ACK, FIN, RST, PSH, URG
```

All multi-byte integer fields are converted from **network byte order (big-endian)** to host byte order using `ntohs()` and `ntohl()` at parse time. The output of this layer is a populated `PacketInfo` struct passed by value into the Flow Tracking Layer.

Malformed or truncated packets — where the reported header lengths exceed the captured bytes — are **silently discarded** at this stage with an internal counter increment for diagnostics.

---

### Layer 3 — Flow Tracking Layer

**Responsibility:** Group individual packets into stateful, bidirectional network sessions.

A raw packet stream is just isolated data points. The Flow Tracking Layer adds *state* by associating every packet with a logical network session (called a **flow**). A flow is defined by a canonical **5-tuple key**:

```
FlowKey = {
    source_ip        : uint32_t,
    destination_ip   : uint32_t,
    source_port      : uint16_t,
    destination_port : uint16_t,
    protocol         : uint8_t   // TCP=6, UDP=17
}
```

To ensure bidirectional flows are matched under a single key regardless of which endpoint is the source in a given packet, the 5-tuple is **lexicographically normalised** before hashing: the lower IP/port pair is always placed in the first position.

The flow table is implemented as a `std::unordered_map<FlowKey, FlowRecord>`, where `FlowKey` uses a **custom hash functor** (FNV-1a or equivalent) for uniform distribution. Each `FlowRecord` maintains:

| Field                    | Type                              | Description                              |
|--------------------------|-----------------------------------|------------------------------------------|
| `first_seen`             | `std::chrono::steady_clock::time_point` | Timestamp of first packet in flow   |
| `last_seen`              | `std::chrono::steady_clock::time_point` | Timestamp of most recent packet     |
| `packet_count`           | `uint64_t`                        | Total packets observed in flow           |
| `byte_count`             | `uint64_t`                        | Total bytes observed in flow             |
| `syn_count`              | `uint32_t`                        | Number of SYN-flagged packets            |
| `ack_count`              | `uint32_t`                        | Number of ACK-flagged packets            |
| `fin_count`              | `uint32_t`                        | Number of FIN-flagged packets            |
| `state`                  | `enum FlowState`                  | INIT / SYN_SENT / ESTABLISHED / CLOSING  |
| `distinct_ports_contacted` | `std::unordered_set<uint16_t>` | Unique destination ports (scan detection)|

Flows that have seen no packets for longer than a configurable idle timeout (default: 120 seconds for TCP, 30 seconds for UDP) are **expired and evicted** from the map by a low-priority background reaper thread, preventing unbounded memory growth.

---

### Layer 4 — Analytics & Threat Detection Layer

**Responsibility:** Apply statistical models and signature rules to enriched flow data to produce verified threat alerts.

This layer is the analytical core of the engine. It processes each updated `FlowRecord` and maintains a per-host statistical model to distinguish normal baseline behaviour from attack patterns.

#### Exponentially Weighted Moving Average (EWMA) Baseline

For each unique source IP observed, the engine maintains an EWMA of **traffic velocity** (packets per second). The EWMA formula provides a dynamically adapting baseline that weights recent observations more heavily than older ones:

```
V_new = α × V_current  +  (1 - α) × V_baseline
```

Where:
- `V_current` is the instantaneous packet rate observed in the latest measurement window (default: 1 second)
- `V_baseline` is the stored EWMA for this host
- `α` (alpha) is the smoothing factor, default **0.15** — a low value that produces a slow-moving, stable baseline resistant to momentary spikes

An alert is raised when `V_current` deviates from `V_baseline` by more than a configurable **deviation multiplier** (default: **5×**). This self-calibrating model eliminates the need for hardcoded packet-per-second thresholds, allowing the engine to adapt to different network environments automatically.

#### Port Scan Detection

A port scan is identified when:
1. A source IP has contacted **more than N distinct destination ports** within a rolling time window (default: 50 ports in 10 seconds), **AND**
2. The **ratio of SYN packets to completed TCP handshakes** for that source exceeds a configured threshold (default: 80% SYN-only)

The `distinct_ports_contacted` set in the `FlowRecord` makes criterion (1) an O(1) check per packet.

#### SYN Flood Detection

A SYN Flood is identified when:
1. A single source IP sends SYN packets at a rate that triggers the EWMA velocity anomaly detector, **AND**
2. The SYN-to-ACK ratio across flows originating from that IP exceeds **10:1**

When either rule fires, a `ThreatAlert` object is constructed and passed downstream to Layer 5.

```cpp
struct ThreatAlert {
    std::string          attacker_ip;
    std::string          victim_ip;
    uint16_t             victim_port;
    AttackType           type;           // PORT_SCAN | SYN_FLOOD | VOLUME_ANOMALY
    double               confidence;     // 0.0 – 1.0
    std::time_t          timestamp;
    std::string          evidence_summary;
};
```

---

### Layer 5 — Delivery & Visualization Layer

**Responsibility:** Persist, display, and forward verified threat alerts through multiple output channels.

**SQLite3 Persistence:**
Each `ThreatAlert` is written synchronously to a local SQLite3 database (`threats.db`). The schema is designed for fast range queries by timestamp and IP address, supporting forensic retrospective analysis. All writes use prepared statements with bound parameters to prevent SQL injection and maximise write throughput.

**ncurses Real-Time Dashboard:**
The terminal dashboard, rendered via ncurses, provides a live operational view of engine state. It is updated at a configurable refresh rate (default: 2 Hz) in a dedicated display thread, decoupled from the detection pipeline. The dashboard panels display:
- Live packet ingestion rate (pps)
- Active flow count
- Top talkers by bandwidth (source IPs)
- Rolling alert feed with severity colouring
- Engine health statistics (queue depth, drop counter, memory usage)

**REST API for SIEM Integration:**
A lightweight HTTP server exposes a `/api/v1/alerts` endpoint accepting `GET` requests. Responses are JSON-serialised `ThreatAlert` payloads, enabling direct ingestion by Security Information and Event Management (SIEM) platforms such as Splunk, Elastic SIEM, or IBM QRadar via polling or webhook configuration.

---

## 3. High-Performance Design Principles

The engine is engineered around several systems-level design principles that collectively ensure it can sustain analysis at wire speed on modern hardware.

### Zero-Copy Capture Concept

In a naive packet capture implementation, each frame is copied multiple times: from the NIC DMA buffer → kernel socket buffer → user-space buffer. The engine minimises this overhead by:
- Using `libpcap`'s memory-mapped interface (`pcap_create` + `PCAP_TSTAMP_HOST`) which allows packet data to be read directly from a kernel-managed memory map
- Passing packet data through the pipeline as **non-owning `std::string_view` or raw pointer + length pairs** wherever possible, deferring heap allocation until the data must be persisted (e.g., on alert creation)

### Multi-Threaded Producer-Consumer Architecture

```
┌─────────────────────┐         ┌─────────────────────────────┐
│  Thread 1           │  push   │  PacketRingBuffer            │
│  Capture / Producer │────────▶│  (bounded, thread-safe queue)│
│  (libpcap loop)     │         └──────────────┬──────────────┘
└─────────────────────┘                        │ pop (blocking)
                                               ▼
                               ┌─────────────────────────────┐
                               │  Thread 2                   │
                               │  Consumer / Pipeline        │
                               │  (L2 → L3 → L4 → L5)       │
                               └─────────────────────────────┘
                                               +
                               ┌─────────────────────────────┐
                               │  Thread 3                   │
                               │  ncurses Display Refresh    │
                               └─────────────────────────────┘
                                               +
                               ┌─────────────────────────────┐
                               │  Thread 4                   │
                               │  Flow Table Reaper          │
                               └─────────────────────────────┘
```

The Producer Thread is given real-time scheduling priority (`SCHED_FIFO`) via `pthread_setschedparam()` to ensure the capture loop is never preempted during sustained traffic bursts.

### Kernel Buffer Tuning

The kernel receive socket buffer is enlarged beyond the OS default (typically 208 KB) to **20 MB** using `setsockopt(SO_RCVBUF)`. This dramatically increases the burst absorption capacity of the capture socket, providing the Producer Thread time to drain the buffer even during high-rate attack traffic.

### Compiler Optimisation

The CMake build is configured with `-O3` optimisation level, enabling the full suite of GCC/Clang loop vectorisation, function inlining, and branch prediction optimisation passes. The `-march=native` flag is optionally enabled to generate code tuned to the CPU microarchitecture of the build host.

---

## 4. Tech Stack

| Component              | Technology                     | Version / Notes                    |
|------------------------|--------------------------------|------------------------------------|
| **Language**           | C++17                          | ISO/IEC 14882:2017 standard        |
| **Build System**       | CMake                          | ≥ 3.15 required                    |
| **Capture Library**    | libpcap                        | `libpcap-dev` via apt              |
| **Concurrency Model**  | POSIX Threads / `std::thread`  | `pthread` linked via CMake         |
| **Flow Table**         | `std::unordered_map`           | C++17 STL                          |
| **Database**           | SQLite3                        | `libsqlite3-dev` via apt           |
| **Terminal UI**        | ncurses                        | `libncurses5-dev` via apt          |
| **Byte Order**         | POSIX `ntohs` / `ntohl`        | `<arpa/inet.h>`                    |
| **Compiler**           | GCC ≥ 9.0 or Clang ≥ 10.0     | C++17 support required             |
| **Target OS**          | Linux                          | Kernel ≥ 4.15 recommended          |

---

## 5. Repository Directory Layout

```
network-threat-engine/
│
├── CMakeLists.txt               # Root CMake build configuration
│                                # Defines targets, links libraries, sets -O3, -pthread
│
├── README.md                    # This document
│
├── LICENSE                      # Project license
│
├── src/                         # All translation units (.cpp)
│   ├── main.cpp                 # Entry point: CLI parsing, interface selection, thread launch
│   ├── CaptureLayer.cpp         # Layer 1: libpcap session, ring buffer producer
│   ├── ProtocolDissector.cpp    # Layer 2: Ethernet/IP/TCP/UDP header parsing
│   ├── FlowTracker.cpp          # Layer 3: 5-tuple flow table management + reaper
│   ├── ThreatDetector.cpp       # Layer 4: EWMA engine, port scan rule, SYN flood rule
│   └── DeliveryLayer.cpp        # Layer 5: SQLite3 writer, ncurses dashboard, REST endpoint
│
├── include/                     # All header files (.hpp)
│   ├── PacketRingBuffer.hpp     # Thread-safe bounded queue (Producer-Consumer)
│   ├── PacketInfo.hpp           # Parsed packet metadata struct
│   ├── FlowKey.hpp              # 5-tuple struct + custom hash functor
│   ├── FlowRecord.hpp           # Per-flow stateful accounting struct
│   ├── ThreatAlert.hpp          # Alert output struct + AttackType enum
│   ├── EWMAEngine.hpp           # Per-host EWMA baseline tracker
│   ├── PortScanDetector.hpp     # Port scan detection rule class
│   ├── SynFloodDetector.hpp     # SYN flood detection rule class
│   └── Config.hpp               # Compile-time and runtime configuration constants
│
└── docs/                        # Engineering documentation
    ├── architecture.md          # Detailed pipeline architecture with sequence diagrams
    ├── threat-model.md          # Attack categories, detection logic, and tuning guide
    └── performance-tuning.md    # Kernel buffer tuning, CPU affinity, NUMA considerations
```

---

## 6. System Prerequisites

The following prerequisites must be satisfied on the build and deployment host.

### Operating System

| Requirement       | Minimum Version         |
|-------------------|-------------------------|
| Linux Kernel      | 4.15 (for mmap pcap)    |
| Ubuntu / Debian   | Ubuntu 20.04 LTS or later |
| Architecture      | x86_64 (amd64)          |

### Compiler

```
GCC  ≥ 9.4.0    (provides full C++17 standard library support)
  OR
Clang ≥ 10.0.0
```

Verify your installed version:
```bash
g++ --version
# Expected: g++ (Ubuntu 11.x.x) 11.x.x
```

### Required System Libraries

| Library                  | apt Package Name       | Purpose                           |
|--------------------------|------------------------|-----------------------------------|
| GNU Build Tools          | `build-essential`      | GCC, G++, Make                    |
| CMake                    | `cmake`                | Build system generator            |
| libpcap (development)    | `libpcap-dev`          | Packet capture API headers + lib  |
| SQLite3 (development)    | `libsqlite3-dev`       | Embedded database headers + lib   |
| ncurses (development)    | `libncurses5-dev`      | Terminal UI headers + lib         |
| POSIX Threads            | Bundled with `libc6`   | Multi-threading (`-lpthread`)     |

### Privileges

> **Critical:** Raw socket access and promiscuous mode NIC configuration require **root-level privileges**. The engine must be executed as `root` or via `sudo`. Attempting execution as an unprivileged user will result in a `pcap_open_live()` permission error and immediate termination.

---

## 7. Installation of Dependencies

Run the following commands on Ubuntu 20.04 / 22.04 / 24.04 or any Debian-based distribution:

```bash
# Step 1: Refresh the package index
sudo apt update

# Step 2: Install all required build and runtime dependencies in a single pass
sudo apt install -y \
    build-essential \
    cmake \
    libpcap-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libncursesw5-dev

# Step 3: Verify core tool versions
gcc --version
cmake --version
pkg-config --modversion libpcap
pkg-config --modversion sqlite3
```

**Expected output of verification commands:**
```
gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
cmake version 3.22.1
1.10.4
3.39.2
```

---

## 8. Compilation and Build

The project uses a standard **out-of-source CMake build** pattern. All generated build artefacts (object files, Makefiles, the final binary) are placed inside a `build/` subdirectory, keeping the source tree clean.

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/network-threat-engine.git
cd network-threat-engine
```

### Step 2: Create the Build Directory

```bash
mkdir build
cd build
```

### Step 3: Configure the Build with CMake

```bash
cmake ..
```

This command reads `CMakeLists.txt` in the parent directory, detects the system compiler, locates all required libraries (`libpcap`, `sqlite3`, `ncurses`, `pthread`), and generates the native Makefiles. You should see output similar to:

```
-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is GNU 11.4.0
-- Detecting CXX compile features - done
-- Found PkgConfig: /usr/bin/pkg-config (found version "0.29.2")
-- Checking for module 'libpcap'
--   Found libpcap, version 1.10.4
-- Checking for module 'sqlite3'
--   Found sqlite3, version 3.39.2
-- Found Curses: /usr/lib/x86_64-linux-gnu/libcurses.so
-- Configuring with: -O3 -std=c++17 -pthread -march=native
-- Build type: Release
-- Configuring done
-- Generating done
-- Build files have been written to: /path/to/network-threat-engine/build
```

### Step 4: Compile

```bash
make -j$(nproc)
```

The `-j$(nproc)` flag parallelises the compilation across all available CPU cores. For a typical installation with 4–8 source files, compilation completes in under 30 seconds on modern hardware.

Successful compilation produces the binary:
```
build/packet_analyzer
```

### Optional: CMake Release Build with Explicit Flags

To manually verify that the optimisation flags are applied, you may invoke CMake with explicit build type:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-O3 -march=native" ..
make -j$(nproc)
```

### Full Build Sequence (Copy-Paste)

```bash
git clone https://github.com/your-org/network-threat-engine.git
cd network-threat-engine
mkdir build && cd build
cmake ..
make -j$(nproc)
```

---

## 9. Execution

### Identify Your Target Network Interface

Before launching the engine, determine the name of the network interface you wish to monitor:

```bash
ip link show
# or
ifconfig -a
```

Common interface names: `eth0`, `ens33`, `enp3s0`, `wlan0`, `lo` (loopback — limited utility for NIDS).

### Launch the Engine

Root privileges are **mandatory**:

```bash
sudo ./packet_analyzer --interface eth0
```

### Command-Line Options

| Flag                        | Description                                              | Default         |
|-----------------------------|----------------------------------------------------------|-----------------|
| `--interface <name>`        | Network interface to capture on (required)              | None (required) |
| `--buffer-size <MB>`        | Kernel receive buffer size in megabytes                  | `20`            |
| `--ewma-alpha <float>`      | EWMA smoothing factor (0.0–1.0; lower = more stable)    | `0.15`          |
| `--ewma-multiplier <float>` | Deviation multiplier to trigger volume anomaly alert    | `5.0`           |
| `--scan-port-threshold <n>` | Distinct ports per host per window to flag port scan    | `50`            |
| `--scan-window-sec <n>`     | Rolling time window in seconds for port scan detection  | `10`            |
| `--db-path <path>`          | Path to the SQLite3 alert database file                  | `./threats.db`  |
| `--flow-timeout-tcp <sec>`  | TCP flow idle expiry timeout in seconds                  | `120`           |
| `--flow-timeout-udp <sec>`  | UDP flow idle expiry timeout in seconds                  | `30`            |
| `--api-port <port>`         | TCP port to expose the REST alert API on                 | `8080`          |
| `--no-dashboard`            | Disable ncurses dashboard (useful for logging pipelines)| Off             |
| `--verbose`                 | Enable DEBUG-level diagnostic logging to stderr          | Off             |

---

## 10. Runtime Behaviour: Example Terminal Output

Upon successful launch, the engine emits structured log lines to `stdout` while the ncurses dashboard occupies the main terminal. With `--no-dashboard`, all output is delivered to `stdout`/`stderr`.

### Startup Sequence

```
[2025-06-24 09:00:01.003] [INFO]  Network Threat Detection Engine — Initialising
[2025-06-24 09:00:01.004] [INFO]  Target Interface    : eth0
[2025-06-24 09:00:01.004] [INFO]  Promiscuous Mode    : ENABLED
[2025-06-24 09:00:01.005] [INFO]  Kernel Ring Buffer  : 20971520 bytes (20 MB)
[2025-06-24 09:00:01.006] [INFO]  EWMA Alpha          : 0.15
[2025-06-24 09:00:01.006] [INFO]  EWMA Multiplier     : 5.00x
[2025-06-24 09:00:01.007] [INFO]  SQLite3 DB          : ./threats.db  [opened OK]
[2025-06-24 09:00:01.008] [INFO]  REST API            : Listening on 0.0.0.0:8080
[2025-06-24 09:00:01.009] [INFO]  Capture Thread      : Started  [PID=TID:14423, SCHED_FIFO prio=10]
[2025-06-24 09:00:01.009] [INFO]  Consumer Thread     : Started  [PID=TID:14424]
[2025-06-24 09:00:01.010] [INFO]  Display Thread      : Started  [PID=TID:14425, refresh=500ms]
[2025-06-24 09:00:01.010] [INFO]  Reaper Thread       : Started  [PID=TID:14426, interval=15s]
[2025-06-24 09:00:01.011] [INFO]  ─────────────────────────────────────────────────
[2025-06-24 09:00:01.011] [INFO]  Pipeline ONLINE. Capturing on eth0.
[2025-06-24 09:00:01.011] [INFO]  ─────────────────────────────────────────────────
```

### Normal Packet Processing

```
[2025-06-24 09:00:02.101] [PKT]   TCP  192.168.1.105:54321  →  93.184.216.34:443   SYN           flow=new
[2025-06-24 09:00:02.102] [PKT]   TCP  93.184.216.34:443    →  192.168.1.105:54321 SYN+ACK       flow=update
[2025-06-24 09:00:02.103] [PKT]   TCP  192.168.1.105:54321  →  93.184.216.34:443   ACK           flow=ESTABLISHED
[2025-06-24 09:00:02.887] [PKT]   UDP  192.168.1.1:53       →  192.168.1.105:49221 len=88        flow=update
[2025-06-24 09:00:03.001] [STAT]  Flows active: 47  |  Queue depth: 0  |  Ingestion: 1,204 pps  |  Dropped: 0
```

### Port Scan Detection Event

```
[2025-06-24 09:02:14.441] [WARN]  Port scan accumulation: 10.0.0.44 → distinct_ports=12 in 3.2s
[2025-06-24 09:02:17.983] [WARN]  Port scan accumulation: 10.0.0.44 → distinct_ports=31 in 6.7s
[2025-06-24 09:02:19.210] [ALERT] ╔══════════════════════════════════════════════════════╗
[2025-06-24 09:02:19.210] [ALERT] ║  THREAT DETECTED: PORT SCAN                         ║
[2025-06-24 09:02:19.210] [ALERT] ║  Attacker IP   : 10.0.0.44                          ║
[2025-06-24 09:02:19.210] [ALERT] ║  Victim IP     : 192.168.1.50                       ║
[2025-06-24 09:02:19.210] [ALERT] ║  Ports Scanned : 53 distinct ports in 9.8 seconds   ║
[2025-06-24 09:02:19.210] [ALERT] ║  SYN Ratio     : 97.2% SYN-only flows               ║
[2025-06-24 09:02:19.210] [ALERT] ║  Confidence    : 0.97                               ║
[2025-06-24 09:02:19.211] [ALERT] ║  Persisted to DB: alert_id=1042                     ║
[2025-06-24 09:02:19.211] [ALERT] ╚══════════════════════════════════════════════════════╝
```

### SYN Flood Detection Event

```
[2025-06-24 09:05:03.771] [WARN]  EWMA anomaly: 203.0.113.9 — current_rate=14,882 pps vs baseline=312 pps (47.7x deviation)
[2025-06-24 09:05:03.772] [WARN]  SYN flood check: 203.0.113.9 → SYN:ACK ratio = 14,210:43 (330.5:1)
[2025-06-24 09:05:03.773] [ALERT] ╔══════════════════════════════════════════════════════╗
[2025-06-24 09:05:03.773] [ALERT] ║  THREAT DETECTED: SYN FLOOD (DoS)                   ║
[2025-06-24 09:05:03.773] [ALERT] ║  Attacker IP   : 203.0.113.9                        ║
[2025-06-24 09:05:03.773] [ALERT] ║  Victim IP     : 192.168.1.50                       ║
[2025-06-24 09:05:03.773] [ALERT] ║  Victim Port   : 80 (HTTP)                          ║
[2025-06-24 09:05:03.773] [ALERT] ║  SYN Rate      : 14,882 pps (baseline: 312 pps)     ║
[2025-06-24 09:05:03.773] [ALERT] ║  SYN:ACK Ratio : 330.5 : 1                         ║
[2025-06-24 09:05:03.773] [ALERT] ║  Confidence    : 0.99                               ║
[2025-06-24 09:05:03.774] [ALERT] ║  Persisted to DB: alert_id=1043                     ║
[2025-06-24 09:05:03.774] [ALERT] ╚══════════════════════════════════════════════════════╝
```

### Graceful Shutdown

Send `SIGINT` (Ctrl+C) or `SIGTERM` to initiate an orderly shutdown:

```
^C
[2025-06-24 09:10:44.001] [INFO]  SIGINT received — initiating graceful shutdown
[2025-06-24 09:10:44.002] [INFO]  Capture Thread     : stopping pcap loop...
[2025-06-24 09:10:44.004] [INFO]  Capture Thread     : joined
[2025-06-24 09:10:44.005] [INFO]  Consumer Thread    : queue drained (0 remaining)
[2025-06-24 09:10:44.005] [INFO]  Consumer Thread    : joined
[2025-06-24 09:10:44.006] [INFO]  Reaper Thread      : joined
[2025-06-24 09:10:44.007] [INFO]  Display Thread     : ncurses teardown complete
[2025-06-24 09:10:44.008] [INFO]  SQLite3 DB         : closed cleanly
[2025-06-24 09:10:44.008] [INFO]  ─────────────────────────────────────────────
[2025-06-24 09:10:44.008] [INFO]  Session Summary:
[2025-06-24 09:10:44.008] [INFO]    Total Packets Captured : 4,821,047
[2025-06-24 09:10:44.008] [INFO]    Total Packets Dropped  : 0
[2025-06-24 09:10:44.008] [INFO]    Peak Ingestion Rate    : 15,204 pps
[2025-06-24 09:10:44.008] [INFO]    Total Flows Tracked    : 83,441
[2025-06-24 09:10:44.009] [INFO]    Total Alerts Generated : 2
[2025-06-24 09:10:44.009] [INFO]  Engine shutdown complete.
```

---

## 11. Alert Schema and Database Structure

All verified threat alerts are persisted to the SQLite3 database at the path specified by `--db-path` (default: `./threats.db`).

### Schema

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        INTEGER NOT NULL,          -- Unix epoch seconds
    timestamp_iso    TEXT    NOT NULL,          -- ISO-8601: "2025-06-24T09:02:19Z"
    attack_type      TEXT    NOT NULL,          -- 'PORT_SCAN' | 'SYN_FLOOD' | 'VOLUME_ANOMALY'
    attacker_ip      TEXT    NOT NULL,          -- Dotted-decimal IPv4
    victim_ip        TEXT    NOT NULL,
    victim_port      INTEGER,                   -- NULL for port scans (multiple ports)
    confidence       REAL    NOT NULL,          -- 0.0 – 1.0
    evidence_summary TEXT    NOT NULL,          -- Human-readable evidence string
    raw_metrics      TEXT                       -- JSON blob of raw counters
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_attacker   ON alerts(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_type       ON alerts(attack_type);
```

### REST API Response Format

`GET http://localhost:8080/api/v1/alerts?since=<unix_epoch>&limit=50`

```json
{
  "status": "ok",
  "count": 2,
  "alerts": [
    {
      "id": 1042,
      "timestamp_iso": "2025-06-24T09:02:19Z",
      "attack_type": "PORT_SCAN",
      "attacker_ip": "10.0.0.44",
      "victim_ip": "192.168.1.50",
      "victim_port": null,
      "confidence": 0.97,
      "evidence_summary": "53 distinct ports scanned in 9.8s; SYN-only ratio 97.2%"
    },
    {
      "id": 1043,
      "timestamp_iso": "2025-06-24T09:05:03Z",
      "attack_type": "SYN_FLOOD",
      "attacker_ip": "203.0.113.9",
      "victim_ip": "192.168.1.50",
      "victim_port": 80,
      "confidence": 0.99,
      "evidence_summary": "SYN rate 14882 pps vs EWMA baseline 312 pps (47.7x); SYN:ACK ratio 330.5:1"
    }
  ]
}
```

---

## 12. Threat Detection Rules

The following table documents all detection rules active in the current release, their governing parameters, and the corresponding configuration flags.

| Rule Name           | Algorithm              | Primary Signal                        | Trigger Condition                              | Config Flags                                        |
|---------------------|------------------------|---------------------------------------|------------------------------------------------|-----------------------------------------------------|
| Port Scan           | Counter + Ratio        | Distinct dst ports per src IP/window  | `distinct_ports ≥ threshold` AND SYN ratio `≥ 0.80` | `--scan-port-threshold`, `--scan-window-sec`   |
| SYN Flood           | EWMA + Ratio           | SYN pps vs EWMA baseline + SYN:ACK   | EWMA deviation `≥ multiplier` AND SYN:ACK `≥ 10:1` | `--ewma-alpha`, `--ewma-multiplier`             |
| Volume Anomaly      | EWMA                   | Total pps vs EWMA baseline per src IP | EWMA deviation `≥ multiplier` (no ratio check)  | `--ewma-alpha`, `--ewma-multiplier`              |
| Half-Open Session   | TCP State Machine      | SYN sent but no SYN-ACK within window | Flow state stuck in `SYN_SENT` for `> 5s` with `count ≥ 10` | `--flow-timeout-tcp` (indirectly)      |

---

## 13. Development Roadmap

The engine is structured as a five-phase development programme, with each phase completing a layer of the pipeline and enabling the next.

---

### Phase 1 — Capture Layer ✅

**Goal:** Capture raw packets from the NIC with zero loss.

- [x] Open NIC in promiscuous mode via `pcap_open_live()`
- [x] Enlarge kernel socket receive buffer to 20 MB via `SO_RCVBUF`
- [x] Isolate capture loop into dedicated `Producer Thread` with `SCHED_FIFO` priority
- [x] Implement `PacketRingBuffer` — thread-safe bounded queue with `std::mutex` + `std::condition_variable`
- [x] Implement packet drop counter and queue-depth monitoring
- [x] Graceful shutdown on `SIGINT` / `SIGTERM` via atomic flag

---

### Phase 2 — Protocol Dissection Layer ✅

**Goal:** Transform raw byte buffers into structured, named packet metadata.

- [x] Parse Ethernet II frame header: validate EtherType `0x0800` for IPv4
- [x] Parse IPv4 header: extract source IP, destination IP, protocol field, IHL
- [x] Parse TCP header: extract src port, dst port, sequence number, flags (SYN, ACK, FIN, RST, PSH, URG)
- [x] Parse UDP header: extract src port, dst port, length
- [x] Handle IP fragmentation detection (flag fragmented packets; full reassembly deferred to Phase 5)
- [x] Discard and count malformed packets (header length sanity checks)
- [x] Network-to-host byte order conversion for all multi-byte fields

---

### Phase 3 — Flow Tracking Layer ✅

**Goal:** Reconstruct stateful bidirectional sessions from the packet stream.

- [x] Define canonical `FlowKey` with 5-tuple normalisation and FNV-1a custom hash
- [x] Implement `std::unordered_map<FlowKey, FlowRecord>` flow table with `std::shared_mutex` (readers-writer lock)
- [x] Maintain per-flow counters: `packet_count`, `byte_count`, `syn_count`, `ack_count`, `fin_count`
- [x] Maintain TCP state machine: `INIT → SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT → CLOSED`
- [x] Maintain `distinct_ports_contacted` set per source IP for scan detection
- [x] Implement background flow reaper thread: expire and evict idle flows on configurable timeouts

---

### Phase 4 — Analytics & Threat Detection Layer 🔄 *(Active Development)*

**Goal:** Detect cyber attacks in real-time using statistical models.

- [x] Implement per-host `EWMAEngine`: velocity baseline with configurable alpha
- [x] Implement `PortScanDetector`: distinct-port threshold rule with SYN ratio gate
- [x] Implement `SynFloodDetector`: EWMA velocity anomaly + SYN:ACK ratio rule
- [x] Define `ThreatAlert` struct with confidence scoring
- [ ] Implement UDP amplification detection (response byte ratio anomaly)
- [ ] Implement ICMP sweep / ping scan detector
- [ ] Implement brute-force login attempt detector (repeated SYN to single port, e.g., 22, 3389)
- [ ] Add per-rule suppression intervals to prevent alert flooding on sustained attacks
- [ ] Introduce configurable whitelist / IP allowlist to suppress alerts from known-good sources

---

### Phase 5 — Delivery & Visualization Layer 🔜 *(Planned)*

**Goal:** Deliver alerts through multiple output channels with operational observability.

- [x] Implement SQLite3 persistence with prepared statements and indexed schema
- [x] Implement ncurses real-time dashboard with live packet rate and alert feed
- [x] Implement basic REST API (`/api/v1/alerts`) for SIEM polling
- [ ] Add `GET /api/v1/flows` endpoint for live flow table inspection
- [ ] Add `GET /api/v1/stats` endpoint for engine health metrics (queue depth, drop rate, memory)
- [ ] Implement JSON-over-UDP syslog forwarding for direct Splunk / rsyslog ingestion
- [ ] Add PCAP dump-on-alert capability: write the triggering flow's packets to a `.pcap` file for forensic replay
- [ ] Implement IPv6 support throughout the full pipeline (L2 through L5)
- [ ] Implement IP fragment reassembly for complete payload analysis
- [ ] Containerise with Docker for repeatable deployment on network monitoring hosts

---

## 14. Security and Operational Notes

- **Privilege Minimisation:** After the `pcap` capture handle is opened (which requires root for promiscuous mode), it is architecturally possible to drop privileges using `setuid()` / `setgid()` to a dedicated low-privilege service account. This capability is planned for a future hardening release.
- **Data Sensitivity:** The flow table and alert database may contain IP addresses and port metadata derived from monitored user traffic. Ensure the `threats.db` file and REST API endpoint are access-controlled appropriately for your deployment environment.
- **Legal Compliance:** Deploying a promiscuous-mode packet capture system on a network segment requires appropriate authorisation. Ensure you have explicit permission from the network owner before deploying this engine. Unauthorised interception of network traffic may constitute a criminal offence under applicable law.
- **False Positive Tuning:** In high-traffic environments with bursty but legitimate traffic (e.g., software update servers, CDN nodes), the EWMA multiplier (`--ewma-multiplier`) should be increased or the EWMA alpha (`--ewma-alpha`) should be decreased to widen the anomaly detection threshold and reduce false positives. Refer to `docs/threat-model.md` for detailed tuning guidance.

---

## 15. Contributing

Contributions are welcome. Please follow the standard fork-and-pull-request workflow:

1. Fork the repository and create a feature branch from `main`
2. Ensure all new code compiles cleanly under `-Wall -Wextra -Wpedantic -std=c++17`
3. Write or update unit tests for any new detection rule or data structure
4. Update `docs/architecture.md` if the pipeline structure is modified
5. Submit a pull request with a clear description of the change, the problem it solves, and any performance implications

Please open an issue before beginning work on a major architectural change to discuss the approach.

---

## 16. License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

*Real-Time Network Threat Detection Engine — engineered for clarity, performance, and operational reliability.*
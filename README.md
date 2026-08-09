# network-manager-rs

**A Rust-first, Linux-native network management stack.**

`network-manager-rs` is an actively developed Linux network-management daemon written in Rust 2024.

The project is building a modern networking stack around Linux-native interfaces such as **rtnetlink**, **generic netlink / nl80211**, native sockets, D-Bus, and Rust implementations of networking protocols.

The long-term goal is to provide a maintainable network-management implementation with a **NetworkManager-compatible D-Bus API**, allowing existing Linux applications and desktop environments to interact with the daemon through familiar interfaces while keeping the implementation underneath clean, typed, modular, and Rust-native.

> **Familiar Linux networking interfaces on the outside. A modern Rust networking stack underneath.**

---

## Project Status

The project has progressed substantially beyond its original read-only rtnetlink foundation.

The current implementation includes:

* Linux link enumeration
* IPv4 and IPv6 address enumeration
* rtnetlink link events
* rtnetlink address events
* native Wi-Fi discovery through `nl80211`
* Wi-Fi interface modelling
* access-point discovery
* Wi-Fi scanning
* WPA/RSN information parsing
* Wi-Fi supplicant integration
* typed connection profiles
* profile storage
* connection policy
* connection state management
* activation orchestration
* Linux IP configuration
* DHCP
* DNS configuration
* Linux activation engine
* network-namespace integration testing
* Rust-native integration test infrastructure
* `nmd` command-line tooling
* NetworkManager-compatible D-Bus facade
* typed D-Bus objects for networking devices, connections, access points, IP configuration, and DHCP configuration

The project is **not yet a drop-in replacement for NetworkManager**.

The current development focus is moving from core networking implementation toward **D-Bus compatibility validation, lifecycle correctness, and desktop integration**.

---

# Architecture

The implementation is intentionally layered.

```text
                         Linux Applications
                                |
                                v
                         System D-Bus
                                |
                                v
               NetworkManager-compatible API
                                |
                                v
                       Rust domain model
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
        Connection          Wi-Fi / Device      IP / DHCP / DNS
         Manager              Manager             Subsystems
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                     Linux-native backends
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
         rtnetlink           nl80211          Linux sockets
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                         Linux kernel
```

A core architectural principle is that **D-Bus is an API boundary rather than the internal networking architecture**.

The D-Bus compatibility layer maps external API requests onto the existing Rust domain and backend abstractions instead of reproducing NetworkManager's historical internal implementation.

---

# Linux-Native Networking

The project does not use command-line networking utilities as its networking backend.

The implementation intentionally avoids depending on:

* `ip`
* `ifconfig`
* `nmcli`
* `iw`
* shell networking scripts
* external DHCP command-line clients

Instead, networking functionality is implemented around Linux APIs and protocols including:

* rtnetlink
* generic netlink
* `nl80211`
* Linux sockets
* network namespaces
* D-Bus
* native protocol implementations
* narrowly scoped Linux FFI where required

This keeps the networking logic inside the Rust application rather than delegating system state management to shell commands.

---

# Rust 2024

The project uses the **Rust 2024 edition** with a declared minimum Rust version of **1.85**.

The implementation is Rust-first and does not maintain a separate C networking implementation.

Where Linux ABI interaction requires FFI, it is kept narrowly scoped to the relevant Linux interfaces.

The resulting architecture is intended to remain suitable for Linux environments using either:

* glibc
* musl

The project does not intentionally depend on a specific libc implementation for its core networking architecture.

---

# Rtnetlink

The rtnetlink backend provides typed access to Linux network state.

## Links

Current functionality includes:

* network interface enumeration
* interface indices
* interface names
* link flags
* link state
* loopback detection
* link creation events
* link removal events
* link state-change events

## Addresses

Current functionality includes:

* IPv4 address enumeration
* IPv6 address enumeration
* interface association
* prefix lengths
* address-added events
* address-removed events

Raw netlink messages are parsed inside the Linux backend and converted into typed Rust structures before being exposed to higher layers.

Higher-level code therefore does not need to understand netlink headers or kernel attribute encoding.

---

# Wi-Fi

Wi-Fi support is implemented using Linux's native **generic netlink / `nl80211`** interface.

Current functionality includes infrastructure for:

* wireless interface discovery
* wireless device modelling
* access-point discovery
* SSID representation
* BSSID representation
* frequency information
* signal strength
* Wi-Fi interface types
* authentication and cipher modelling
* Wi-Fi scanning
* WPA/RSN information parsing
* Wi-Fi event infrastructure

The Wi-Fi subsystem is intended for **normal network management and connectivity**, not wireless security testing or attack functionality.

The intended flow is:

```text
Wi-Fi discovery
      |
      v
Access-point selection
      |
      v
Authentication / supplicant
      |
      v
Connection activation
      |
      v
IP configuration
      |
      v
DNS configuration
```

---

# Connection Management

The project contains a typed connection-management architecture.

The major components include:

* connection profiles
* profile validation
* profile storage
* secret-provider abstraction
* autoconnect policy
* connection state machines
* connection events
* activation management
* activation engines
* device information

The architecture separates policy from activation:

```text
Connection Profile
        |
        v
      Policy
        |
        v
Activation Manager
        |
        v
Activation Engine
        |
        v
Linux Networking
```

This makes connection behaviour independently testable and allows different activation mechanisms to be introduced without rewriting the domain model.

---

# IP Configuration

The Linux activation layer can coordinate IP configuration as part of connection activation.

The current architecture covers:

* interface configuration
* IPv4 configuration
* IPv6-aware networking state
* routes required for activation
* gateway information
* DNS configuration
* connection teardown

The implementation communicates with Linux networking APIs directly rather than invoking `ip` or other networking commands.

---

# DHCP

DHCP functionality has been integrated into the activation stack.

The DHCP layer participates in connection activation and provides configuration information to the IP engine.

The project also contains integration tests that exercise DHCP behaviour in isolated Linux network namespaces.

The goal is to make DHCP part of the managed connection lifecycle rather than an opaque external process.

---

# DNS

DNS configuration is represented as part of connection activation rather than being treated as an unrelated side effect.

The current implementation provides the foundation for:

* DNS server configuration
* DNS information returned through DHCP
* DNS state exposed through the domain model
* D-Bus IPv4 configuration data

More advanced DNS policy remains future work, including areas such as:

* split DNS
* per-connection resolver policy
* VPN-aware DNS
* resolver backend integration

---

# D-Bus

A NetworkManager-compatible D-Bus facade has now been added.

The facade is implemented using **zbus** and exposes typed objects over the system D-Bus architecture.

Current D-Bus work covers the major object families needed for the compatibility layer, including:

* NetworkManager root object
* devices
* Ethernet devices
* Wi-Fi devices
* access points
* active connections
* connection profiles
* settings
* IPv4 configuration
* IPv6 configuration
* DHCP configuration
* D-Bus signals
* settings-dictionary conversion

The facade is designed as a translation layer over the existing Rust networking model.

It does **not** maintain a completely independent networking state database.

```text
NetworkManager-compatible D-Bus API
                 |
                 v
          D-Bus compatibility
                 |
                 v
           Rust domain model
                 |
                 v
       NetworkBackend / engines
                 |
                 v
            Linux kernel
```

### Compatibility status

The D-Bus API surface is under active development.

The next compatibility milestone is to validate the implementation against:

* actual system D-Bus behaviour
* D-Bus introspection
* object lifecycle
* property semantics
* method signatures
* signal behaviour
* NetworkManager-compatible clients
* desktop integration

The existence of an API with NetworkManager-compatible names does **not yet mean that every NetworkManager client will work without compatibility gaps**.

That distinction is intentional and documented.

---

# `nmd`

The project includes the `nmd` command-line interface.

Current commands include:

```text
nmd links
nmd addresses
nmd wifi
nmd wifi scan
nmd connections
nmd monitor
nmd connect <profile> <interface>
nmd disconnect <interface>
```

The CLI provides a convenient operational and debugging surface for the underlying networking stack.

It is not intended to replace the D-Bus API as the primary application integration interface.

---

# Network Namespace Integration Testing

Networking code requires more than unit tests.

The repository contains a Rust-native Linux network-namespace integration harness.

The integration environment can create isolated networking environments and exercise real kernel networking behaviour without requiring production host networking to be modified.

The harness covers areas including:

* network namespaces
* virtual Ethernet interfaces
* rtnetlink operations
* DHCP
* IP activation
* connection teardown
* route configuration
* DNS/resolver configuration

The project deliberately moved away from shell-based integration testing toward Rust-native test infrastructure.

This allows the test suite to exercise the same architectural primitives used by the production implementation.

---

# Testing

The project uses several layers of verification.

## Unit Tests

Deterministic tests cover areas such as:

* rtnetlink parsing
* IPv4 parsing
* IPv6 parsing
* malformed netlink messages
* malformed attributes
* generic-netlink parsing
* Wi-Fi information elements
* WPA/RSN parsing
* connection state transitions
* profile validation
* connection policy
* DHCP behaviour
* settings conversion
* D-Bus translation

## Integration Tests

Linux integration testing covers real kernel behaviour including:

* network namespaces
* virtual Ethernet devices
* DHCP
* IP activation
* connection teardown

The repository's Rust-native network-namespace harness has successfully exercised the DHCP and IP activation path in an isolated environment.

## Verification Standard

The project uses:

```text
cargo fmt
cargo test
cargo clippy
```

as the baseline Rust verification gate, supplemented by Linux integration testing where kernel behaviour is involved.

---

# Security and Privilege Model

Network management is privileged infrastructure.

The architecture therefore distinguishes between:

### Read-only operations

Examples:

* device discovery
* link inspection
* address inspection
* Wi-Fi discovery
* access-point inspection
* connection inspection

and:

### State-changing operations

Examples:

* connection activation
* connection deactivation
* interface configuration
* route changes
* DNS changes
* Wi-Fi authentication
* profile modification

The long-term D-Bus architecture will use the appropriate Linux authorization mechanisms rather than treating every D-Bus client as equally trusted.

Secrets are deliberately isolated behind secret-provider abstractions instead of being embedded directly into the core connection profile model.

---

# No Shell Networking Backend

One of the project's explicit goals is reducing dependence on shell orchestration for networking.

Instead of:

```text
Rust
 |
 +--> shell
       |
       +--> ip
       +--> iw
       +--> dhclient
       +--> other tools
```

the intended architecture is:

```text
Rust
 |
 +--> rtnetlink
 +--> nl80211
 +--> Linux sockets
 +--> DHCP
 +--> D-Bus
 +--> Linux kernel
```

This makes the implementation easier to test, reason about, embed, and eventually deploy in systems with a minimal userspace.

---

# Compatibility Strategy

The project is **not attempting to reproduce obsolete internal NetworkManager architecture**.

Instead, compatibility is being approached at the interface boundary.

The strategy is:

1. Identify interfaces required by modern Linux applications.
2. Preserve compatible object names and API semantics where appropriate.
3. Implement those interfaces over the Rust domain model.
4. Validate behaviour against current Linux networking clients.
5. Expand compatibility based on actual application requirements.

This allows the implementation underneath to remain modern while the external API remains familiar.

---

# Current Limitations

Despite the substantial progress, this remains an active development project.

It should **not yet be installed as a production replacement for NetworkManager on a machine where network availability is critical**.

Known areas still requiring substantial work include:

* complete NetworkManager D-Bus compatibility
* real desktop-client compatibility testing
* comprehensive D-Bus lifecycle behaviour
* authorization / polkit integration
* robust long-running daemon supervision
* connection reconciliation
* connection failure recovery
* suspend/resume handling
* hardware lifecycle management
* complete route management
* advanced DNS policy
* VPN support
* broader Wi-Fi lifecycle management
* persistent configuration hardening
* production deployment integration

These are known roadmap items rather than undocumented gaps.

---

# Roadmap

## Completed Foundations

* [x] Rust 2024 migration
* [x] Linux link enumeration
* [x] rtnetlink link monitoring
* [x] IPv4/IPv6 address enumeration
* [x] address monitoring
* [x] typed network events
* [x] Wi-Fi discovery foundation
* [x] `nl80211` integration
* [x] access-point modelling
* [x] Wi-Fi scanning
* [x] connection profiles
* [x] connection state machine
* [x] activation architecture
* [x] Linux IP engine
* [x] DHCP integration
* [x] DNS integration
* [x] Linux network-namespace integration testing
* [x] Rust-native integration harness
* [x] `nmd` management CLI
* [x] NetworkManager-compatible D-Bus facade

## Current Milestone

**D-Bus compatibility validation and lifecycle hardening**

Planned work includes:

* [ ] system-bus integration
* [ ] D-Bus introspection validation
* [ ] object lifecycle validation
* [ ] property semantics validation
* [ ] method compatibility validation
* [ ] signal validation
* [ ] real-client compatibility testing
* [ ] compatibility gap documentation
* [ ] daemon lifecycle hardening

## Future Platform Work

* [ ] complete NetworkManager API coverage
* [ ] polkit authorization
* [ ] robust connection reconciliation
* [ ] advanced DNS policy
* [ ] VPN integration
* [ ] suspend/resume handling
* [ ] hardware lifecycle management
* [ ] connection recovery
* [ ] broader desktop integration
* [ ] production deployment hardening

---

# Design Principles

The project follows several core engineering principles:

1. **Rust-first**
2. **Linux-native**
3. **No shell commands as networking backends**
4. **Typed domain models**
5. **Clear subsystem boundaries**
6. **Deterministic testing**
7. **Real kernel integration testing**
8. **Minimal unnecessary dependencies**
9. **Explicit privilege boundaries**
10. **Compatibility at the API boundary**
11. **No unnecessary reproduction of legacy internals**
12. **Correctness before feature-count inflation**

---

# Intended Use

`network-manager-rs` is intended to become infrastructure for Linux systems that require a modern, programmable network-management stack.

Potential deployment environments include:

* general Linux distributions
* desktop Linux
* custom Linux distributions
* embedded Linux systems
* minimal Linux environments
* Rust-based operating-system projects
* specialized Linux appliances

The architecture is designed to remain useful whether the surrounding userspace is large and conventional or deliberately minimal.

---

# Project Maturity

**Status: Active development / pre-production**

The networking foundation is substantially implemented.

The connection and activation layers are operational in isolated integration environments.

The NetworkManager-compatible D-Bus facade is now present and entering compatibility validation.

The project is **not yet a drop-in replacement for NetworkManager** and APIs may continue to evolve.

---

# License

This project is released under the **MIT No Attribution (MIT-0)** license.

See [`LICENSE`](LICENSE) for the complete license text.

A separate patent grant is also included in the repository.

---

# Contributing

Contributions and technical review are welcome.

Particularly useful areas include:

* Linux networking expertise
* rtnetlink / generic-netlink expertise
* Wi-Fi and `nl80211`
* DHCP
* DNS
* D-Bus
* NetworkManager compatibility
* desktop Linux integration
* Linux network-namespace testing
* Rust systems programming

The preferred direction is to improve the existing architecture rather than introducing parallel implementations of functionality already provided by the core Rust domain.

# network-manager-rs

**A Rust-first, Linux-native network management daemon and compatibility platform.**

`network-manager-rs` is a ground-up implementation of a Linux network management stack written in Rust.

The project is designed around a straightforward premise:

> **Keep the public Linux networking experience compatible where it matters, while replacing fragile shell-driven orchestration and legacy internal architecture with a modern, strongly typed Rust implementation.**

The objective is not to reproduce NetworkManager's internal implementation.

The objective is to provide the capabilities Linux applications and desktop environments expect from a network manager while maintaining a cleaner, modular, testable, Linux-native implementation underneath.

---

## Current Status

This project has progressed beyond the initial networking-foundation stage.

The current stack includes substantial work across:

* Linux link discovery and monitoring
* IPv4/IPv6 address discovery and monitoring
* native rtnetlink integration
* native generic-netlink / `nl80211` Wi-Fi discovery
* Wi-Fi access-point modelling and scanning
* Wi-Fi supplicant integration
* typed connection profiles
* profile storage
* connection policy
* connection state management
* activation orchestration
* Linux IP configuration
* DHCP
* DNS handling
* composite activation engines
* Linux network-namespace integration testing
* a Rust-native integration harness
* `nmd` command-line management tooling
* D-Bus integration groundwork
* NetworkManager-compatible API architecture

The project is now transitioning from **Linux networking primitives** into the **system integration and compatibility layer** required for a production-oriented network manager.

It is still under active development and should not yet be considered a drop-in replacement for NetworkManager.

---

# Architecture

The architecture is deliberately layered.

```text
                    Linux Applications
                           |
                           |
                     System D-Bus
                           |
                           v
              NetworkManager-compatible
                   compatibility API
                           |
                           v
                 Rust domain model
                           |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
   Connection          Device/Wi-Fi      IP/DHCP/DNS
    Manager              subsystem         subsystem
        |                  |                  |
        +------------------+------------------+
                           |
                           v
                 Linux-native backends
                           |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
     rtnetlink          nl80211             sysfs
        |                  |                  |
        +------------------+------------------+
                           |
                           v
                       Linux kernel
```

The important architectural rule is that **D-Bus is a compatibility boundary, not the internal architecture**.

NetworkManager-compatible interfaces should translate into the existing Rust domain rather than forcing the entire implementation to imitate NetworkManager's historical internals.

---

# Linux-Native by Design

Core networking functionality is implemented against Linux APIs directly.

The project intentionally does **not** use networking command-line utilities as hidden implementation backends.

The architecture avoids depending on:

* `ip`
* `ifconfig`
* `nmcli`
* `iw`
* `dhclient`
* shell networking scripts
* other command-line networking utilities

Instead, the project uses mechanisms such as:

* rtnetlink
* generic netlink
* `nl80211`
* Linux sockets
* sysfs
* kernel networking interfaces
* D-Bus
* native Rust implementations of required protocols and services

This makes the networking stack substantially easier to reason about, test, embed, and eventually deploy independently of a traditional GNU/Linux userspace.

---

# Rust-First

The implementation is written in Rust 2024.

The project intentionally keeps the implementation Rust-native rather than introducing a C implementation layer.

Linux ABI interaction may use narrowly scoped FFI where required to communicate with kernel interfaces, but the project does not require a custom C codebase.

This keeps the core architecture suitable for environments built around either:

* glibc
* musl

The goal is not to tie the daemon unnecessarily to one particular userspace implementation.

---

# Networking Foundation

The rtnetlink layer currently provides typed access to Linux network state.

Supported areas include:

### Links

* interface enumeration
* interface indices
* interface names
* interface flags
* link state
* loopback identification
* link creation/removal/state-change events

### Addresses

* IPv4 addresses
* IPv6 addresses
* interface association
* prefix lengths
* address enumeration
* address-added events
* address-removed events

The event system converts raw kernel notifications into typed Rust events before they reach higher layers.

That separation is intentional.

Higher-level code should not need to understand netlink message headers or kernel attribute encoding.

---

# Wi-Fi

The Wi-Fi subsystem is built around Linux's native `nl80211` generic-netlink interface.

Current functionality includes infrastructure for:

* wireless interface discovery
* wireless device modelling
* access-point discovery
* BSSID representation
* SSID representation
* channel/frequency information
* signal information
* Wi-Fi authentication/cipher modelling
* scan results
* WPA/RSN information parsing
* Wi-Fi event handling
* supplicant integration

The project is a **network manager**, not a Wi-Fi security-testing framework.

Wi-Fi functionality exists to manage normal Linux connectivity:

```text
discover
    ↓
select network
    ↓
authenticate through the appropriate supplicant/control path
    ↓
activate connection
    ↓
configure IP
    ↓
maintain state
```

No wireless attack functionality is part of the project objective.

---

# Connection Management

The project now contains a typed connection-management architecture rather than treating connections as ad-hoc command execution.

Core concepts include:

* connection profiles
* profile validation
* profile storage
* secret-provider boundaries
* autoconnect policy
* connection state machines
* activation managers
* activation engines
* device information
* typed connection events

The architecture deliberately separates:

```text
Profile
   |
Policy
   |
ActivationManager
   |
ActivationEngine
   |
Linux networking
```

This allows the public API layer to remain independent from the underlying implementation.

---

# IP Configuration

The project includes a Linux-native IP activation layer capable of coordinating:

* interface configuration
* IPv4 configuration
* IPv6-aware state
* routes required by activation
* gateway configuration
* DNS information
* teardown

The implementation is designed around direct kernel networking APIs rather than invoking `ip` or similar utilities.

---

# DHCP

DHCP functionality is implemented as part of the networking stack rather than delegated to an external command-line DHCP client.

The DHCP layer participates in connection activation and provides the resulting configuration to the IP engine.

The architecture allows DHCP state to become part of the higher-level connection state rather than existing as an opaque external process.

---

# DNS

DNS handling is separated into its own subsystem.

The activation architecture treats DNS configuration as a managed component rather than an incidental side effect of obtaining an IP address.

This is important for eventually supporting:

* desktop environments
* multiple active connections
* per-connection DNS policy
* VPN integration
* split DNS
* different resolver backends

The current implementation remains intentionally narrower than a complete production DNS policy engine.

---

# Integration Testing

Network management code cannot be validated purely through unit tests.

The project therefore includes Linux network-namespace integration testing.

The integration infrastructure can construct isolated networking environments and validate real kernel behavior without modifying the host's production network configuration.

The integration test architecture uses Rust-native mechanisms for:

* network namespaces
* virtual Ethernet interfaces
* rtnetlink configuration
* DHCP testing
* IP activation
* teardown validation

The previous shell-based network integration harness has been replaced with a Rust-native integration harness.

This is an intentional architectural decision:

> **The test infrastructure should exercise the same Linux APIs the production implementation uses.**

---

# `nmd`

The project includes an `nmd` command-line interface for interacting with the daemon functionality.

Current functionality spans inspection and management operations including:

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

The CLI is primarily an operational/debugging surface.

It is not intended to become the primary application API.

The long-term desktop/application integration surface is D-Bus.

---

# NetworkManager Compatibility

A major long-term objective is compatibility with the interfaces expected by existing Linux desktop environments and applications.

The project is therefore building a **NetworkManager-compatible D-Bus facade**.

The design principle is:

```text
NetworkManager-compatible API
            |
            v
      compatibility layer
            |
            v
       Rust domain
            |
            v
      Linux backends
```

This allows applications to interact with the project through familiar Linux networking APIs without requiring the internal implementation to reproduce NetworkManager's historical architecture.

Compatibility will be implemented incrementally.

The project will prioritize the APIs actually required by modern Linux desktop environments and applications rather than attempting to blindly reproduce every historical interface from day one.

---

# Desktop Compatibility

The intended integration target is the existing Linux desktop ecosystem.

The project is designed to eventually support applications and environments such as:

* GNOME
* KDE Plasma
* XFCE
* Cinnamon
* MATE
* LXQt
* COSMIC
* other environments using standard Linux networking APIs

The objective is **application compatibility**, not requiring a custom desktop environment.

---

# Security Model

Network management is privileged infrastructure.

The architecture therefore distinguishes between:

### Observation

Examples:

* enumerate devices
* inspect addresses
* inspect Wi-Fi state
* inspect connection state

and:

### State-changing operations

Examples:

* activate a connection
* modify a profile
* configure an interface
* modify routes
* modify DNS
* manage Wi-Fi credentials

The D-Bus layer will eventually enforce an appropriate Linux authorization model rather than treating every connected client as fully trusted.

Secrets are intentionally kept behind provider abstractions rather than being embedded directly into the core connection model.

---

# Testing Philosophy

The project uses several layers of verification.

### Deterministic unit tests

Used for:

* netlink parsing
* generic-netlink parsing
* Wi-Fi information elements
* connection state machines
* profile validation
* policy decisions
* DHCP protocol behavior
* translation logic

### Integration tests

Used for:

* Linux network namespaces
* virtual interfaces
* DHCP
* IP activation
* connection teardown
* kernel interaction

### Real-system compatibility testing

The project also benefits from observing real Linux systems for:

* D-Bus object layouts
* device state
* Wi-Fi state
* NetworkManager compatibility behavior
* kernel networking behavior

Potentially disruptive network experiments should be isolated using network namespaces or disposable virtual interfaces rather than treating a production host connection as a test fixture.

---

# Development Principles

The project follows several non-negotiable engineering principles:

1. **Rust-first**
2. **Linux-native**
3. **No shell commands as networking backends**
4. **Typed domain models**
5. **Explicit subsystem boundaries**
6. **Deterministic tests wherever possible**
7. **Real kernel integration tests where necessary**
8. **No unnecessary dependencies**
9. **Security and authorization are architectural concerns**
10. **Compatibility belongs at the API boundary**
11. **Do not reproduce legacy implementation architecture unnecessarily**
12. **Prefer correctness over feature-count inflation**

---

# Current Limitations

This is still an actively developed network-management stack.

It is **not yet a drop-in replacement for NetworkManager**.

Remaining work includes substantial areas such as:

* complete D-Bus compatibility
* broader device support
* complete route management
* production-grade policy/reconciliation
* robust persistent configuration
* complete Wi-Fi connection lifecycle management
* VPN integration
* advanced DNS policy
* complete desktop compatibility
* authorization/polkit integration
* suspend/resume handling
* hardware lifecycle handling
* connection failure recovery
* richer observability
* long-running daemon lifecycle management
* comprehensive compatibility testing against real applications

These are deliberate future milestones rather than hidden functionality.

---

# Roadmap

The project is progressing toward a layered Linux network-management platform.

### Foundation

* [x] Rust 2024 foundation
* [x] Linux link enumeration
* [x] rtnetlink link events
* [x] IPv4/IPv6 address enumeration
* [x] address events
* [x] typed networking domain

### Connectivity

* [x] Wi-Fi discovery foundation
* [x] access-point modelling
* [x] Wi-Fi scanning
* [x] connection profiles
* [x] activation architecture
* [x] Linux IP engine
* [x] DHCP foundation
* [x] DNS integration
* [x] isolated Linux integration testing

### Compatibility

* [ ] NetworkManager-compatible D-Bus service
* [ ] manager/device object model
* [ ] settings/profile compatibility
* [ ] active connection compatibility
* [ ] IP configuration compatibility
* [ ] Wi-Fi D-Bus compatibility
* [ ] desktop application compatibility testing

### Production Platform

* [ ] robust reconciliation engine
* [ ] complete authorization model
* [ ] VPN subsystem
* [ ] advanced DNS policy
* [ ] suspend/resume
* [ ] hardware lifecycle management
* [ ] comprehensive recovery behavior
* [ ] production deployment integration

---

# Why This Project Exists

Linux networking is already backed by extremely capable kernel APIs.

The problem is not the kernel.

The challenge is building a coherent userspace management layer that can:

* understand those APIs;
* maintain consistent state;
* coordinate multiple networking subsystems;
* expose stable interfaces to applications;
* handle failures correctly;
* remain testable;
* remain maintainable for years.

`network-manager-rs` is an attempt to build that layer from the ground up in Rust.

The strategic goal is simple:

> **Modernize the implementation without breaking the Linux ecosystem around it.**

Same ecosystem.

Familiar interfaces.

Different engine.

---

# License

`network-manager-rs` is released under the **MIT No Attribution (MIT-0)** license.

See [`LICENSE`](LICENSE) for the full license text.

A separate patent grant is also included in the repository.

---

## Project Status

**Active development — experimental / pre-production.**

The architecture is evolving rapidly and APIs should not yet be assumed stable.

Contributions, architectural review, Linux compatibility testing, and implementation feedback are welcome.

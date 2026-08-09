# network-manager-rs

`network-manager-rs` is an early Rust-first foundation for a Linux-native network
management daemon. The project goal is to use native Linux interfaces directly
instead of shelling out to tools such as `ip`, `ifconfig`, `nmcli`, or `iw`.

## Current phase

Phase 2 establishes read-only rtnetlink event monitoring on top of the Phase 1
snapshot foundation:

- a daemon binary (`nmd`) with non-destructive `links` and `monitor` commands;
- a Linux networking abstraction trait for snapshots and typed events;
- direct rtnetlink link enumeration and `RTMGRP_LINK` multicast monitoring;
- typed link creation, removal, and state-change events;
- deterministic parser tests built from synthetic netlink fixtures.

This phase intentionally does not configure interfaces, manage Wi-Fi, run DHCP,
change DNS, alter routes, manage VPNs, persist policy, or expose
NetworkManager-compatible D-Bus APIs yet.

## Build and test

```console
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Commands

```console
cargo run -- links
cargo run -- monitor
```

`nmd monitor` subscribes to rtnetlink link multicast notifications and prints
human-readable link events until interrupted with Ctrl-C.

## Architecture direction

The daemon should grow around narrow subsystems backed by Linux-native APIs:

- rtnetlink for link/address/route state and changes;
- sysfs/ethtool APIs for device metadata;
- D-Bus for desktop-facing compatibility surfaces;
- DHCP, DNS, Wi-Fi, VPN, and policy engines as later explicit subsystems.

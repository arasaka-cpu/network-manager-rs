# network-manager-rs

`network-manager-rs` is an early Rust-first foundation for a Linux-native network
management daemon. The project goal is to use native Linux interfaces directly
instead of shelling out to tools such as `ip`, `ifconfig`, `nmcli`, or `iw`.

## Current phase

Phase 1 establishes a small, testable daemon foundation:

- a daemon binary (`nmd`) with a non-destructive `links` command;
- a Linux networking abstraction trait;
- a direct rtnetlink implementation for enumerating kernel network links;
- parser tests built from deterministic netlink fixtures.

This phase intentionally does not configure interfaces, manage Wi-Fi, run DHCP,
change DNS, or expose NetworkManager-compatible D-Bus APIs yet.

## Build and test

```console
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Architecture direction

The daemon should grow around narrow subsystems backed by Linux-native APIs:

- rtnetlink for link/address/route state and changes;
- sysfs/ethtool APIs for device metadata;
- D-Bus for desktop-facing compatibility surfaces;
- DHCP, DNS, Wi-Fi, VPN, and policy engines as later explicit subsystems.

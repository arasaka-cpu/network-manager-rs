# network-manager-rs

`network-manager-rs` is an early Rust-first foundation for a Linux-native network
management daemon. The project goal is to use native Linux interfaces directly
instead of shelling out to tools such as `ip`, `ifconfig`, `nmcli`, or `iw`.

## Current phase

The current milestone adds the typed connection layer on top of the read-only
rtnetlink/nl80211 foundation:

- a typed [`ConnectionProfile`](src/connection/profile.rs) model for Wi-Fi and
  Ethernet, validated on construction;
- a secret-handling boundary so profiles never carry plaintext credentials;
- deterministic profile storage (in-memory and TOML-file backends behind a
  `ProfileStore` trait);
- a strict activation state machine with typed connection events;
- an `ActivationManager` that picks the best profile for a device, tracks
  active connections, and delegates the real work to an `ActivationEngine`
  boundary;
- a daemon facade (`Daemon`) that coordinates backend, profiles, and activation;
- deterministic unit tests across the profile, policy, store, secrets, state,
  activation, and daemon layers.

This phase intentionally does not yet bring connections up or down (the shipped
`UnsupportedActivationEngine` reports failure honestly), configure interfaces,
run DHCP, change DNS, alter routes, manage VPNs, or expose
NetworkManager-compatible D-Bus APIs.

## Build and test

```console
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Commands

```console
cargo run -- links
cargo run -- addresses
cargo run -- monitor
```

`nmd monitor` subscribes to rtnetlink link and address multicast notifications
and prints human-readable events until interrupted with Ctrl-C.

## Architecture direction

The daemon should grow around narrow subsystems backed by Linux-native APIs:

- rtnetlink for link/address/route state and changes;
- nl80211 for Wi-Fi scanning and association;
- sysfs/ethtool APIs for device metadata;
- D-Bus for desktop-facing compatibility surfaces;
- DHCP, DNS, Wi-Fi, VPN, and policy engines as later explicit subsystems.

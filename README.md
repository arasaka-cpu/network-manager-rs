# network-manager-rs

`network-manager-rs` is an early Rust-first foundation for a Linux-native network
management daemon. The project goal is to use native Linux interfaces directly
instead of shelling out to tools such as `ip`, `ifconfig`, `nmcli`, or `iw`.

## Current phase

The current milestone adds read-only rtnetlink address monitoring on top of the
Phase 1/2 snapshot and link-event foundation:

- a daemon binary (`nmd`) with non-destructive `links`, `addresses`, and
  `monitor` commands;
- a Linux networking abstraction trait for link/address snapshots and typed
  events;
- direct rtnetlink link/address enumeration and multicast monitoring;
- typed link creation, removal, and state-change events;
- typed IPv4/IPv6 address snapshots and address-added/address-removed events;
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
cargo run -- addresses
cargo run -- monitor
```

`nmd monitor` subscribes to rtnetlink link and address multicast notifications
and prints human-readable events until interrupted with Ctrl-C.

## Architecture direction

The daemon should grow around narrow subsystems backed by Linux-native APIs:

- rtnetlink for link/address/route state and changes;
- sysfs/ethtool APIs for device metadata;
- D-Bus for desktop-facing compatibility surfaces;
- DHCP, DNS, Wi-Fi, VPN, and policy engines as later explicit subsystems.

## License and patent grant

This project is dedicated under the MIT No Attribution (MIT-0) license. See the
LICENSE file for the full text.

Patent grant

Subject to the terms and conditions of the MIT No Attribution (MIT-0) license,
the copyright holder (arasaka) hereby grants to any recipient of the Work a
perpetual, worldwide, non-exclusive, royalty-free, irrevocable patent license
to make, have made, use, offer to sell, sell, import, and otherwise transfer the
Work. This patent license applies only to patents that are necessarily
infringed by the use or distribution of the Work as provided by this
repository.

# Project status

Status of the network-manager-rs daemon and its NetworkManager-compatible
D-Bus facade. Updated after each milestone.

## Last milestone: D-Bus wire compatibility audit

**Status: complete.**

The facade's D-Bus surface was audited against the NetworkManager running on
this host (introspected live over the system bus) and the official spec, and
the wire-level mismatches found were fixed. See `docs/compat.md` for the full
member-by-member inventory.

### Delivered

- `docs/compat.md` — compatibility inventory for every interface the facade
  exposes, with per-member signatures, status, and known gaps.
- Wire-type corrections so the introspection matches a real daemon:
  - `Device.ActiveConnection`, `Ip4Config`, `Dhcp4Config`, `Ip6Config`,
    `Dhcp6Config`: `s` → `o`.
  - `Device.AvailableConnections`, `Ports`: `as` → `ao`.
  - `Wireless.GetAccessPoints`, `GetAllAccessPoints`, `AccessPoints`: `as` → `ao`.
  - `Wireless.ActiveAccessPoint`: `s` → `o`.
  - `AccessPoint.LastSeen`: `u` → `i`.
- Members added for client compatibility:
  - Wireless signals `AccessPointAdded(o)` / `AccessPointRemoved(o)`.
  - AccessPoint `Bandwidth` property.
  - Root `State` property, `Enable`, `Reload`, `GetLogging`,
    `AddAndActivateConnection2`.
  - Settings `AddConnection2`.
- `src/dbus/tests.rs` gained `p2p_probe_wire_signatures_match_networkmanager`,
  which locks the fixed signatures against introspection.

### Verification

- `cargo test`: 172 tests pass (168 unit + 4 D-Bus probe tests over a
  peer-to-peer connection; netns integration test skips without root).
- `cargo build` clean.

## Remaining backlog

Semantic gaps (signature matches, values are stubs):

- Device `Path`/`Udi` empty; `Ip4Address` always 0; `Carrier` uses link-up
  rather than carrier state.
- AccessPoint `LastSeen` renders millis-ago instead of NM's monotonic seconds
  timestamp.
- Root `Version` reports the crate version.
- Wireless `WirelessCapabilities` and Device `Driver` are fixed stubs.

Lifecycle coverage (members exist but are never driven):

- Root `DeviceAdded`/`DeviceRemoved` and Wireless `AccessPointAdded`/
  `AccessPointRemoved` are never emitted: the object tree is registered once at
  `Server::attach` with no hotplug observation path.
- `StateChanged` signals are only emitted on the disconnect/delete paths.

Missing members (backlog):

- Root checkpoint family, `Checkpoints`, `RadioFlags`, `ConnectivityCheck*`,
  `Wimax*` properties, `GetDevicesByType`, deprecated `state()` method.
- `DHCP6Config.Options` and per-device `Statistics` counters are empty.

## Earlier milestones

- D-Bus facade exposing the daemon via NetworkManager's API (device, wireless,
  access point, active connection, settings, IP config interfaces).
- Linux DNS manager, IP engine, and composite activation engine.
- netns integration test harness replaced by a Rust-native `tests/` harness.
- `Send` requirements on daemon engine, store, and provider traits.

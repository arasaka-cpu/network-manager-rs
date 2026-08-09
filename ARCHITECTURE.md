# Architecture notes

## Repository reconnaissance

The initial repository contained only the MIT `LICENSE` file and Git metadata.
There were no Rust crates, source modules, tests, documentation, CI workflows,
or existing TODO files to preserve. The initial commit history also consisted of
a single `Initial commit` entry.

## Phase 1 architecture

Phase 1 established a read-only daemon foundation that can be safely tested on a
Linux host without changing network state.

Acceptance criteria:

1. Provide a buildable Rust crate and daemon binary.
2. Define a small backend trait that separates daemon coordination from Linux
   networking implementation details.
3. Enumerate network links through rtnetlink directly, without invoking shell
   commands or command-line networking utilities.
4. Include deterministic unit tests for netlink message parsing.
5. Pass formatting, compilation, tests, and Clippy checks.

## Phase 2 architecture

Phase 2 extended the same abstraction with read-only link event monitoring:

```text
Linux kernel
↓
NETLINK_ROUTE / RTMGRP_LINK
↓
RtnetlinkBackend
↓
typed NetworkEvent values
↓
NetworkBackend abstraction
↓
Daemon
↓
nmd monitor
```

## Address monitoring milestone

The current milestone adds read-only IPv4/IPv6 address snapshots and address
multicast monitoring while preserving the existing daemon/backend split:

```text
Linux kernel
↓
NETLINK_ROUTE / RTMGRP_LINK / RTMGRP_IPV4_IFADDR / RTMGRP_IPV6_IFADDR
↓
RtnetlinkBackend
↓
typed Link and Address snapshots + typed NetworkEvent values
↓
NetworkBackend abstraction
↓
Daemon
↓
nmd links / nmd addresses / nmd monitor
```

The `NetworkBackend` trait exposes link snapshots, address snapshots, and an
event-source API. The Linux backend subscribes to link, IPv4-address, and
IPv6-address rtnetlink multicast groups and converts supported messages into
typed `NetworkEvent` values. Unknown message types and unsupported address
families are ignored deliberately. Malformed message boundaries, truncated
payloads, malformed attributes, and invalid address attribute lengths are
surfaced as controlled `NetlinkError` values instead of panicking.

Supported events:

- link creation (`RTM_NEWLINK` with `NLM_F_CREATE`);
- link removal (`RTM_DELLINK`);
- link state change (`RTM_NEWLINK` without `NLM_F_CREATE`);
- address addition (`RTM_NEWADDR`) for IPv4 and IPv6;
- address removal (`RTM_DELADDR`) for IPv4 and IPv6.

## Connection layer milestone

The current milestone adds the typed connection architecture above the Linux
backends:

```text
typed ConnectionProfile model + SecretReference boundary
↓
ProfileStore (in-memory / TOML-file) + autoconnect ordering
↓
ActivationManager + strict ConnectionState machine + ConnectionEvent stream
↓
ActivationEngine trait (real Linux work lands in a later phase)
↓
DeviceInfo (converted from nl80211 wireless interfaces)
```

Key decisions:

- Profiles are validated on construction. Wi-Fi security references a
  [`SecretReference`](src/connection/secrets.rs) instead of embedding
  credentials, and open/OWE profiles are forbidden from carrying one.
- The activation state machine only moves through [`ConnectionState::transition_to`](src/connection/state.rs),
  so the daemon can never report success unless the underlying operation
  actually did. In this milestone the engine reports full success in one step
  and the manager walks the intermediate states; the Linux-backed engine will
  drive them incrementally.
- The default [`UnsupportedActivationEngine`](src/connection/activation.rs)
  fails honestly until Phase 5 wires in nl80211/IP configuration.
- The daemon keeps the in-memory store and placeholder engine by default;
  callers inject a real store/engine via `with_store`, `with_engine`, or
  `with_components`.

## Foundational subsystem boundaries

- `daemon`: orchestration and policy-independent daemon facade.
- `connection`: typed profiles, secrets boundary, stores, policy, state, and
  activation.
- `linux::netlink`: direct Linux rtnetlink access, multicast subscription, and
  packet parsing.
- `linux::nl80211` / `linux::wifi`: direct Linux Wi-Fi enumeration and scanning.
- `nmd`: operator-facing binary for non-destructive inspection and monitoring
  commands while the daemon foundation is still forming.

## Dependency policy

The foundation uses only a small amount of native Linux socket API surface
through direct FFI plus `serde`/`toml` for profile serialization. No networking
work shells out to command-line utilities. Future milestones may add
well-maintained crates after verifying that they expose the needed Linux APIs
without shelling out.

## Testing strategy

Parser tests use deterministic synthetic netlink/nl80211 fixtures. They cover
link creation, removal, state changes, IPv4/IPv6 address enumeration, address
add and remove events, malformed/truncated headers, unsupported message types,
malformed attributes, and multiple mixed messages in one receive buffer.
Connection-layer tests cover profile validation, device matching, autoconnect
ordering, in-memory and file-backed stores (including malformed files), the
state machine, secret references, and the full activation lifecycle with a
scripted engine. Tests never modify host networking state.

## Current limitations

The daemon remains read-only. It does not yet bring connections up or down,
configure links, addresses, routes, DNS, DHCP, or Wi-Fi association, manage
VPNs, or expose desktop-facing D-Bus APIs. Activation is tracked and reported,
but the real engine is deliberately not implemented in this milestone.

## Recommended next milestone

Wire the Linux-backed [`ActivationEngine`](src/connection/activation.rs):
nl80211 association for Wi-Fi profiles (using the existing scan/auth parsing
foundation), followed by IP configuration for `IpMethod::Manual` profiles.
Before that, consider adding read-only route enumeration and route event
monitoring around rtnetlink route messages.

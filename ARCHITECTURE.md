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

## Foundational subsystem boundaries

- `daemon`: orchestration and policy-independent daemon facade.
- `linux::netlink`: direct Linux rtnetlink access, multicast subscription, and
  packet parsing.
- `nmd`: operator-facing binary for non-destructive inspection and monitoring
  commands while the daemon foundation is still forming.

## Dependency policy

No third-party crates are used in this milestone. The environment has repeatedly
failed to reach the crates.io index, and this read-only milestone only needs a
small amount of native Linux socket API surface. The implementation uses direct
FFI so the foundation remains small and reviewable. Future milestones may add
well-maintained crates after verifying that they expose the needed Linux APIs
without shelling out.

## Testing strategy

Parser tests use deterministic synthetic netlink fixtures. They cover link
creation, removal, state changes, IPv4/IPv6 address enumeration, address add and
remove events, malformed/truncated headers, unsupported message types,
unsupported address families, malformed attributes, and multiple mixed messages
in one receive buffer. They do not modify host networking state.

## Current limitations

The daemon remains read-only. It does not configure links, addresses, routes,
DNS, DHCP, Wi-Fi, VPNs, persistence, policy, or desktop-facing D-Bus APIs.
Runtime monitoring currently covers link and interface-address events only.

## Recommended next milestone

Add read-only route enumeration and route event monitoring around rtnetlink route
messages. That should include typed route destinations, gateways, output
interfaces, priorities/metrics, parser tests, and monitor output for route
add/remove events.

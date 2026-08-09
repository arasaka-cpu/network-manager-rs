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

Phase 2 extends the same abstraction with read-only event monitoring:

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

The `NetworkBackend` trait now exposes both a snapshot API and an event-source
API. The Linux backend subscribes to the `RTMGRP_LINK` rtnetlink multicast group
and converts supported messages into typed `NetworkEvent::Link` values. Unknown
message types are ignored deliberately. Malformed message boundaries, truncated
payloads, and malformed attributes are surfaced as controlled `NetlinkError`
values instead of panicking.

Supported Phase 2 events:

- link creation (`RTM_NEWLINK` with `NLM_F_CREATE`);
- link removal (`RTM_DELLINK`);
- link state change (`RTM_NEWLINK` without `NLM_F_CREATE`).

Address events are intentionally not included yet. They require typed address
payload modeling, prefix handling, and separate multicast subscriptions; adding
that now would broaden the milestone beyond link event infrastructure.

## Foundational subsystem boundaries

- `daemon`: orchestration and policy-independent daemon facade.
- `linux::netlink`: direct Linux rtnetlink access, multicast subscription, and
  packet parsing.
- `nmd`: operator-facing binary for non-destructive inspection and monitoring
  commands while the daemon foundation is still forming.

## Dependency policy

No third-party crates are used in Phase 2. The environment still cannot reach the
crates.io index for evaluating rtnetlink crates, and this narrow milestone only
needs a small amount of native Linux socket API surface. The implementation uses
direct FFI so the foundation remains small and reviewable. Future milestones may
add well-maintained crates after verifying that they expose the needed Linux APIs
without shelling out.

## Testing strategy

Parser tests use deterministic synthetic netlink fixtures. They cover link
creation, removal, state changes, malformed/truncated headers, unsupported
message types, malformed attributes, and multiple messages in one receive buffer.
They do not modify host networking state.

## Current limitations

The daemon remains read-only. It does not configure links, addresses, routes,
DNS, DHCP, Wi-Fi, VPNs, persistence, policy, or desktop-facing D-Bus APIs.
Runtime monitoring currently covers link events only.

## Recommended next milestone

Add read-only address-event monitoring around rtnetlink address multicast groups.
That should include typed address payloads, prefix metadata, tests for address
message parsing, and `nmd monitor` output for address add/remove events.

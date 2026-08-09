# Architecture notes

## Repository reconnaissance

The initial repository contained only the MIT `LICENSE` file and Git metadata.
There were no Rust crates, source modules, tests, documentation, CI workflows,
or existing TODO files to preserve. The initial commit history also consisted of
a single `Initial commit` entry.

## Phase 1 architecture

Phase 1 establishes a read-only daemon foundation that can be safely tested on a
Linux host without changing network state.

Acceptance criteria:

1. Provide a buildable Rust crate and daemon binary.
2. Define a small backend trait that separates daemon coordination from Linux
   networking implementation details.
3. Enumerate network links through rtnetlink directly, without invoking shell
   commands or command-line networking utilities.
4. Include deterministic unit tests for netlink message parsing.
5. Pass formatting, compilation, tests, and Clippy checks.

## Foundational subsystem boundaries

- `daemon`: orchestration and policy-independent daemon facade.
- `linux::netlink`: direct Linux rtnetlink access and packet parsing.
- `nmd`: operator-facing binary for non-destructive inspection commands while
  the daemon foundation is still forming.

## Dependency policy

No third-party crates are used in Phase 1. The rtnetlink implementation calls the
Linux socket API directly through FFI so the initial foundation remains small and
reviewable. Future milestones may add well-maintained crates after verifying that
they expose the needed Linux APIs without shelling out.

## Recommended next milestone

Add a long-running event monitor around rtnetlink multicast groups for link and
address changes. That should include a typed event stream, cancellation/shutdown
handling, tests for event parsing, and a read-only `nmd monitor` command.

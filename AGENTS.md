# AGENTS.md

## Verification

After making changes, run:

```
cargo build --all-targets
cargo test --lib
cargo clippy --all-targets
```

## Conventions

- Rust workspace; the daemon talks to NetworkManager through the D-Bus system
  bus (`org.freedesktop.NetworkManager`). No code comments unless asked.
- D-Bus interface structs live in `src/dbus/`, Linux networking in
  `src/linux/`, the shared activation model in `src/connection/`.

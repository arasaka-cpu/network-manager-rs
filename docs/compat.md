# D-Bus wire compatibility inventory

This file is the living compatibility inventory for the
`org.freedesktop.NetworkManager` facade. It records, member by member, how the
facade's D-Bus surface compares to the API a real NetworkManager daemon
exposes, so existing clients (nmcli, GNOME settings, iwd-style tools) can talk
to the daemon without changes.

## Methodology

Signatures are compared against two references:

1. The official NetworkManager D-Bus API documentation
   (<https://networkmanager.dev/docs/api/latest/>, `spec.html`), which is the
   contract the facade targets.
2. The live introspection of the NetworkManager running on this host
   (`org.freedesktop.NetworkManager` on the system bus, read-only). Where the
   installed daemon disagrees with the published spec, the installed daemon is
   authoritative for practical client compatibility and is called out.

Status values:

- **ok** — member exists with a matching signature.
- **fixed** — member was present but with the wrong wire signature; corrected
  during this audit.
- **gap** — member exists but with semantic gaps (valid signature, stub or
  empty value).
- **missing** — member that real clients may rely on and is not yet exposed.
- **extra** — member not part of the reference API; harmless extension.

## Interfaces

- `org.freedesktop.NetworkManager` (root)
- `org.freedesktop.NetworkManager.Device`
- `org.freedesktop.NetworkManager.Device.Wired`
- `org.freedesktop.NetworkManager.Device.Wireless`
- `org.freedesktop.NetworkManager.Device.Statistics`
- `org.freedesktop.NetworkManager.AccessPoint`
- `org.freedesktop.NetworkManager.Connection.Active`
- `org.freedesktop.NetworkManager.IP4Config`, `IP6Config`, `DHCP4Config`,
  `DHCP6Config`
- `org.freedesktop.NetworkManager.Settings`
- `org.freedesktop.NetworkManager.Settings.Connection`

## Root (`org.freedesktop.NetworkManager`)

Methods (real NM on host: `Reload`, `GetDevices`, `GetAllDevices`,
`GetDeviceByIpIface`, `ActivateConnection`, `AddAndActivateConnection`,
`AddAndActivateConnection2`, `DeactivateConnection`, `Sleep`, `Enable`,
`GetPermissions`, `SetLogging`, `GetLogging`, `CheckConnectivity`, `state`,
checkpoint family).

| Member | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `GetDevices()` | `ao` | `ao` | ok |
| `GetAllDevices()` | `ao` | `ao` | ok |
| `GetDeviceByIpIface(iface: s)` | `o` | `o` | ok |
| `ActivateConnection(connection: o, device: o, specific_object: o)` | `o` | `o` | ok |
| `AddAndActivateConnection(connection: a{sa{sv}}, device: o, specific_object: o)` | `(o, o)` | `(o, o)` | ok |
| `AddAndActivateConnection2(connection: a{sa{sv}}, device: o, specific_object: o, options: a{sv})` | `(o, o, a{sv})` | `(o, o, a{sv})` | fixed (added) |
| `DeactivateConnection(active: o)` | `()` | `()` | ok |
| `Sleep(sleep: b)` | `()` | `()` | ok |
| `Enable(enable: b)` | `()` | `()` | fixed (added) |
| `GetPermissions()` | `a{ss}` | `a{ss}` | ok |
| `SetLogging(level: s, domains: s)` | `()` | `()` | ok |
| `GetLogging()` | `(s, s)` | `(s, s)` | fixed (added) |
| `CheckConnectivity()` | `u` | `u` | ok |
| `Reload(flags: u)` | `()` | `()` | fixed (added) |
| `state()` | `u` | — | missing (deprecated; `State` property used instead) |
| `CheckpointCreate/Destroy/Rollback/AdjustRollbackTimeout` | various | — | missing (out of scope; no checkpoints) |
| `GetDevicesByType(device_type: u)` | `ao` (NM >= 1.2) | — | missing (extension candidate) |
| `GetDeviceStateReasons(device: o)` | `au` (removed from modern NM) | `au` | extra (kept, harmless) |
| `CheckConnectivityFull` | — | `u` | extra (kept) |
| `GetConnectivity` | — | `u` | extra (kept; iwd-style alias) |

Properties (real NM on host):

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `Devices` | `ao` | `ao` | ok |
| `AllDevices` | `ao` | `ao` | ok |
| `ActiveConnections` | `ao` | `ao` | ok |
| `PrimaryConnection` | `o` | `o` | ok |
| `PrimaryConnectionType` | `s` | `s` | ok |
| `ActivatingConnection` | `o` | `o` | ok |
| `Metered` | `u` | `u` | ok |
| `Startup` | `b` | `b` | ok |
| `Version` | `s` | `s` | gap (reports crate version, not an NM version) |
| `VersionInfo` | `au` | `au` | ok (derived from crate version) |
| `Capabilities` | `au` | `au` | ok (empty) |
| `State` | `u` | `u` | fixed (added) |
| `Connectivity` | `u` | `u` | ok |
| `NetworkingEnabled` | `b` | `b` | ok |
| `WirelessEnabled` | `b` | `b` | ok |
| `WirelessHardwareEnabled` | `b` | `b` | ok |
| `WwanEnabled` | `b` | `b` | ok |
| `WwanHardwareEnabled` | `b` | `b` | ok |
| `GlobalDnsConfiguration` | `a{sv}` | `a{sv}` | ok |
| `Checkpoints` | `ao` | — | missing (no checkpoints) |
| `RadioFlags` | `u` | — | missing |
| `ConnectivityCheckAvailable/Enabled/Uri` | `b/b/s` | — | missing |
| `WimaxEnabled`/`WimaxHardwareEnabled` | `b` | — | missing (obsolete) |

Signals (real NM on host): `CheckPermissions`, `StateChanged(u)`,
`DeviceAdded(o)`, `DeviceRemoved(o)`, `ActiveConnectionAdded(o)`,
`ActiveConnectionRemoved(o)`.

| Signal | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `StateChanged(state: u)` | `u` | `u` | ok (declared; never emitted) |
| `DeviceAdded(device: o)` | `o` | `o` | gap (declared; never emitted — no hotplug path) |
| `DeviceRemoved(device: o)` | `o` | `o` | gap (declared; never emitted) |
| `ActiveConnectionAdded(active: o)` | `o` | `o` | ok (emitted on activation) |
| `ActiveConnectionRemoved(active: o)` | `o` | `o` | ok (declared) |

## Device (`org.freedesktop.NetworkManager.Device`)

Methods (real NM on host): `Reapply`, `GetAppliedConnection`, `SetManaged`,
`Disconnect`, `Delete`.

| Member | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `Reapply(connection: a{sa{sv}}, version_id: t, flags: u)` | `()` | `()` | ok (returns NotSupported) |
| `GetAppliedConnection(flags: u)` | `(a{sa{sv}}, t)` | `(a{sa{sv}}, t)` | ok |
| `SetManaged(managed: u, flags: u)` | `()` | `(u, u)` | ok (returns NotSupported) |
| `Disconnect()` | `()` | `()` | ok |
| `Delete()` | `()` | `()` | ok |

Properties (real NM on host):

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `Udi` | `s` | `s` | ok (empty) |
| `Path` | `s` | `s` | gap (sysfs path unknown; empty) |
| `Interface` | `s` | `s` | ok |
| `IpInterface` | `s` | `s` | ok |
| `Driver` | `s` | `s` | gap (stub per device kind) |
| `DriverVersion` | `s` | `s` | ok (empty) |
| `FirmwareVersion` | `s` | `s` | ok (empty) |
| `Capabilities` | `u` | `u` | ok (0) |
| `Ip4Address` | `u` | `u` | gap (always 0) |
| `State` | `u` | `u` | ok |
| `StateReason` | `(uu)` | `(uu)` | ok |
| `ActiveConnection` | `o` | `o` | fixed (was `s`) |
| `Ip4Config` | `o` | `o` | fixed (was `s`) |
| `Dhcp4Config` | `o` | `o` | fixed (was `s`) |
| `Ip6Config` | `o` | `o` | fixed (was `s`) |
| `Dhcp6Config` | `o` | `o` | fixed (was `s`) |
| `Managed` | `b` | `b` | ok |
| `Autoconnect` | `b` | `b` | ok |
| `FirmwareMissing` | `b` | `b` | ok |
| `NmPluginMissing` | `b` | `b` | ok |
| `DeviceType` | `u` | `u` | ok |
| `AvailableConnections` | `ao` | `ao` | fixed (was `as`) |
| `PhysicalPortId` | `s` | `s` | ok (empty) |
| `Mtu` | `u` | `u` | ok (0) |
| `Metered` | `u` | `u` | ok (0) |
| `LldpNeighbors` | `aa{sv}` | `aa{sv}` | ok (empty) |
| `Real` | `b` | `b` | ok (true) |
| `Ip4Connectivity` | `u` | `u` | ok |
| `Ip6Connectivity` | `u` | `u` | ok |
| `InterfaceFlags` | `u` | `u` | ok |
| `HwAddress` | `s` | `s` | ok |
| `Ports` | `ao` | `ao` | fixed (was `as`) |

Signals (real NM on host): `StateChanged(u, u, u)`.

| Signal | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `StateChanged(state: u, reason: u, prev_state: u)` | `(u, u, u)` | `(u, u, u)` | ok (emitted on disconnect/delete) |

## Device.Wired

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `HwAddress` | `s` | `s` | ok |
| `PermHwAddress` | `s` | `s` | ok (empty) |
| `Speed` | `u` | `u` | ok (0) |
| `S390Subchannels` | `as` | `as` | ok (empty) |
| `Carrier` | `b` | `b` | gap (derived from link up, not carrier state) |

## Device.Wireless

Methods (real NM on host): `GetAccessPoints`, `GetAllAccessPoints`,
`RequestScan`.

| Member | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `GetAccessPoints()` | `ao` | `ao` | fixed (was `as`) |
| `GetAllAccessPoints()` | `ao` | `ao` | fixed (was `as`) |
| `RequestScan(options: a{sv})` | `()` | `()` | ok |

Properties (real NM on host):

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `HwAddress` | `s` | `s` | ok |
| `PermHwAddress` | `s` | `s` | ok (empty) |
| `Mode` | `u` | `u` | ok (always 2 = infrastructure) |
| `Bitrate` | `u` | `u` | ok (0) |
| `AccessPoints` | `ao` | `ao` | fixed (was `as`) |
| `ActiveAccessPoint` | `o` | `o` | fixed (was `s`) |
| `WirelessCapabilities` | `u` | `u` | gap (stub bitmask) |
| `LastScan` | `x` | `x` | ok (0) |

Signals (real NM on host): `AccessPointAdded(o)`, `AccessPointRemoved(o)`,
`PropertiesChanged`.

| Signal | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `AccessPointAdded(access_point: o)` | `o` | `o` | fixed (added; no AP lifecycle path yet) |
| `AccessPointRemoved(access_point: o)` | `o` | `o` | fixed (added; no AP lifecycle path yet) |

## Device.Statistics

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `RefreshRateMs` | `u` | `u` | ok (0) |
| `TxBytes` | `t` | `t` | ok (0) |
| `RxBytes` | `t` | `t` | ok (0) |

## AccessPoint

Properties (real NM on host): `Flags u`, `WpaFlags u`, `RsnFlags u`, `Ssid ay`,
`Frequency u`, `HwAddress s`, `Mode u`, `MaxBitrate u`, `Bandwidth u`,
`Strength y`, `LastSeen i`.

| Property | NM type | Facade type | Status |
| --- | --- | --- | --- |
| `Flags` | `u` | `u` | ok |
| `WpaFlags` | `u` | `u` | ok |
| `RsnFlags` | `u` | `u` | ok |
| `Ssid` | `ay` | `ay` | ok |
| `Frequency` | `u` | `u` | ok |
| `HwAddress` | `s` | `s` | ok |
| `Mode` | `u` | `u` | ok (2) |
| `MaxBitrate` | `u` | `u` | ok (0) |
| `Bandwidth` | `u` | `u` | fixed (added) |
| `Strength` | `y` | `y` | ok |
| `LastSeen` | `i` | `i` | fixed (was `u`) |
| `Channel` | — | `u` | extra (removed from modern NM; kept) |
| `Steerable` | — | `b` | extra (kept) |
| `Ies` | — | `aa{sv}` | extra (kept) |

## Connection.Active

Real NM properties: `Connection o`, `Id s`, `Uuid s`, `Type s`,
`SpecificObject o`, `Devices ao`, `State u`, `Default b`, `Default6 b`,
`Vpn b`, `Master o`, `Ip4Config o`, `Dhcp4Config o`, `Ip6Config o`,
`Dhcp6Config o`, `Controller o`, `ConnectionType s`, `StateFlags u`,
`Unmetered b`.

All present with matching signatures. Status: ok.

Signal `StateChanged(state: u, reason: u, prev_state: u)` — declared, never
emitted.

## IP4Config / IP6Config / DHCP4Config / DHCP6Config

Properties are rendered from the installed
[`crate::connection::ip::ActivationOutcome`]. Types match NM (`AddressData`,
`Gateway`, `DnsData`, `DnsSearches`, `Nameservers`, `Options`, ...). Status: ok
(values are partial for unused features; IPv6 outcome is limited).

## Settings

| Method | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `ListConnections()` | `ao` | `ao` | ok |
| `GetConnectionByUuid(uuid: s)` | `o` | `o` | ok |
| `AddConnection(connection: a{sa{sv}})` | `o` | `o` | ok |
| `AddConnectionUnsaved(connection: a{sa{sv}})` | `o` | `o` | ok (persists immediately) |
| `AddConnection2(settings: a{sa{sv}}, flags: u, args: a{sv})` | `(o, a{sv})` | `(o, a{sv})` | fixed (added) |
| `LoadConnections(filenames: as)` | `(b, as)` | `(b, as)` | ok |
| `ReloadConnections()` | `b` | `b` | ok |
| `SaveHostname(hostname: s)` | `()` | `()` | ok |

Properties: `Connections ao` ok, `Hostname s` ok (empty), `CanModify b` ok.

## Settings.Connection

| Member | NM signature | Facade | Status |
| --- | --- | --- | --- |
| `GetSettings()` | `a{sa{sv}}` | `a{sa{sv}}` | ok |
| `GetSecrets(setting_name: s)` | `a{sa{sv}}` | `a{sa{sv}}` | ok (empty) |
| `Update(settings: a{sa{sv}})` | `()` | `()` | ok |
| `UpdateUnsaved(settings: a{sa{sv}})` | `()` | `()` | ok |
| `Delete()` | `()` | `()` | ok |
| `GetSettingsFlags()` | `u` | `u` | ok |
| `GetAppliedConnection(flags: u)` | `(a{sa{sv}}, t)` | `(a{sa{sv}}, t)` | ok |
| `Updated()` signal | `()` | `()` | ok |
| `Removed()` signal | `()` | `()` | ok |

## Fixes applied in this audit

Wire-type corrections so the introspection matches a real daemon:

- Device `ActiveConnection`, `Ip4Config`, `Dhcp4Config`, `Ip6Config`,
  `Dhcp6Config`: `s` → `o`.
- Device `AvailableConnections`, `Ports`: `as` → `ao`.
- Wireless `GetAccessPoints`, `GetAllAccessPoints`, `AccessPoints`: `as` → `ao`.
- Wireless `ActiveAccessPoint`: `s` → `o`.
- AccessPoint `LastSeen`: `u` → `i`.

Members added for client compatibility:

- Wireless signals `AccessPointAdded(o)`, `AccessPointRemoved(o)`.
- AccessPoint `Bandwidth` property.
- Root `State` property, `Enable`, `Reload`, `GetLogging`,
  `AddAndActivateConnection2`.
- Settings `AddConnection2`.

## Known gaps and remaining backlog

Semantic (signature matches, value is a stub):

- Device `Path` (sysfs path) and `Udi` are empty.
- Device `Ip4Address` always `0`; real NM keeps the primary IPv4 here.
- Device `Carrier` reflects link-up, not carrier state.
- AccessPoint `LastSeen` is rendered from `seen_millis_ago` (milliseconds since
  seen) instead of NM's monotonic seconds timestamp.
- Root `Version` reports the crate version, which clients may parse as an NM
  version.
- Wireless `WirelessCapabilities` is a fixed stub bitmask rather than the
  device's real capabilities.
- Device `Driver` is a fixed per-kind string rather than the real kernel driver.

Lifecycle (members exist but are never driven):

- Root `DeviceAdded`/`DeviceRemoved` are never emitted: the facade registers
  the device tree once at `Server::attach` and has no hotplug observation path.
- Wireless `AccessPointAdded`/`AccessPointRemoved` are never emitted: access
  point objects are registered once at attach time.
- Root `StateChanged`, Device `StateChanged` on activation, and
  `Connection.Active.StateChanged` are emitted only for the disconnect/delete
  paths, not for the full state machine.

Missing (backlog):

- Root checkpoint family and `Checkpoints`, `RadioFlags`,
  `ConnectivityCheck*`, `Wimax*` properties.
- Root `GetDevicesByType`.
- Root deprecated `state()` method (the `State` property covers it).
- Per-device `Statistics` counters always report zero.
- DHCP options for IPv6 (`DHCP6Config.Options` is empty).

Not tracked (by design):

- Real NM devices expose extra per-kind interfaces (e.g. `Device.Bridge`,
  `Device.WifiP2P`); the facade renders Ethernet, Wireless, and Loopback only.

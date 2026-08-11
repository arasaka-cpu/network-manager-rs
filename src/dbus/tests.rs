//! Wire-level compatibility tests for the D-Bus facade.
//!
//! These tests drive the facade over a peer-to-peer connection and assert on
//! the actual D-Bus contract clients see: object paths, interface names,
//! method/property/signal signatures, property values and error names.

use crate::daemon::Daemon;

use super::testutil::{FakeBackend, SuccessEngine, TestServer, ethernet_link, wifi_interface};

#[test]
fn p2p_probe_root_devices_property() {
    let backend = FakeBackend::default().with_wifi(wifi_interface(
        2,
        "wlan0",
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server
        .proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager")
        .unwrap();
    let devices: Vec<zbus::zvariant::OwnedObjectPath> = proxy.get_property("Devices").unwrap();
    assert_eq!(
        devices,
        vec![
            zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/2")
                .unwrap()
        ]
    );
}

/// A device property read must complete promptly. The proxy populates its
/// property cache with a `GetAll`, which runs every getter on the device
/// interface; regression test for a self-deadlock in `available_connections`,
/// which held the daemon mutex while re-acquiring it via `view()`.
#[test]
fn p2p_probe_device_property_read_completes() {
    let backend = FakeBackend::default().with_wifi(wifi_interface(
        2,
        "wlan0",
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server
        .proxy(
            "/org/freedesktop/NetworkManager/Devices/2",
            "org.freedesktop.NetworkManager.Device",
        )
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let state: u32 = proxy.get_property("State").unwrap();
        tx.send(state).ok();
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(state) => assert_eq!(
            state, 30,
            "an up device with no active connection is disconnected"
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("device property read did not complete within 10s (daemon mutex self-deadlock?)")
        }
        Err(_) => panic!("device property read failed"),
    }
}

#[test]
fn p2p_probe_introspection_reports_interfaces() {
    let backend = FakeBackend::default().with_wifi(wifi_interface(
        2,
        "wlan0",
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server
        .proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager")
        .unwrap();
    let xml = proxy.introspect().unwrap();
    assert!(
        xml.contains("org.freedesktop.NetworkManager"),
        "root introspection mentions the manager interface"
    );
}

#[test]
fn p2p_probe_ethernet_devices_are_enumerated() {
    let backend = FakeBackend::default()
        .with_link(ethernet_link(3, "eth0", true))
        .with_wifi(wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        ));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server
        .proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager")
        .unwrap();
    let devices: Vec<zbus::zvariant::OwnedObjectPath> = proxy.get_property("Devices").unwrap();
    let paths: Vec<String> = devices
        .iter()
        .map(|path| path.as_str().to_string())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/org/freedesktop/NetworkManager/Devices/2",
            "/org/freedesktop/NetworkManager/Devices/3"
        ]
    );
}

/// The deprecated IPv4 scalar properties must carry the exact values a real
/// NetworkManager publishes: the four address octets as a little-endian `u32`.
/// Values captured from the live NM 1.58 on this host (`192.168.1.184` →
/// `3087116480`, gateway `192.168.1.1` → `16885952`, connected network
/// `192.168.1.0` → `108736`).
#[test]
fn p2p_probe_ip4config_values_match_networkmanager_encoding() {
    let backend = FakeBackend::default().with_link(ethernet_link(3, "eth0", true));
    let daemon = Daemon::with_engine(backend, Box::new(SuccessEngine));
    let server = TestServer::start(daemon).expect("server starts");

    let device =
        zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/3")
            .unwrap();
    let root = server
        .proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager")
        .unwrap();

    let mut connection = std::collections::HashMap::new();
    connection.insert(
        "id".to_string(),
        zbus::zvariant::OwnedValue::from(zbus::zvariant::Str::from("eth0-conn")),
    );
    connection.insert(
        "type".to_string(),
        zbus::zvariant::OwnedValue::from(zbus::zvariant::Str::from("802-3-ethernet")),
    );
    let mut settings = super::convert::SettingsDict::new();
    settings.insert("connection".to_string(), connection);

    let (_, active): (
        zbus::zvariant::OwnedObjectPath,
        zbus::zvariant::OwnedObjectPath,
    ) = root
        .call_method(
            "AddAndActivateConnection",
            &(
                settings,
                device,
                zbus::zvariant::OwnedObjectPath::try_from("/").unwrap(),
            ),
        )
        .unwrap()
        .body()
        .deserialize()
        .unwrap();

    let id: u64 = active
        .as_str()
        .strip_prefix("/org/freedesktop/NetworkManager/ActiveConnection/")
        .unwrap()
        .parse()
        .unwrap();
    let ip4 = server
        .proxy(
            &super::ip4_path(crate::connection::activation::ActiveConnectionId::new(id)),
            "org.freedesktop.NetworkManager.IP4Config",
        )
        .unwrap();

    let addresses: Vec<Vec<u32>> = ip4.get_property("Addresses").unwrap();
    assert_eq!(addresses, vec![vec![3087116480, 24, 16885952]]);
    let nameservers: Vec<u32> = ip4.get_property("Nameservers").unwrap();
    assert_eq!(nameservers, vec![16885952]);
    let routes: Vec<Vec<u32>> = ip4.get_property("Routes").unwrap();
    assert_eq!(routes, vec![vec![108736, 24, 0, 600]]);
}

/// True when an introspection XML declares a property with the given type,
/// regardless of attribute order.
fn has_property(xml: &str, name: &str, ty: &str) -> bool {
    xml.contains(&format!(r#"type="{ty}" name="{name}""#))
        || xml.contains(&format!(r#"name="{name}" type="{ty}""#))
}

#[test]
fn p2p_probe_wire_signatures_match_networkmanager() {
    let backend = FakeBackend::default()
        .with_link(ethernet_link(3, "eth0", true))
        .with_wifi(wifi_interface(
            2,
            "wlan0",
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        ))
        .with_access_point(super::testutil::access_point(
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            "test-net",
            2412,
            -45,
        ));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let root_xml = server
        .proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager")
        .unwrap()
        .introspect()
        .unwrap();
    assert!(has_property(&root_xml, "State", "u"));
    assert!(root_xml.contains(r#"<method name="Enable""#));
    assert!(root_xml.contains(r#"<method name="Reload""#));
    assert!(root_xml.contains(r#"<method name="GetLogging""#));
    assert!(root_xml.contains(r#"<method name="AddAndActivateConnection2""#));

    let device_xml = server
        .proxy(
            "/org/freedesktop/NetworkManager/Devices/2",
            "org.freedesktop.NetworkManager.Device",
        )
        .unwrap()
        .introspect()
        .unwrap();
    assert!(has_property(&device_xml, "ActiveConnection", "o"));
    assert!(has_property(&device_xml, "Ip4Config", "o"));
    assert!(has_property(&device_xml, "Dhcp4Config", "o"));
    assert!(has_property(&device_xml, "Ip6Config", "o"));
    assert!(has_property(&device_xml, "Dhcp6Config", "o"));
    assert!(has_property(&device_xml, "AvailableConnections", "ao"));
    assert!(has_property(&device_xml, "Ports", "ao"));

    let wireless_xml = server
        .proxy(
            "/org/freedesktop/NetworkManager/Devices/2",
            "org.freedesktop.NetworkManager.Device.Wireless",
        )
        .unwrap()
        .introspect()
        .unwrap();
    assert!(has_property(&wireless_xml, "AccessPoints", "ao"));
    assert!(has_property(&wireless_xml, "ActiveAccessPoint", "o"));
    assert!(wireless_xml.contains(r#"<method name="GetAccessPoints""#));
    assert!(wireless_xml.contains(r#"<signal name="AccessPointAdded""#));
    assert!(wireless_xml.contains(r#"<signal name="AccessPointRemoved""#));

    let ap_xml = server
        .proxy(
            "/org/freedesktop/NetworkManager/AccessPoint/2_deadbeef0001",
            "org.freedesktop.NetworkManager.AccessPoint",
        )
        .unwrap()
        .introspect()
        .unwrap();
    assert!(has_property(&ap_xml, "Bandwidth", "u"));
    assert!(has_property(&ap_xml, "LastSeen", "i"));

    let settings_xml = server
        .proxy(
            super::SETTINGS_PATH,
            "org.freedesktop.NetworkManager.Settings",
        )
        .unwrap()
        .introspect()
        .unwrap();
    assert!(settings_xml.contains(r#"<method name="AddConnection2""#));
}

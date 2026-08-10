//! Wire-level compatibility tests for the D-Bus facade.
//!
//! These tests drive the facade over a peer-to-peer connection and assert on
//! the actual D-Bus contract clients see: object paths, interface names,
//! method/property/signal signatures, property values and error names.

use crate::daemon::Daemon;

use super::testutil::{FakeBackend, TestServer, ethernet_link, wifi_interface};

#[test]
fn p2p_probe_root_devices_property() {
    let backend = FakeBackend::default()
        .with_wifi(wifi_interface(2, "wlan0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server.proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager").unwrap();
    let devices: Vec<zbus::zvariant::OwnedObjectPath> =
        proxy.get_property("Devices").unwrap();
    assert_eq!(
        devices,
        vec![zbus::zvariant::OwnedObjectPath::try_from(
            "/org/freedesktop/NetworkManager/Devices/2"
        )
        .unwrap()]
    );
}

#[test]
fn p2p_probe_introspection_reports_interfaces() {
    let backend = FakeBackend::default()
        .with_wifi(wifi_interface(2, "wlan0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server.proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager").unwrap();
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
        .with_wifi(wifi_interface(2, "wlan0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    let server = TestServer::start(Daemon::new(backend)).expect("server starts");

    let proxy = server.proxy(super::ROOT_PATH, "org.freedesktop.NetworkManager").unwrap();
    let devices: Vec<zbus::zvariant::OwnedObjectPath> =
        proxy.get_property("Devices").unwrap();
    let paths: Vec<String> = devices.iter().map(|path| path.as_str().to_string()).collect();
    assert_eq!(
        paths,
        vec![
            "/org/freedesktop/NetworkManager/Devices/2",
            "/org/freedesktop/NetworkManager/Devices/3"
        ]
    );
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
        .with_wifi(wifi_interface(2, "wlan0", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
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
        .proxy(super::SETTINGS_PATH, "org.freedesktop.NetworkManager.Settings")
        .unwrap()
        .introspect()
        .unwrap();
    assert!(settings_xml.contains(r#"<method name="AddConnection2""#));
}

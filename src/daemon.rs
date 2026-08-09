use crate::linux::model::{
    AccessPoint, Address, Link, NetlinkError, NetworkEvent, NetworkEventSource, WirelessInterface,
};

/// Minimal backend boundary for daemon networking state.
pub trait NetworkBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError>;

    fn addresses(&self) -> Result<Vec<Address>, NetlinkError>;

    fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError>;

    fn wifi_interfaces(&self) -> Result<Vec<WirelessInterface>, NetlinkError>;

    fn access_points(&self) -> Result<Vec<AccessPoint>, NetlinkError>;

    fn scan_wifi(&self) -> Result<Vec<AccessPoint>, NetlinkError>;

    fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError>;
}

/// Daemon coordinator. It remains deliberately read-only.
pub struct Daemon<B> {
    backend: B,
}

impl<B> Daemon<B>
where
    B: NetworkBackend,
{
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn links(&self) -> Result<Vec<Link>, NetlinkError> {
        self.backend.links()
    }

    pub fn addresses(&self) -> Result<Vec<Address>, NetlinkError> {
        self.backend.addresses()
    }

    pub fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        self.backend.events()
    }

    pub fn wifi_interfaces(&self) -> Result<Vec<WirelessInterface>, NetlinkError> {
        self.backend.wifi_interfaces()
    }

    pub fn access_points(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
        self.backend.access_points()
    }

    pub fn scan_wifi(&self) -> Result<Vec<AccessPoint>, NetlinkError> {
        self.backend.scan_wifi()
    }

    pub fn wifi_events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        self.backend.wifi_events()
    }

    pub fn next_event(
        source: &mut dyn NetworkEventSource,
    ) -> Result<Option<NetworkEvent>, NetlinkError> {
        source.next_event()
    }
}

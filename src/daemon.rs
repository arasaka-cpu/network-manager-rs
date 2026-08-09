use crate::linux::netlink::{Link, NetlinkError, NetworkEvent, NetworkEventSource};

/// Minimal backend boundary for daemon networking state.
pub trait NetworkBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError>;

    fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError>;
}

/// Daemon coordinator. Phase 2 remains deliberately read-only.
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

    pub fn events(&self) -> Result<Box<dyn NetworkEventSource>, NetlinkError> {
        self.backend.events()
    }

    pub fn next_event(
        source: &mut dyn NetworkEventSource,
    ) -> Result<Option<NetworkEvent>, NetlinkError> {
        source.next_event()
    }
}

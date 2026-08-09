use crate::linux::netlink::{Link, NetlinkError};

/// Minimal backend boundary for daemon networking state.
pub trait NetworkBackend {
    fn links(&self) -> Result<Vec<Link>, NetlinkError>;
}

/// Daemon coordinator. Phase 1 is deliberately read-only.
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
}

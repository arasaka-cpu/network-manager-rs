//! Connection profile and activation architecture.
//!
//! This layer sits above the Linux backends and below any future D-Bus API:
//!
//! ```text
//! typed network state -> connection/profile manager -> activation engine
//! ```
//!
//! It provides the typed [`ConnectionProfile`] model, a secret-handling
//! boundary, deterministic profile storage, a connection state machine and
//! the activation coordinator.

pub mod activation;
pub mod device;
pub mod ip;
pub mod policy;
pub mod profile;
pub mod secrets;
pub mod state;
pub mod store;
pub mod supplicant_engine;

pub use activation::{
    ActivationEngine, ActivationError, ActivationManager, ActiveConnection, ActiveConnectionId,
    UnsupportedActivationEngine,
};
pub use device::{DeviceInfo, DeviceKind, MacAddress};
pub use ip::{
    ActivationOutcome, ActiveIpState, ActiveIpv4, ActiveIpv6, Degradation, DhcpClient, DhcpError,
    DhcpLease, DhcpRequest, DnsConfig, DnsError, DnsManager, DnsOwnership, IpConfigError,
    IpConfigurator, Ipv4Config, Ipv4Outcome, Ipv4Source, Ipv6Config, Ipv6Outcome, Ipv6Source,
};
pub use policy::order_for_autoconnect;
pub use profile::{
    ConnectionProfile, ConnectionType, DeviceMatch, EthernetDuplex, EthernetSettings, IpConfig,
    IpMethod, KeyManagement, ProfileId, ProfileValidationError, WifiSecurity, WifiSettings,
};
pub use secrets::{EnvSecretProvider, SecretError, SecretProvider, SecretReference};
pub use state::{ConnectionEvent, ConnectionState, StateError};
pub use store::{FileProfileStore, InMemoryProfileStore, ProfileStore, StoreError};
pub use supplicant_engine::WpaSupplicantActivationEngine;

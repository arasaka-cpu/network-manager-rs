//! Activation architecture.
//!
//! [`ActivationManager`] coordinates profile activation: it picks a suitable
//! profile, tracks typed state transitions, records [`ConnectionEvent`]s and
//! inspects active connections. The actual work of bringing a connection up is
//! delegated to an [`ActivationEngine`]; this milestone only defines that
//! boundary and ships an [`UnsupportedActivationEngine`] until Phase 5 wires
//! in the real Linux Wi-Fi/IP stack.

use std::fmt;

use crate::connection::device::DeviceInfo;
use crate::connection::ip::ActivationOutcome;
use crate::connection::policy::order_for_autoconnect;
use crate::connection::profile::{ConnectionProfile, ProfileId};
use crate::connection::state::{ConnectionEvent, ConnectionState, StateError};
use crate::connection::store::{ProfileStore, StoreError};

/// Unique handle for an active connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActiveConnectionId(u64);

impl ActiveConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ActiveConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A connection that has been (or is being) activated on a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveConnection {
    pub id: ActiveConnectionId,
    pub profile: ConnectionProfile,
    pub device: DeviceInfo,
    pub state: ConnectionState,
    /// The configuration the engine actually put in place, once `Activated`.
    pub outcome: ActivationOutcome,
}

/// Errors reported during activation and deactivation.
#[derive(Debug)]
pub enum ActivationError {
    ProfileNotFound(ProfileId),
    DeviceIncompatible {
        profile_id: ProfileId,
        device: DeviceInfo,
    },
    NoSuitableProfile(DeviceInfo),
    AlreadyActive(ProfileId),
    UnknownActiveConnection(ActiveConnectionId),
    InvalidState {
        active_id: ActiveConnectionId,
        from: ConnectionState,
    },
    State(StateError),
    Store(StoreError),
    Engine(String),
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileNotFound(id) => write!(f, "connection profile {id:?} not found"),
            Self::DeviceIncompatible { profile_id, device } => write!(
                f,
                "connection profile {profile_id:?} does not match device {} ({})",
                device.interface_name, device.kind
            ),
            Self::NoSuitableProfile(device) => write!(
                f,
                "no suitable connection profile for device {} ({})",
                device.interface_name, device.kind
            ),
            Self::AlreadyActive(id) => write!(f, "connection profile {id:?} is already active"),
            Self::UnknownActiveConnection(active_id) => {
                write!(f, "no active connection with id {active_id}")
            }
            Self::InvalidState { active_id, from } => write!(
                f,
                "active connection {active_id} cannot be deactivated from {from}"
            ),
            Self::State(err) => write!(f, "{err}"),
            Self::Store(err) => write!(f, "profile store error: {err}"),
            Self::Engine(reason) => write!(f, "activation engine error: {reason}"),
        }
    }
}

impl std::error::Error for ActivationError {}

/// Performs the real work of bringing a profile up or down on a device.
///
/// Implementations report success only when the underlying operation actually
/// succeeded; the manager will not fabricate an `Activated` state otherwise.
/// On success [`ActivationEngine::activate`] returns the configuration that was
/// actually installed so callers can render it without probing the kernel.
///
/// `Send` is required so a daemon holding `Box<dyn ActivationEngine>` can be
/// shared across the D-Bus compatibility layer's object server threads.
pub trait ActivationEngine: Send {
    fn activate(
        &mut self,
        profile: &ConnectionProfile,
        device: &DeviceInfo,
    ) -> Result<ActivationOutcome, ActivationError>;

    fn deactivate(&mut self, profile: &ConnectionProfile) -> Result<(), ActivationError>;
}

/// A placeholder engine that reports activation as unsupported.
#[derive(Debug, Default)]
pub struct UnsupportedActivationEngine;

impl ActivationEngine for UnsupportedActivationEngine {
    fn activate(
        &mut self,
        _profile: &ConnectionProfile,
        _device: &DeviceInfo,
    ) -> Result<ActivationOutcome, ActivationError> {
        Err(ActivationError::Engine(
            "no activation engine is configured for this daemon".to_string(),
        ))
    }

    fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
        Err(ActivationError::Engine(
            "no activation engine is configured for this daemon".to_string(),
        ))
    }
}

/// Coordinates profile activation, state tracking and connection events.
pub struct ActivationManager {
    engine: Box<dyn ActivationEngine>,
    next_id: u64,
    active: Vec<ActiveConnection>,
    events: Vec<ConnectionEvent>,
}

impl ActivationManager {
    pub fn new(engine: Box<dyn ActivationEngine>) -> Self {
        Self {
            engine,
            next_id: 1,
            active: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Returns the connections that are currently tracked.
    pub fn active_connections(&self) -> &[ActiveConnection] {
        &self.active
    }

    /// Returns the state of the active connection for `profile_id`, or
    /// [`ConnectionState::Disconnected`] if the profile is not active.
    pub fn state(&self, profile_id: &ProfileId) -> ConnectionState {
        self.active
            .iter()
            .find(|active| active.profile.id == *profile_id)
            .map(|active| active.state)
            .unwrap_or(ConnectionState::Disconnected)
    }

    pub fn is_active(&self, profile_id: &ProfileId) -> bool {
        self.active
            .iter()
            .any(|active| active.profile.id == *profile_id)
    }

    /// Takes all pending connection events.
    pub fn drain_events(&mut self) -> Vec<ConnectionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Activates the best matching profile for `device`, following autoconnect
    /// ordering.
    pub fn activate(
        &mut self,
        store: &dyn ProfileStore,
        device: &DeviceInfo,
    ) -> Result<ActiveConnection, ActivationError> {
        let profiles = store.list().map_err(ActivationError::Store)?;
        let candidate =
            order_for_autoconnect(&profiles)
                .into_iter()
                .find_map(|id| match store.get(&id) {
                    Ok(profile) if profile.matches(device) && !self.is_active(&profile.id) => {
                        Some(profile)
                    }
                    _ => None,
                });
        match candidate {
            Some(profile) => self.activate_matching(&profile, device),
            None => Err(ActivationError::NoSuitableProfile(device.clone())),
        }
    }

    /// Activates a specific profile on `device`.
    pub fn activate_profile(
        &mut self,
        store: &dyn ProfileStore,
        profile_id: &ProfileId,
        device: &DeviceInfo,
    ) -> Result<ActiveConnection, ActivationError> {
        let profile = match store.get(profile_id) {
            Ok(profile) => profile,
            Err(StoreError::NotFound(_)) => {
                return Err(ActivationError::ProfileNotFound(profile_id.clone()));
            }
            Err(other) => return Err(ActivationError::Store(other)),
        };
        if !profile.matches(device) {
            return Err(ActivationError::DeviceIncompatible {
                profile_id: profile_id.clone(),
                device: device.clone(),
            });
        }
        if self.is_active(profile_id) {
            return Err(ActivationError::AlreadyActive(profile_id.clone()));
        }
        self.activate_matching(&profile, device)
    }

    /// Deactivates an active connection, returning its profile to
    /// `Disconnected`.
    pub fn deactivate(&mut self, active_id: ActiveConnectionId) -> Result<(), ActivationError> {
        let index = self
            .active
            .iter()
            .position(|active| active.id == active_id)
            .ok_or(ActivationError::UnknownActiveConnection(active_id))?;
        if self.active[index].state != ConnectionState::Activated {
            return Err(ActivationError::InvalidState {
                active_id,
                from: self.active[index].state,
            });
        }
        let profile = self.active[index].profile.clone();
        Self::transition(
            &mut self.active[index],
            ConnectionState::Deactivating,
            &mut self.events,
        )
        .map_err(ActivationError::State)?;
        match self.engine.deactivate(&profile) {
            Ok(()) => {
                Self::transition(
                    &mut self.active[index],
                    ConnectionState::Disconnected,
                    &mut self.events,
                )
                .map_err(ActivationError::State)?;
                self.active.remove(index);
                self.events.push(ConnectionEvent::Deactivated {
                    active_id,
                    profile_id: profile.id,
                });
                Ok(())
            }
            Err(err) => {
                Self::transition(
                    &mut self.active[index],
                    ConnectionState::Failed,
                    &mut self.events,
                )
                .map_err(ActivationError::State)?;
                self.events.push(ConnectionEvent::Failed {
                    active_id,
                    profile_id: profile.id,
                    reason: err.to_string(),
                });
                Err(err)
            }
        }
    }

    fn activate_matching(
        &mut self,
        profile: &ConnectionProfile,
        device: &DeviceInfo,
    ) -> Result<ActiveConnection, ActivationError> {
        let id = ActiveConnectionId(self.next_id);
        self.next_id += 1;
        let mut active = ActiveConnection {
            id,
            profile: profile.clone(),
            device: device.clone(),
            state: ConnectionState::Preparing,
            outcome: ActivationOutcome::default(),
        };
        self.events.push(ConnectionEvent::StateChanged {
            active_id: id,
            profile_id: profile.id.clone(),
            previous: ConnectionState::Disconnected,
            current: ConnectionState::Preparing,
        });
        match self.engine.activate(profile, device) {
            Ok(outcome) => {
                active.outcome = outcome;
                // The engine boundary reports full success in one step in this
                // milestone, so the manager walks the strict state machine
                // through the intermediate stages on the way to Activated.
                Self::transition(&mut active, ConnectionState::Configuring, &mut self.events)
                    .map_err(ActivationError::State)?;
                Self::transition(&mut active, ConnectionState::Activating, &mut self.events)
                    .map_err(ActivationError::State)?;
                Self::transition(&mut active, ConnectionState::Activated, &mut self.events)
                    .map_err(ActivationError::State)?;
                self.events.push(ConnectionEvent::Activated {
                    active_id: id,
                    profile_id: profile.id.clone(),
                });
                self.active.push(active.clone());
                Ok(active)
            }
            Err(err) => {
                Self::transition(&mut active, ConnectionState::Failed, &mut self.events)
                    .map_err(ActivationError::State)?;
                self.events.push(ConnectionEvent::Failed {
                    active_id: id,
                    profile_id: profile.id.clone(),
                    reason: err.to_string(),
                });
                self.active.push(active.clone());
                Err(err)
            }
        }
    }

    fn transition(
        active: &mut ActiveConnection,
        next: ConnectionState,
        events: &mut Vec<ConnectionEvent>,
    ) -> Result<(), StateError> {
        let previous = active.state;
        let current = previous.transition_to(next)?;
        active.state = current;
        events.push(ConnectionEvent::StateChanged {
            active_id: active.id,
            profile_id: active.profile.id.clone(),
            previous,
            current,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivationEngine, ActivationError, ActivationManager, ActiveConnectionId, ConnectionState,
    };
    use crate::connection::device::DeviceInfo;
    use crate::connection::profile::{ConnectionProfile, WifiSecurity};
    use crate::connection::secrets::SecretReference;
    use crate::connection::state::ConnectionEvent;
    use crate::connection::store::{InMemoryProfileStore, ProfileStore};
    use crate::linux::model::Ssid;

    fn wifi_device() -> DeviceInfo {
        DeviceInfo::wifi("wlan0", Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    }

    fn ethernet_device() -> DeviceInfo {
        DeviceInfo::ethernet("eth0", Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
    }

    fn open_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::open(),
        )
        .unwrap()
    }

    fn psk_profile(id: &str) -> ConnectionProfile {
        ConnectionProfile::wifi(
            id,
            id,
            Ssid::from_bytes(b"home").unwrap(),
            WifiSecurity::psk(SecretReference::Keyring {
                identifier: format!("nmd/{id}"),
            }),
        )
        .unwrap()
    }

    struct ScriptedEngine {
        activate_ok: bool,
        deactivate_ok: bool,
    }

    impl Default for ScriptedEngine {
        fn default() -> Self {
            Self {
                activate_ok: true,
                deactivate_ok: true,
            }
        }
    }

    impl ActivationEngine for ScriptedEngine {
        fn activate(
            &mut self,
            _profile: &ConnectionProfile,
            _device: &DeviceInfo,
        ) -> Result<crate::connection::ip::ActivationOutcome, ActivationError> {
            if self.activate_ok {
                Ok(crate::connection::ip::ActivationOutcome::default())
            } else {
                Err(ActivationError::Engine(
                    "simulated activate failure".to_string(),
                ))
            }
        }

        fn deactivate(&mut self, _profile: &ConnectionProfile) -> Result<(), ActivationError> {
            if self.deactivate_ok {
                Ok(())
            } else {
                Err(ActivationError::Engine(
                    "simulated deactivate failure".to_string(),
                ))
            }
        }
    }

    fn failing_activate_engine() -> ScriptedEngine {
        ScriptedEngine {
            activate_ok: false,
            deactivate_ok: true,
        }
    }

    fn failing_deactivate_engine() -> ScriptedEngine {
        ScriptedEngine {
            activate_ok: true,
            deactivate_ok: false,
        }
    }

    #[test]
    fn activation_lifecycle_reports_events_in_order() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));

        let active = manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap();
        assert_eq!(active.state, ConnectionState::Activated);
        assert_eq!(
            manager.state(&"home".to_string()),
            ConnectionState::Activated
        );
        assert_eq!(manager.active_connections().len(), 1);
        assert!(manager.is_active(&"home".to_string()));

        let events = manager.drain_events();
        assert!(matches!(
            events[0],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Disconnected,
                current: ConnectionState::Preparing,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Preparing,
                current: ConnectionState::Configuring,
                ..
            }
        ));
        assert!(matches!(
            events[2],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Configuring,
                current: ConnectionState::Activating,
                ..
            }
        ));
        assert!(matches!(
            events[3],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Activating,
                current: ConnectionState::Activated,
                ..
            }
        ));
        assert!(matches!(events[4], ConnectionEvent::Activated { .. }));
    }

    #[test]
    fn activation_failure_leaves_connection_in_failed_state() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(failing_activate_engine()));

        let err = manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap_err();
        assert!(matches!(err, ActivationError::Engine(_)));
        assert_eq!(manager.state(&"home".to_string()), ConnectionState::Failed);
        assert!(matches!(
            manager.drain_events().last(),
            Some(ConnectionEvent::Failed { .. })
        ));
    }

    #[test]
    fn activation_rejects_incompatible_devices_and_unknown_profiles() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));

        assert!(matches!(
            manager
                .activate_profile(&store, &"home".to_string(), &ethernet_device())
                .unwrap_err(),
            ActivationError::DeviceIncompatible { .. }
        ));
        assert!(matches!(
            manager
                .activate_profile(&store, &"ghost".to_string(), &wifi_device())
                .unwrap_err(),
            ActivationError::ProfileNotFound(_)
        ));
        assert!(manager.active_connections().is_empty());
    }

    #[test]
    fn a_profile_can_only_be_active_once() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));

        manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap();
        assert!(matches!(
            manager
                .activate_profile(&store, &"home".to_string(), &wifi_device())
                .unwrap_err(),
            ActivationError::AlreadyActive(_)
        ));
    }

    #[test]
    fn autoconnect_activation_picks_the_best_profile() {
        let mut store = InMemoryProfileStore::new();
        let mut low = psk_profile("low");
        low.priority = 1;
        let mut high = psk_profile("high");
        high.priority = 10;
        let mut disabled = psk_profile("disabled");
        disabled.enabled = false;
        store.create(low).unwrap();
        store.create(high).unwrap();
        store.create(disabled).unwrap();

        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));
        let active = manager.activate(&store, &wifi_device()).unwrap();
        assert_eq!(active.profile.id, "high");
    }

    #[test]
    fn autoconnect_activation_reports_when_no_profile_matches() {
        let store = InMemoryProfileStore::new();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));
        assert!(matches!(
            manager.activate(&store, &wifi_device()).unwrap_err(),
            ActivationError::NoSuitableProfile(_)
        ));
    }

    #[test]
    fn deactivation_returns_profile_to_disconnected() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));
        let active = manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap();
        manager.drain_events();

        manager.deactivate(active.id).unwrap();
        assert_eq!(
            manager.state(&"home".to_string()),
            ConnectionState::Disconnected
        );
        assert!(manager.active_connections().is_empty());

        let events = manager.drain_events();
        assert!(matches!(
            events[0],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Activated,
                current: ConnectionState::Deactivating,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            ConnectionEvent::StateChanged {
                previous: ConnectionState::Deactivating,
                current: ConnectionState::Disconnected,
                ..
            }
        ));
        assert!(matches!(events[2], ConnectionEvent::Deactivated { .. }));
    }

    #[test]
    fn deactivating_an_unknown_connection_is_rejected() {
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));
        assert!(matches!(
            manager
                .deactivate(ActiveConnectionId::new(999))
                .unwrap_err(),
            ActivationError::UnknownActiveConnection(_)
        ));
    }

    #[test]
    fn a_failed_connection_cannot_be_deactivated() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(failing_activate_engine()));
        manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap_err();

        let failed = &manager.active_connections()[0];
        assert!(matches!(
            manager.deactivate(failed.id).unwrap_err(),
            ActivationError::InvalidState { .. }
        ));
    }

    #[test]
    fn deactivation_failure_marks_connection_failed() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        let mut manager = ActivationManager::new(Box::new(failing_deactivate_engine()));
        let active = manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap();

        assert!(matches!(
            manager.deactivate(active.id).unwrap_err(),
            ActivationError::Engine(_)
        ));
        assert_eq!(manager.state(&"home".to_string()), ConnectionState::Failed);
        assert!(matches!(
            manager.drain_events().last(),
            Some(ConnectionEvent::Failed { .. })
        ));
    }

    #[test]
    fn active_connection_ids_are_unique_and_displayable() {
        let mut store = InMemoryProfileStore::new();
        store.create(open_profile("home")).unwrap();
        store.create(psk_profile("office")).unwrap();
        let mut manager = ActivationManager::new(Box::new(ScriptedEngine::default()));

        let first = manager
            .activate_profile(&store, &"home".to_string(), &wifi_device())
            .unwrap();
        manager.deactivate(first.id).unwrap();
        let second = manager
            .activate_profile(&store, &"office".to_string(), &wifi_device())
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(second.id.to_string(), "2");
        assert_eq!(second.id.as_u64(), 2);
    }
}

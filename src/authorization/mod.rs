//! Authorization boundary between the D-Bus facade and the OS policy layer.
//!
//! Every privileged D-Bus method resolves the caller from the message header
//! and asks the configured [`Authorization`] whether that caller may perform a
//! NetworkManager policy action (`org.freedesktop.NetworkManager.*`). The
//! activation engine and profile store never see authorization concerns; the
//! facade enforces policy at the interface boundary, so a misconfigured
//! backend can only deny access, never bypass it.
//!
//! The actions use NetworkManager's own polkit action IDs rather than a
//! namespaced set: real clients read `GetPermissions` for those exact names
//! and the host policy already defines their semantics.

mod error;
mod polkit;

use std::fmt;
use std::sync::{Arc, Mutex};

pub use error::AuthorizationError;
pub use polkit::PolkitAuthorization;

/// NetworkManager policy action IDs, matching the host polkit policy.
pub const ACTION_ENABLE_DISABLE_NETWORK: &str =
    "org.freedesktop.NetworkManager.enable-disable-network";
pub const ACTION_ENABLE_DISABLE_WIFI: &str = "org.freedesktop.NetworkManager.enable-disable-wifi";
pub const ACTION_NETWORK_CONTROL: &str = "org.freedesktop.NetworkManager.network-control";
pub const ACTION_RELOAD: &str = "org.freedesktop.NetworkManager.reload";
pub const ACTION_SETTINGS_MODIFY_SYSTEM: &str =
    "org.freedesktop.NetworkManager.settings.modify.system";
pub const ACTION_SETTINGS_MODIFY_OWN: &str = "org.freedesktop.NetworkManager.settings.modify.own";

/// Every action exposed through `GetPermissions`, in the order clients see.
pub const PERMISSION_ACTIONS: &[&str] = &[
    ACTION_ENABLE_DISABLE_NETWORK,
    ACTION_ENABLE_DISABLE_WIFI,
    ACTION_NETWORK_CONTROL,
    "org.freedesktop.NetworkManager.wifi.share.protected",
    "org.freedesktop.NetworkManager.wifi.share.open",
    ACTION_SETTINGS_MODIFY_SYSTEM,
    ACTION_SETTINGS_MODIFY_OWN,
    ACTION_RELOAD,
    "org.freedesktop.NetworkManager.checkpoint-rollback",
    "org.freedesktop.NetworkManager.enable-disable-statistics",
    "org.freedesktop.NetworkManager.enable-disable-connectivity-check",
];

/// Who made a D-Bus request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallerIdentity {
    /// The caller's D-Bus unique name (the message header sender).
    UniqueName(String),
    /// The request carried no sender, so it cannot be attributed.
    Unidentifiable,
}

impl CallerIdentity {
    /// Builds the identity from the message header's sender.
    pub fn from_sender(sender: Option<&str>) -> Self {
        match sender {
            Some(name) => Self::UniqueName(name.to_string()),
            None => Self::Unidentifiable,
        }
    }

    /// The unique name to present to a policy backend, if there is one.
    pub fn unique_name(&self) -> Option<&str> {
        match self {
            Self::UniqueName(name) => Some(name),
            Self::Unidentifiable => None,
        }
    }
}

impl fmt::Display for CallerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UniqueName(name) => f.write_str(name),
            Self::Unidentifiable => f.write_str("<unidentifiable>"),
        }
    }
}

/// The answer an authorization backend produced for one action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Yes,
    No,
    Unknown,
}

/// Decides whether a caller may perform a NetworkManager policy action.
///
/// Implementations must be cheap enough to run synchronously on the D-Bus
/// thread and must never return `Err` for a plain denial: a caller that is
/// denied an action is `Ok(No)`. Errors are reserved for failures to determine
/// the answer at all.
pub trait Authorization: Send + Sync {
    fn check(
        &self,
        caller: &CallerIdentity,
        action: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError>;
}

/// Grants every action to every caller. Used by the test facade and as the
/// default for embedding code that wants no policy enforcement.
#[derive(Debug, Default)]
pub struct AllowAllAuthorization;

impl Authorization for AllowAllAuthorization {
    fn check(
        &self,
        _caller: &CallerIdentity,
        _action: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::Yes)
    }
}

/// Denies every action to every caller. Used to prove the enforcement points
/// reject requests before any daemon state changes.
#[derive(Debug, Default)]
pub struct DenyAllAuthorization;

impl Authorization for DenyAllAuthorization {
    fn check(
        &self,
        _caller: &CallerIdentity,
        _action: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::No)
    }
}

/// Records every check it forwards to an inner backend, for tests and
/// debugging.
pub struct RecordingAuthorization {
    inner: Arc<dyn Authorization>,
    calls: Mutex<Vec<(CallerIdentity, String)>>,
}

impl fmt::Debug for RecordingAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingAuthorization")
            .field("calls", &self.calls)
            .finish_non_exhaustive()
    }
}

impl RecordingAuthorization {
    pub fn new(inner: Arc<dyn Authorization>) -> Self {
        Self {
            inner,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The checks forwarded so far, oldest first.
    pub fn calls(&self) -> Vec<(CallerIdentity, String)> {
        self.calls
            .lock()
            .expect("recording authorization mutex poisoned")
            .clone()
    }
}

impl Authorization for RecordingAuthorization {
    fn check(
        &self,
        caller: &CallerIdentity,
        action: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.calls
            .lock()
            .expect("recording authorization mutex poisoned")
            .push((caller.clone(), action.to_string()));
        self.inner.check(caller, action)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllowAllAuthorization, Authorization, AuthorizationDecision, CallerIdentity,
        DenyAllAuthorization, RecordingAuthorization,
    };

    #[test]
    fn allow_all_grants_every_action() {
        let backend = AllowAllAuthorization;
        assert_eq!(
            backend
                .check(&CallerIdentity::Unidentifiable, "any.action")
                .unwrap(),
            AuthorizationDecision::Yes
        );
    }

    #[test]
    fn deny_all_rejects_every_action() {
        let backend = DenyAllAuthorization;
        assert_eq!(
            backend
                .check(&CallerIdentity::from_sender(Some(":1.42")), "any.action")
                .unwrap(),
            AuthorizationDecision::No
        );
    }

    #[test]
    fn recording_authorization_records_callers_and_actions() {
        let backend = RecordingAuthorization::new(std::sync::Arc::new(DenyAllAuthorization));
        let caller = CallerIdentity::from_sender(Some(":1.7"));
        assert_eq!(
            backend.check(&caller, "org.freedesktop.NetworkManager.network-control"),
            Ok(AuthorizationDecision::No)
        );
        assert_eq!(
            backend.calls(),
            vec![(
                caller,
                "org.freedesktop.NetworkManager.network-control".to_string()
            )]
        );
    }

    #[test]
    fn caller_identity_preserves_sender_or_marks_unidentifiable() {
        assert_eq!(
            CallerIdentity::from_sender(Some(":1.9")),
            CallerIdentity::UniqueName(":1.9".to_string())
        );
        assert_eq!(
            CallerIdentity::from_sender(None),
            CallerIdentity::Unidentifiable
        );
        assert_eq!(
            CallerIdentity::UniqueName(":1.9".to_string()).unique_name(),
            Some(":1.9")
        );
        assert_eq!(CallerIdentity::Unidentifiable.unique_name(), None);
    }
}

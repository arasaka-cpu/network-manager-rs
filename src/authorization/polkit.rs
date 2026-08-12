//! Polkit-backed authorization.
//!
//! The production backend asks the system authority
//! (`org.freedesktop.PolicyKit1`) whether the caller's D-Bus unique name may
//! perform the requested NetworkManager action. Only the message-header sender
//! is ever used as the subject; the daemon never trusts caller-supplied uid,
//! pid or username arguments.

use std::collections::HashMap;

use zbus::blocking::Connection;

use crate::authorization::error::AuthorizationError;
use crate::authorization::{Authorization, AuthorizationDecision, CallerIdentity};

/// The well-known system authority the daemon asks.
const POLKIT_DESTINATION: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// Asks the polkit authority on the system bus.
pub struct PolkitAuthorization {
    proxy: zbus::blocking::Proxy<'static>,
}

impl PolkitAuthorization {
    /// Connects to the system bus and binds the polkit authority proxy.
    pub fn new() -> Result<Self, AuthorizationError> {
        let connection = Connection::system().map_err(|error| {
            AuthorizationError::Backend(format!("cannot connect to the system bus: {error}"))
        })?;
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            POLKIT_DESTINATION,
            POLKIT_PATH,
            POLKIT_INTERFACE,
        )
        .map_err(|error| {
            AuthorizationError::Backend(format!("cannot bind polkit proxy: {error}"))
        })?;
        Ok(Self { proxy })
    }
}

impl Authorization for PolkitAuthorization {
    fn check(
        &self,
        caller: &CallerIdentity,
        action: &str,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        let Some(sender) = caller.unique_name() else {
            return Err(AuthorizationError::UnidentifiableCaller);
        };
        let subject: (String, HashMap<String, zbus::zvariant::Value>) = (
            "system-bus-name".to_string(),
            HashMap::from([("name".to_string(), zbus::zvariant::Value::new(sender))]),
        );
        let details: HashMap<String, String> = HashMap::new();
        // No user interaction: the daemon only surfaces policy that the host has
        // already decided for the caller's session.
        let flags: u32 = 0;
        let cancellation_id = String::new();
        let reply: (
            bool,
            HashMap<String, HashMap<String, zbus::zvariant::OwnedValue>>,
        ) = self
            .proxy
            .call(
                "CheckAuthorization",
                &(subject, action, details, flags, cancellation_id),
            )
            .map_err(|error| AuthorizationError::Backend(error.to_string()))?;
        Ok(if reply.0 {
            AuthorizationDecision::Yes
        } else {
            AuthorizationDecision::No
        })
    }
}

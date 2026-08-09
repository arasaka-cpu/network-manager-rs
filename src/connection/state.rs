//! Typed connection state machine.
//!
//! Activation state is modelled explicitly instead of as scattered booleans.
//! A connection may only move between states through [`ConnectionState::transition_to`],
//! which rejects invalid jumps so the daemon can never pretend an activation
//! succeeded unless the underlying operation actually reported success.

use std::fmt;

use crate::connection::activation::ActiveConnectionId;
use crate::connection::profile::ProfileId;

/// The lifecycle state of an active connection.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ConnectionState {
    /// No information about this connection is available yet.
    #[default]
    Unknown,
    /// The connection is known but not active.
    Disconnected,
    /// Activation started: the device is being prepared.
    Preparing,
    /// Device configuration is being applied.
    Configuring,
    /// The connection is being brought up (association, IP, routes).
    Activating,
    /// The underlying operation has reported the connection as up.
    Activated,
    /// Teardown has been requested.
    Deactivating,
    /// The connection attempt or teardown failed.
    Failed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Disconnected => "disconnected",
            Self::Preparing => "preparing",
            Self::Configuring => "configuring",
            Self::Activating => "activating",
            Self::Activated => "activated",
            Self::Deactivating => "deactivating",
            Self::Failed => "failed",
        })
    }
}

impl ConnectionState {
    /// Returns whether a transition from `self` to `next` is allowed.
    pub fn can_transition_to(self, next: ConnectionState) -> bool {
        use ConnectionState::*;
        match self {
            Unknown => matches!(next, Disconnected),
            Disconnected => matches!(next, Preparing),
            Preparing => matches!(next, Configuring | Failed),
            Configuring => matches!(next, Activating | Failed),
            Activating => matches!(next, Activated | Failed),
            Activated => matches!(next, Deactivating | Failed),
            Deactivating => matches!(next, Disconnected | Failed),
            Failed => matches!(next, Disconnected),
        }
    }

    /// Attempts a state transition, rejecting invalid jumps.
    pub fn transition_to(self, next: ConnectionState) -> Result<ConnectionState, StateError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(StateError::InvalidTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// Errors reported by invalid state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidTransition {
        from: ConnectionState,
        to: ConnectionState,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid connection state transition {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for StateError {}

/// Typed events produced by the activation manager.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionEvent {
    StateChanged {
        active_id: ActiveConnectionId,
        profile_id: ProfileId,
        previous: ConnectionState,
        current: ConnectionState,
    },
    Activated {
        active_id: ActiveConnectionId,
        profile_id: ProfileId,
    },
    Deactivated {
        active_id: ActiveConnectionId,
        profile_id: ProfileId,
    },
    Failed {
        active_id: ActiveConnectionId,
        profile_id: ProfileId,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{ConnectionEvent, ConnectionState, StateError};
    use crate::connection::activation::ActiveConnectionId;

    #[test]
    fn success_path_follows_the_full_lifecycle() {
        use ConnectionState::*;
        let path = [
            Unknown,
            Disconnected,
            Preparing,
            Configuring,
            Activating,
            Activated,
            Deactivating,
            Disconnected,
            Preparing,
            Failed,
            Disconnected,
        ];
        for pair in path.windows(2) {
            let from = pair[0];
            let to = pair[1];
            assert_eq!(
                from.transition_to(to).unwrap(),
                to,
                "{from} -> {to} should be allowed"
            );
        }
    }

    #[test]
    fn impossible_jumps_are_rejected() {
        use ConnectionState::*;
        let impossible = [
            (Disconnected, Activated),
            (Preparing, Activated),
            (Activated, Configuring),
            (Activated, Preparing),
            (Unknown, Activated),
            (Failed, Preparing),
            (Failed, Activating),
        ];
        for (from, to) in impossible {
            assert!(
                !from.can_transition_to(to),
                "{from} -> {to} must not be allowed"
            );
            assert_eq!(
                from.transition_to(to),
                Err(StateError::InvalidTransition { from, to }),
                "{from} -> {to} must report an error"
            );
        }
    }

    #[test]
    fn failure_is_always_an_escape_hatch_before_activation() {
        use ConnectionState::*;
        for from in [Preparing, Configuring, Activating] {
            assert_eq!(from.transition_to(Failed).unwrap(), Failed);
        }
    }

    #[test]
    fn failed_connections_can_only_go_back_to_disconnected() {
        use ConnectionState::*;
        assert_eq!(Failed.transition_to(Disconnected).unwrap(), Disconnected);
        assert!(matches!(
            Failed.transition_to(Preparing),
            Err(StateError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn events_are_comparable_and_self_describing() {
        let event = ConnectionEvent::Activated {
            active_id: ActiveConnectionId::new(7),
            profile_id: "home".to_string(),
        };
        assert_eq!(
            event,
            ConnectionEvent::Activated {
                active_id: ActiveConnectionId::new(7),
                profile_id: "home".to_string(),
            }
        );
    }
}

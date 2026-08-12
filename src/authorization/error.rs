//! Authorization error types.

use std::fmt;

/// Reasons an authorization check could not produce a decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    /// The caller's identity could not be determined from the request.
    UnidentifiableCaller,
    /// The authorization backend failed to answer.
    Backend(String),
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnidentifiableCaller => {
                f.write_str("the caller's identity could not be determined")
            }
            Self::Backend(reason) => write!(f, "authorization backend error: {reason}"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

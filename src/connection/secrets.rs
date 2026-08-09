//! Secret-handling boundary.
//!
//! Connection profiles must never hold plaintext credentials. This module
//! defines the reference type stored inside a profile and the provider
//! boundary that a later milestone will implement on top of the appropriate
//! Linux secret-management / authentication infrastructure (Secret Service,
//! keyring agents, and so on). No secret material is ever stored or
//! serialized here.

use serde::{Deserialize, Serialize};

/// A reference to a secret that is managed outside of the profile store.
///
/// A [`SecretReference`] deliberately carries only enough information to
/// locate a secret; it never contains the secret material itself.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum SecretReference {
    /// A secret managed by a system secret service / keyring.
    Keyring { identifier: String },
    /// A secret requested from an agent at activation time.
    Agent { identifier: String },
}

impl SecretReference {
    /// Returns the opaque identifier used to locate the secret.
    pub fn identifier(&self) -> &str {
        match self {
            Self::Keyring { identifier } | Self::Agent { identifier } => identifier,
        }
    }
}

/// Errors surfaced by secret providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    /// No secret could be located for the given reference.
    NotFound,
    /// The provider is not yet available.
    Unavailable,
}

/// Boundary for retrieving secrets referenced by connection profiles.
///
/// The concrete implementation is intentionally left to a later milestone so
/// that this project can coordinate with the existing Linux secret-management
/// and Wi-Fi authentication infrastructure.
pub trait SecretProvider {
    /// Retrieves the secret bytes for `reference`, if one exists.
    fn retrieve(&self, reference: &SecretReference) -> Result<Option<Vec<u8>>, SecretError>;
}

/// A stopgap [`SecretProvider`] that reads passphrases from environment
/// variables named `NMD_WIFI_<identifier>`.
///
/// This is a development convenience, not a production secret store: the
/// passphrase is visible to same-user processes through `/proc/<pid>/environ`.
/// It lets the activation engine be exercised end-to-end until a real Linux
/// secret-management backend (keyring / Secret Service agent) is implemented.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvSecretProvider;

impl SecretProvider for EnvSecretProvider {
    fn retrieve(&self, reference: &SecretReference) -> Result<Option<Vec<u8>>, SecretError> {
        let variable = format!("NMD_WIFI_{}", reference.identifier());
        match std::env::var(&variable) {
            Ok(value) => Ok(Some(value.into_bytes())),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretError, SecretProvider, SecretReference};

    #[test]
    fn reference_exposes_its_identifier() {
        let keyring = SecretReference::Keyring {
            identifier: "nmd/wifi".to_string(),
        };
        let agent = SecretReference::Agent {
            identifier: "nmd/session".to_string(),
        };
        assert_eq!(keyring.identifier(), "nmd/wifi");
        assert_eq!(agent.identifier(), "nmd/session");
    }

    #[test]
    fn reference_round_trips_through_toml() {
        let reference = SecretReference::Keyring {
            identifier: "nmd/wifi".to_string(),
        };
        let encoded = toml::to_string(&reference).unwrap();
        let decoded: SecretReference = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded, reference);
    }

    #[test]
    fn provider_boundary_supports_missing_and_unavailable() {
        struct Provider(&'static [(&'static str, &'static [u8])]);

        impl SecretProvider for Provider {
            fn retrieve(
                &self,
                reference: &SecretReference,
            ) -> Result<Option<Vec<u8>>, SecretError> {
                let id = reference.identifier();
                self.0
                    .iter()
                    .find(|(key, _)| *key == id)
                    .map(|(_, value)| Ok(Some(value.to_vec())))
                    .unwrap_or(Ok(None))
            }
        }

        let provider = Provider(&[("nmd/present", b"hunter2")]);
        let present = SecretReference::Keyring {
            identifier: "nmd/present".to_string(),
        };
        let missing = SecretReference::Keyring {
            identifier: "nmd/absent".to_string(),
        };

        assert_eq!(
            provider.retrieve(&present).unwrap().as_deref(),
            Some(b"hunter2".as_slice())
        );
        assert_eq!(provider.retrieve(&missing).unwrap(), None);
    }

    #[test]
    fn env_provider_reads_its_stopgap_variable() {
        let reference = SecretReference::Keyring {
            identifier: "zbus_env_test".to_string(),
        };
        // SAFETY: this test is single-threaded and the variable only feeds the
        // stopgap provider; setting it cannot affect any other test's data.
        unsafe { std::env::set_var("NMD_WIFI_zbus_env_test", "hunter2") };
        let provider = super::EnvSecretProvider;
        assert_eq!(
            provider.retrieve(&reference).unwrap().as_deref(),
            Some(b"hunter2".as_slice())
        );
        let absent = SecretReference::Keyring {
            identifier: "zbus_env_absent".to_string(),
        };
        assert_eq!(provider.retrieve(&absent).unwrap(), None);
        // SAFETY: mirrors the set above; this test owns the variable.
        unsafe { std::env::remove_var("NMD_WIFI_zbus_env_test") };
    }
}

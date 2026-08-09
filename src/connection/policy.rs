//! Autoconnect policy foundation.
//!
//! This milestone only defines the deterministic ordering used to pick which
//! profile should be tried first. The aggressive background autoconnect daemon
//! is deliberately out of scope.

use crate::connection::profile::{ConnectionProfile, ProfileId};

/// Returns the IDs of profiles eligible for autoconnect, ordered
/// most-likely-first.
///
/// Ordering is deterministic: higher [`ConnectionProfile::priority`] first,
/// ties broken by ascending profile id. Disabled profiles and profiles with
/// autoconnect turned off are excluded.
pub fn order_for_autoconnect(profiles: &[ConnectionProfile]) -> Vec<ProfileId> {
    let mut candidates: Vec<&ConnectionProfile> = profiles
        .iter()
        .filter(|profile| profile.enabled && profile.autoconnect)
        .collect();
    candidates.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
    candidates
        .into_iter()
        .map(|profile| profile.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::order_for_autoconnect;
    use crate::connection::profile::{ConnectionProfile, WifiSecurity};
    use crate::connection::secrets::SecretReference;
    use crate::linux::model::Ssid;

    fn profile(id: &str) -> ConnectionProfile {
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

    #[test]
    fn orders_by_descending_priority() {
        let mut low = profile("low");
        low.priority = 1;
        let mut high = profile("high");
        high.priority = 10;
        let mut middle = profile("middle");
        middle.priority = 5;

        let order = order_for_autoconnect(&[low, middle, high]);
        assert_eq!(order, ["high", "middle", "low"]);
    }

    #[test]
    fn breaks_priority_ties_by_ascending_id() {
        let mut a = profile("a");
        a.priority = 7;
        let mut b = profile("b");
        b.priority = 7;
        let mut c = profile("c");
        c.priority = 7;

        let order = order_for_autoconnect(&[c, a, b]);
        assert_eq!(order, ["a", "b", "c"]);
    }

    #[test]
    fn excludes_disabled_profiles() {
        let enabled = profile("enabled");
        let mut disabled = profile("disabled");
        disabled.enabled = false;

        let order = order_for_autoconnect(&[enabled, disabled]);
        assert_eq!(order, ["enabled"]);
    }

    #[test]
    fn excludes_profiles_with_autoconnect_off() {
        let mut manual = profile("manual");
        manual.autoconnect = false;
        let automatic = profile("automatic");

        let order = order_for_autoconnect(&[manual, automatic]);
        assert_eq!(order, ["automatic"]);
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(order_for_autoconnect(&[]).is_empty());
    }
}

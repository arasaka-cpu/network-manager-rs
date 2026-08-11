//! The `org.freedesktop.NetworkManager.AccessPoint` interface.
//!
//! One object per discovered BSSID. Properties are rendered from the live
//! nl80211 scan results held by the daemon, so the strength and security
//! columns a client sees track the kernel's view.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::interface;
use zbus::zvariant::OwnedValue;

use crate::daemon::NetworkBackend;
use crate::linux::model::{AccessPoint, frequency_to_channel};

use super::error::FacadeError;
use super::shared::Shared;
use super::{
    NM_802_11_AP_SEC_KEY_MGMT_802_1X, NM_802_11_AP_SEC_KEY_MGMT_OWE, NM_802_11_AP_SEC_KEY_MGMT_PSK,
    NM_802_11_AP_SEC_KEY_MGMT_SAE, NM_ACCESS_POINT_FLAGS_NONE, NM_ACCESS_POINT_FLAGS_PRIVACY,
};

/// Maps a dBm signal reading to NetworkManager's 0-100 strength percentage.
fn strength_pct(signal_dbm: Option<i32>) -> u8 {
    signal_dbm
        .map(|dbm| (100 + dbm).clamp(0, 100) as u8)
        .unwrap_or(0)
}

/// Maps the daemon's security model onto the WPA/RSN flag bitmasks.
fn security_flags(ap: &AccessPoint) -> u32 {
    let mut flags = 0;
    if ap.security.wpa2 || ap.security.wpa3 {
        flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;
    }
    if ap.security.wpa1 || ap.security.wpa2 {
        flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
    }
    if ap.security.wpa3 {
        flags |= NM_802_11_AP_SEC_KEY_MGMT_SAE | NM_802_11_AP_SEC_KEY_MGMT_OWE;
    }
    flags
}

/// The `org.freedesktop.NetworkManager.AccessPoint` interface.
pub struct AccessPointIface<B> {
    shared: Arc<Shared<B>>,
    bssid: [u8; 6],
}

impl<B: NetworkBackend + Send + Sync + 'static> AccessPointIface<B> {
    pub fn new(shared: Arc<Shared<B>>, bssid: [u8; 6]) -> Self {
        Self { shared, bssid }
    }

    fn ap(&self) -> Option<AccessPoint> {
        let daemon = self.shared.daemon();
        daemon
            .access_points()
            .unwrap_or_default()
            .into_iter()
            .find(|ap| ap.bssid.as_ref().map(|b| b.as_bytes()) == Some(&self.bssid))
    }
}

#[interface(name = "org.freedesktop.NetworkManager.AccessPoint")]
impl<B: NetworkBackend + Send + Sync + 'static> AccessPointIface<B> {
    #[zbus(property)]
    fn flags(&self) -> Result<u32, zbus::fdo::Error> {
        let ap = self.ap().ok_or_else(|| {
            FacadeError::UnknownDevice(format!(
                "access point {}",
                crate::linux::model::format_mac_address(&self.bssid)
            ))
        })?;
        let privacy = ap.security.wep || ap.security.wpa1 || ap.security.wpa2 || ap.security.wpa3;
        Ok(if privacy {
            NM_ACCESS_POINT_FLAGS_PRIVACY
        } else {
            NM_ACCESS_POINT_FLAGS_NONE
        })
    }

    #[zbus(property)]
    fn wpa_flags(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(security_flags(&self.ap().ok_or_else(|| {
            FacadeError::UnknownDevice(format!(
                "access point {}",
                crate::linux::model::format_mac_address(&self.bssid)
            ))
        })?))
    }

    #[zbus(property)]
    fn rsn_flags(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(security_flags(&self.ap().ok_or_else(|| {
            FacadeError::UnknownDevice(format!(
                "access point {}",
                crate::linux::model::format_mac_address(&self.bssid)
            ))
        })?))
    }

    #[zbus(property)]
    fn ssid(&self) -> Result<Vec<u8>, zbus::fdo::Error> {
        Ok(self
            .ap()
            .ok_or_else(|| {
                FacadeError::UnknownDevice(format!(
                    "access point {}",
                    crate::linux::model::format_mac_address(&self.bssid)
                ))
            })?
            .ssid
            .map(|ssid| ssid.as_bytes().to_vec())
            .unwrap_or_default())
    }

    #[zbus(property)]
    fn frequency(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(self
            .ap()
            .ok_or_else(|| {
                FacadeError::UnknownDevice(format!(
                    "access point {}",
                    crate::linux::model::format_mac_address(&self.bssid)
                ))
            })?
            .frequency
            .unwrap_or(0))
    }

    #[zbus(property)]
    fn channel(&self) -> Result<u32, zbus::fdo::Error> {
        let ap = self.ap().ok_or_else(|| {
            FacadeError::UnknownDevice(format!(
                "access point {}",
                crate::linux::model::format_mac_address(&self.bssid)
            ))
        })?;
        Ok(ap
            .channel
            .map(u32::from)
            .or_else(|| {
                ap.frequency
                    .map(|frequency| u32::from(frequency_to_channel(frequency).unwrap_or(0)))
            })
            .unwrap_or(0))
    }

    #[zbus(property)]
    fn hw_address(&self) -> Result<String, zbus::fdo::Error> {
        Ok(crate::linux::model::format_mac_address(&self.bssid))
    }

    #[zbus(property)]
    fn mode(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(2)
    }

    #[zbus(property)]
    fn max_bitrate(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn bandwidth(&self) -> Result<u32, zbus::fdo::Error> {
        Ok(0)
    }

    #[zbus(property)]
    fn strength(&self) -> Result<u8, zbus::fdo::Error> {
        Ok(strength_pct(
            self.ap()
                .ok_or_else(|| {
                    FacadeError::UnknownDevice(format!(
                        "access point {}",
                        crate::linux::model::format_mac_address(&self.bssid)
                    ))
                })?
                .signal_dbm,
        ))
    }

    #[zbus(property)]
    fn last_seen(&self) -> Result<i32, zbus::fdo::Error> {
        Ok(self
            .ap()
            .ok_or_else(|| {
                FacadeError::UnknownDevice(format!(
                    "access point {}",
                    crate::linux::model::format_mac_address(&self.bssid)
                ))
            })?
            .seen_millis_ago
            .map(|millis| (millis / 1000) as i32)
            .unwrap_or(0))
    }

    #[zbus(property)]
    fn steerable(&self) -> Result<bool, zbus::fdo::Error> {
        Ok(false)
    }

    #[zbus(property)]
    fn ies(&self) -> Result<Vec<HashMap<String, OwnedValue>>, zbus::fdo::Error> {
        Ok(Vec::new())
    }
}

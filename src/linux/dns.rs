//! System DNS management on Linux.
//!
//! [`LinuxDnsManager`] writes a `resolv.conf`-style file on behalf of the
//! daemon, marking every file it writes with an owner sentinel comment. It
//! refuses to touch files managed by another component (systemd-resolved,
//! dnsmasq, or a foreign config), matching the behaviour described in the
//! `DnsManager` trait contract.

use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::connection::ip::{DnsConfig, DnsError, DnsManager, DnsOwnership};

const SENTINEL_PREFIX: &str = "# nmd-owned owner=";
const DEFAULT_PATH: &str = "/etc/resolv.conf";

/// Manages DNS configuration by writing a marked `resolv.conf` file.
#[derive(Debug)]
pub struct LinuxDnsManager {
    path: PathBuf,
}

impl Default for LinuxDnsManager {
    fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_PATH))
    }
}

impl LinuxDnsManager {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_owner(&self) -> Result<Option<String>, DnsError> {
        match fs::read_to_string(&self.path) {
            Ok(content) => Ok(parse_owner(&content)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn serialize(&self, config: &DnsConfig) -> Result<String, DnsError> {
        let mut out = String::new();
        if !config.search_domains.is_empty() {
            out.push_str("search ");
            for (index, domain) in config.search_domains.iter().enumerate() {
                if index > 0 {
                    out.push(' ');
                }
                out.push_str(domain);
            }
            out.push('\n');
        }
        for server in &config.servers {
            match server {
                IpAddr::V4(address) => out.push_str(&format!("nameserver {address}\n")),
                IpAddr::V6(address) => out.push_str(&format!("nameserver {address}\n")),
            }
        }
        Ok(out)
    }
}

fn parse_owner(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(SENTINEL_PREFIX))
        .map(str::trim)
        .filter(|owner| !owner.is_empty())
        .map(str::to_string)
}

impl DnsManager for LinuxDnsManager {
    fn apply(&mut self, owner: &str, config: &DnsConfig) -> Result<DnsOwnership, DnsError> {
        if owner.is_empty() {
            return Err(DnsError::InvalidConfig("owner must not be empty"));
        }
        if let Some(existing) = self.read_owner()? {
            if existing != owner {
                return Err(DnsError::ForeignManaged {
                    path: self.path.display().to_string(),
                });
            }
        } else {
            // No sentinel: only take over files that are absent or effectively
            // empty, never a foreign resolv.conf (e.g. systemd-resolved).
            if let Ok(content) = fs::read_to_string(&self.path) {
                if content.lines().any(|line| !line.trim().is_empty()) {
                    return Err(DnsError::ForeignManaged {
                        path: self.path.display().to_string(),
                    });
                }
            }
        }
        let body = self.serialize(config)?;
        let marked = format!("{SENTINEL_PREFIX}{owner}\n{body}");
        write_atomic(&self.path, marked.as_bytes())?;
        Ok(DnsOwnership {
            owner: owner.to_string(),
            path: self.path.display().to_string(),
        })
    }

    fn remove(&mut self, ownership: &DnsOwnership) -> Result<(), DnsError> {
        match self.read_owner()? {
            Some(existing) if existing == ownership.owner => {
                // Restore the pre-takeover state: the file was empty or absent,
                // so leave the system without our config.
                let _ = fs::remove_file(&self.path);
                Ok(())
            }
            Some(_existing) => Err(DnsError::ForeignManaged {
                path: self.path.display().to_string(),
            }),
            None => Ok(()),
        }
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), DnsError> {
    let directory = path.parent().unwrap_or_else(|| Path::new("/"));
    let mut temporary = directory.join(format!(
        ".{}.tmp{}",
        path.file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "resolv.conf".to_string()),
        std::process::id()
    ));
    let mut counter = 0;
    while temporary.exists() {
        counter += 1;
        temporary = directory.join(format!(
            ".{}.tmp{}.{counter}",
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "resolv.conf".to_string()),
            std::process::id()
        ));
    }
    fs::write(&temporary, contents)?;
    if let Err(err) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(err.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nmd-dns-{tag}-{}", std::process::id()));
        let _ = fs::remove_file(&dir);
        dir
    }

    fn config() -> DnsConfig {
        DnsConfig {
            search_domains: vec!["lan.example".to_string()],
            servers: vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ],
        }
    }

    #[test]
    fn applies_and_removes_owned_config() {
        let path = temp_path("basic");
        let mut manager = LinuxDnsManager::new(path.clone());
        let ownership = manager.apply("profile-a", &config()).unwrap();
        assert_eq!(ownership.owner, "profile-a");
        assert_eq!(ownership.path, path.display().to_string());

        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(parse_owner(&written).as_deref(), Some("profile-a"));
        assert!(written.contains("search lan.example"));
        assert!(written.contains("nameserver 192.168.1.1"));
        assert!(written.contains("nameserver 8.8.8.8"));

        manager.remove(&ownership).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_steal_a_foreign_file() {
        let path = temp_path("foreign");
        fs::write(&path, "nameserver 127.0.0.53\n").unwrap();
        let mut manager = LinuxDnsManager::new(path.clone());
        let err = manager.apply("profile-b", &config()).unwrap_err();
        assert!(matches!(err, DnsError::ForeignManaged { .. }));
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 127.0.0.53\n");
    }

    #[test]
    fn refuses_to_overwrite_another_owner() {
        let path = temp_path("two-owners");
        let mut manager = LinuxDnsManager::new(path.clone());
        manager.apply("owner-one", &config()).unwrap();
        let err = manager.apply("owner-two", &config()).unwrap_err();
        assert!(matches!(err, DnsError::ForeignManaged { .. }));
    }

    #[test]
    fn removal_ignores_unowned_or_absent_files() {
        let path = temp_path("absent");
        let mut manager = LinuxDnsManager::new(path.clone());
        manager
            .remove(&DnsOwnership {
                owner: "nobody".to_string(),
                path: path.display().to_string(),
            })
            .unwrap();

        fs::write(&path, "nameserver 127.0.0.53\n").unwrap();
        manager
            .remove(&DnsOwnership {
                owner: "nobody".to_string(),
                path: path.display().to_string(),
            })
            .unwrap();
        assert!(path.exists(), "foreign file must be left untouched");
    }

    #[test]
    fn renders_ipv6_nameservers() {
        let path = temp_path("ipv6");
        let mut manager = LinuxDnsManager::new(path.clone());
        let ownership = manager
            .apply(
                "profile-v6",
                &DnsConfig {
                    search_domains: vec![],
                    servers: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                },
            )
            .unwrap();
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("nameserver ::1"));
        manager.remove(&ownership).unwrap();
    }

    #[test]
    fn rejects_empty_owner() {
        let path = temp_path("empty-owner");
        let mut manager = LinuxDnsManager::new(path.clone());
        let err = manager.apply("", &config()).unwrap_err();
        assert!(matches!(err, DnsError::InvalidConfig(_)));
    }
}

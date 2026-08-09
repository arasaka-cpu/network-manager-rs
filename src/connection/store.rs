//! Profile storage.
//!
//! The daemon's networking logic depends only on the [`ProfileStore`] trait;
//! persistence details live in the concrete implementations. An in-memory
//! store covers the default daemon, and a TOML-file store provides safe,
//! human-readable persistence on Linux filesystems.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::connection::profile::{ConnectionProfile, ProfileId, ProfileValidationError};

/// Errors surfaced by profile stores.
#[derive(Debug)]
pub enum StoreError {
    NotFound(ProfileId),
    AlreadyExists(ProfileId),
    Invalid(ProfileValidationError),
    Malformed { id: ProfileId, reason: String },
    Io(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "connection profile {id:?} not found"),
            Self::AlreadyExists(id) => write!(f, "connection profile {id:?} already exists"),
            Self::Invalid(reason) => write!(f, "invalid connection profile: {reason}"),
            Self::Malformed { id, reason } => {
                write!(f, "malformed persisted profile {id:?}: {reason}")
            }
            Self::Io(err) => write!(f, "profile store I/O failed: {err}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Storage boundary for connection profiles.
///
/// `Send` is required so a daemon holding `Box<dyn ProfileStore>` can be
/// shared across the D-Bus compatibility layer's object server threads.
pub trait ProfileStore: Send {
    /// Lists all profiles, deterministically ordered by id.
    fn list(&self) -> Result<Vec<ConnectionProfile>, StoreError>;

    /// Retrieves a single profile by id.
    fn get(&self, id: &ProfileId) -> Result<ConnectionProfile, StoreError>;

    /// Creates a new profile; rejects duplicates and invalid profiles.
    fn create(&mut self, profile: ConnectionProfile) -> Result<(), StoreError>;

    /// Replaces an existing profile; rejects unknown ids and invalid profiles.
    fn update(&mut self, profile: ConnectionProfile) -> Result<(), StoreError>;

    /// Removes a profile by id.
    fn delete(&mut self, id: &ProfileId) -> Result<(), StoreError>;
}

/// A profile store kept entirely in memory. Used as the default daemon store
/// so the daemon itself never depends on filesystem details.
#[derive(Debug, Default)]
pub struct InMemoryProfileStore {
    profiles: BTreeMap<ProfileId, ConnectionProfile>,
}

impl InMemoryProfileStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProfileStore for InMemoryProfileStore {
    fn list(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        Ok(self.profiles.values().cloned().collect())
    }

    fn get(&self, id: &ProfileId) -> Result<ConnectionProfile, StoreError> {
        self.profiles
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(id.clone()))
    }

    fn create(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        profile.validate().map_err(StoreError::Invalid)?;
        if self.profiles.contains_key(&profile.id) {
            return Err(StoreError::AlreadyExists(profile.id));
        }
        self.profiles.insert(profile.id.clone(), profile);
        Ok(())
    }

    fn update(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        profile.validate().map_err(StoreError::Invalid)?;
        if !self.profiles.contains_key(&profile.id) {
            return Err(StoreError::NotFound(profile.id));
        }
        self.profiles.insert(profile.id.clone(), profile);
        Ok(())
    }

    fn delete(&mut self, id: &ProfileId) -> Result<(), StoreError> {
        if self.profiles.remove(id).is_none() {
            return Err(StoreError::NotFound(id.clone()));
        }
        Ok(())
    }
}

/// A profile store persisted as one TOML file per profile.
///
/// File names are derived from the validated profile id (restricted to ASCII
/// alphanumerics, `-` and `_`), which prevents path traversal. Malformed files
/// are surfaced as [`StoreError::Malformed`] rather than being silently
/// ignored.
pub struct FileProfileStore {
    directory: PathBuf,
}

impl FileProfileStore {
    /// Opens (creating if necessary) a store rooted at `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path_for(&self, id: &ProfileId) -> PathBuf {
        self.directory.join(format!("{id}.toml"))
    }

    fn write_profile(&self, profile: &ConnectionProfile) -> Result<(), StoreError> {
        profile.validate().map_err(StoreError::Invalid)?;
        let serialized = toml::to_string(profile).map_err(|err| StoreError::Malformed {
            id: profile.id.clone(),
            reason: err.to_string(),
        })?;
        fs::write(self.path_for(&profile.id), serialized)?;
        Ok(())
    }

    fn read_profile(&self, id: &ProfileId) -> Result<ConnectionProfile, StoreError> {
        let contents = fs::read_to_string(self.path_for(id))?;
        parse_profile(id, &contents)
    }

    fn profile_paths(&self) -> Result<Vec<PathBuf>, StoreError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }
}

fn parse_profile(id: &ProfileId, contents: &str) -> Result<ConnectionProfile, StoreError> {
    let profile: ConnectionProfile =
        toml::from_str(contents).map_err(|err| StoreError::Malformed {
            id: id.clone(),
            reason: err.to_string(),
        })?;
    if &profile.id != id {
        return Err(StoreError::Malformed {
            id: id.clone(),
            reason: format!("file name does not match profile id {:?}", profile.id),
        });
    }
    profile.validate().map_err(|err| StoreError::Malformed {
        id: id.clone(),
        reason: err.to_string(),
    })?;
    Ok(profile)
}

impl ProfileStore for FileProfileStore {
    fn list(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        let mut profiles = Vec::new();
        for path in self.profile_paths()? {
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| StoreError::Malformed {
                    id: path.display().to_string(),
                    reason: "invalid file name".to_string(),
                })?;
            let contents = fs::read_to_string(&path)?;
            profiles.push(parse_profile(&id.to_string(), &contents)?);
        }
        profiles.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(profiles)
    }

    fn get(&self, id: &ProfileId) -> Result<ConnectionProfile, StoreError> {
        if !self.path_for(id).is_file() {
            return Err(StoreError::NotFound(id.clone()));
        }
        self.read_profile(id)
    }

    fn create(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        if self.path_for(&profile.id).is_file() {
            return Err(StoreError::AlreadyExists(profile.id));
        }
        self.write_profile(&profile)
    }

    fn update(&mut self, profile: ConnectionProfile) -> Result<(), StoreError> {
        if !self.path_for(&profile.id).is_file() {
            return Err(StoreError::NotFound(profile.id));
        }
        self.write_profile(&profile)
    }

    fn delete(&mut self, id: &ProfileId) -> Result<(), StoreError> {
        if !self.path_for(id).is_file() {
            return Err(StoreError::NotFound(id.clone()));
        }
        fs::remove_file(self.path_for(id))?;
        Ok(())
    }
}

impl AsRef<Path> for FileProfileStore {
    fn as_ref(&self) -> &Path {
        &self.directory
    }
}

#[cfg(test)]
mod tests {
    use super::{FileProfileStore, InMemoryProfileStore, ProfileStore, StoreError};
    use crate::connection::profile::{ConnectionProfile, WifiSecurity};
    use crate::connection::secrets::SecretReference;
    use crate::linux::model::Ssid;

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

    fn temp_store_dir(label: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("nmd-test-{label}-{}-{unique}", std::process::id()))
    }

    #[test]
    fn in_memory_store_crud_round_trip() {
        let mut store = InMemoryProfileStore::new();
        assert!(store.list().unwrap().is_empty());

        store.create(psk_profile("home")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(store.get(&"home".to_string()).unwrap().id, "home");

        store.update(open_profile("home")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);

        store.delete(&"home".to_string()).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(matches!(
            store.delete(&"home".to_string()),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn in_memory_store_rejects_duplicates() {
        let mut store = InMemoryProfileStore::new();
        store.create(psk_profile("home")).unwrap();
        assert!(matches!(
            store.create(psk_profile("home")),
            Err(StoreError::AlreadyExists(_))
        ));
    }

    #[test]
    fn in_memory_store_rejects_invalid_profiles() {
        let mut store = InMemoryProfileStore::new();
        let mut invalid = psk_profile("home");
        invalid.name = String::new();
        assert!(matches!(store.create(invalid), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn in_memory_store_rejects_updates_to_unknown_ids() {
        let mut store = InMemoryProfileStore::new();
        assert!(matches!(
            store.update(psk_profile("ghost")),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn in_memory_store_lists_in_deterministic_id_order() {
        let mut store = InMemoryProfileStore::new();
        store.create(psk_profile("zeta")).unwrap();
        store.create(psk_profile("alpha")).unwrap();
        store.create(psk_profile("mid")).unwrap();
        let ids: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(ids, ["alpha", "mid", "zeta"]);
    }

    #[test]
    fn file_store_persists_and_reloads_profiles() {
        let directory = temp_store_dir("file");
        let mut store = FileProfileStore::new(&directory).unwrap();
        store.create(psk_profile("home")).unwrap();
        store.create(psk_profile("office")).unwrap();
        drop(store);

        let reloaded = FileProfileStore::new(&directory).unwrap();
        let ids: Vec<String> = reloaded
            .list()
            .unwrap()
            .into_iter()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(ids, ["home", "office"]);
        assert_eq!(reloaded.get(&"home".to_string()).unwrap().id, "home");
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn file_store_surfaces_malformed_files() {
        let directory = temp_store_dir("malformed");
        FileProfileStore::new(&directory).unwrap();
        std::fs::write(directory.join("broken.toml"), "this is not toml").unwrap();

        let store = FileProfileStore::new(&directory).unwrap();
        assert!(matches!(
            store.get(&"broken".to_string()),
            Err(StoreError::Malformed { .. })
        ));
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn file_store_rejects_mismatched_file_name_and_id() {
        let directory = temp_store_dir("mismatch");
        let store = FileProfileStore::new(&directory).unwrap();
        let profile = psk_profile("home");
        std::fs::write(
            directory.join("other.toml"),
            toml::to_string(&profile).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            store.get(&"other".to_string()),
            Err(StoreError::Malformed { .. })
        ));
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn file_store_rejects_duplicate_create() {
        let directory = temp_store_dir("duplicate");
        let mut store = FileProfileStore::new(&directory).unwrap();
        store.create(psk_profile("home")).unwrap();
        assert!(matches!(
            store.create(psk_profile("home")),
            Err(StoreError::AlreadyExists(_))
        ));
        std::fs::remove_dir_all(&directory).ok();
    }
}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

const LEGACY_ENTRY: &str = "secrets";
const MANIFEST_ENTRY: &str = "secrets.v2.manifest";
const CHUNK_ENTRY_PREFIX: &str = "secrets.v2";
const MAX_CHUNK_UTF16_UNITS: usize = 900;
const MAX_CHUNKS: usize = 1_024;
const MAX_SECRET_BYTES: usize = 4 * 1024 * 1024;
const FORMAT_VERSION: u32 = 2;

pub(crate) trait CredentialStore {
    fn get(&self, name: &str) -> Result<Option<String>, String>;
    fn set(&self, name: &str, value: &str) -> Result<(), String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    active: Option<GenerationMetadata>,
    pending: Option<GenerationMetadata>,
    retired: Option<GenerationMetadata>,
    legacy_cleanup_pending: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationMetadata {
    id: String,
    chunks: usize,
    digest: String,
}

impl Manifest {
    fn empty() -> Self {
        Self {
            version: FORMAT_VERSION,
            active: None,
            pending: None,
            retired: None,
            legacy_cleanup_pending: false,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != FORMAT_VERSION {
            return Err("Unsupported keyring secrets format version".to_string());
        }
        for generation in [&self.active, &self.pending, &self.retired]
            .into_iter()
            .flatten()
        {
            if Uuid::parse_str(&generation.id).is_err()
                || generation.chunks == 0
                || generation.chunks > MAX_CHUNKS
                || generation.digest.len() != 64
                || !generation
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("Invalid keyring secrets manifest metadata".to_string());
            }
        }
        if let (Some(active), Some(pending)) = (&self.active, &self.pending) {
            if active.id == pending.id {
                return Err("Invalid keyring secrets manifest generations".to_string());
            }
        }
        if let (Some(active), Some(retired)) = (&self.active, &self.retired) {
            if active.id == retired.id {
                return Err("Invalid keyring secrets manifest generations".to_string());
            }
        }
        Ok(())
    }
}

fn generation_entry(id: &str, index: usize) -> String {
    format!("{CHUNK_ENTRY_PREFIX}.{id}.{index:04}")
}

fn digest(payload: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(payload.as_bytes()) {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn service_lock_name(service: &str) -> String {
    format!("secrets.keyring.{}", digest(service))
}

fn split_chunks(payload: &str) -> Result<Vec<String>, String> {
    if payload.len() > MAX_SECRET_BYTES {
        return Err("Serialized keyring secrets exceed the supported size".to_string());
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut utf16_units = 0;

    for character in payload.chars() {
        let character_units = character.len_utf16();
        if utf16_units + character_units > MAX_CHUNK_UTF16_UNITS {
            chunks.push(std::mem::take(&mut current));
            utf16_units = 0;
        }
        current.push(character);
        utf16_units += character_units;
    }
    if !current.is_empty() || chunks.is_empty() {
        chunks.push(current);
    }
    if chunks.len() > MAX_CHUNKS {
        return Err("Serialized keyring secrets require too many entries".to_string());
    }
    Ok(chunks)
}

fn read_manifest(store: &impl CredentialStore) -> Result<Option<Manifest>, String> {
    let Some(content) = store.get(MANIFEST_ENTRY)? else {
        return Ok(None);
    };
    let manifest: Manifest = serde_json::from_str(&content)
        .map_err(|_| "Invalid keyring secrets manifest".to_string())?;
    manifest.validate()?;
    Ok(Some(manifest))
}

fn write_manifest(store: &impl CredentialStore, manifest: &Manifest) -> Result<(), String> {
    manifest.validate()?;
    let content = serde_json::to_string(manifest)
        .map_err(|_| "Unable to serialize keyring secrets manifest".to_string())?;
    store.set(MANIFEST_ENTRY, &content)
}

fn delete_generation(
    store: &impl CredentialStore,
    generation: &GenerationMetadata,
) -> Result<(), String> {
    for index in 0..generation.chunks {
        store.delete(&generation_entry(&generation.id, index))?;
    }
    Ok(())
}

fn recover_manifest(store: &impl CredentialStore, manifest: &mut Manifest) -> Result<(), String> {
    let had_recovery_work =
        manifest.pending.is_some() || manifest.retired.is_some() || manifest.legacy_cleanup_pending;

    if let Some(pending) = &manifest.pending {
        delete_generation(store, pending)?;
        manifest.pending = None;
    }
    if let Some(retired) = &manifest.retired {
        delete_generation(store, retired)?;
        manifest.retired = None;
    }
    if manifest.legacy_cleanup_pending {
        store.delete(LEGACY_ENTRY)?;
        manifest.legacy_cleanup_pending = false;
    }

    if had_recovery_work {
        write_manifest(store, manifest)?;
    }
    Ok(())
}

fn read_generation(
    store: &impl CredentialStore,
    generation: &GenerationMetadata,
) -> Result<String, String> {
    let mut payload = String::new();
    for index in 0..generation.chunks {
        let chunk = store
            .get(&generation_entry(&generation.id, index))?
            .ok_or_else(|| "Incomplete keyring secrets generation".to_string())?;
        payload.push_str(&chunk);
        if payload.len() > MAX_SECRET_BYTES {
            return Err("Keyring secrets exceed the supported size".to_string());
        }
    }
    if digest(&payload) != generation.digest {
        return Err("Keyring secrets integrity check failed".to_string());
    }
    Ok(payload)
}

fn parse_secrets(content: &str) -> Result<HashMap<String, Value>, String> {
    serde_json::from_str(content).map_err(|_| "Invalid keyring secrets payload".to_string())
}

pub(crate) fn read(store: &impl CredentialStore) -> Result<Option<HashMap<String, Value>>, String> {
    let Some(mut manifest) = read_manifest(store)? else {
        return store
            .get(LEGACY_ENTRY)?
            .map(|content| parse_secrets(&content))
            .transpose();
    };

    recover_manifest(store, &mut manifest)?;

    let has_legacy = store.get(LEGACY_ENTRY)?.is_some();
    if manifest.active.is_some() && has_legacy && !manifest.legacy_cleanup_pending {
        return Err(
            "Legacy keyring secrets reappeared after versioned storage was committed".to_string(),
        );
    }

    let Some(active) = &manifest.active else {
        return store
            .get(LEGACY_ENTRY)?
            .map(|content| parse_secrets(&content))
            .transpose();
    };

    let payload = read_generation(store, active)?;
    parse_secrets(&payload).map(Some)
}

pub(crate) fn write(
    store: &impl CredentialStore,
    values: &HashMap<String, Value>,
) -> Result<(), String> {
    let _ = read(store)?;
    let mut manifest = match read_manifest(store)? {
        Some(mut manifest) => {
            recover_manifest(store, &mut manifest)?;
            manifest
        }
        None => Manifest::empty(),
    };

    let payload = serde_json::to_string(values)
        .map_err(|_| "Unable to serialize keyring secrets".to_string())?;
    let chunks = split_chunks(&payload)?;
    let new_generation = Uuid::new_v4().to_string();
    let new_metadata = GenerationMetadata {
        id: new_generation.clone(),
        chunks: chunks.len(),
        digest: digest(&payload),
    };
    let legacy_cleanup_pending = manifest.active.is_none() && store.get(LEGACY_ENTRY)?.is_some();
    let previous_active = manifest.active.clone();

    manifest.pending = Some(new_metadata.clone());
    write_manifest(store, &manifest)?;

    for (index, chunk) in chunks.iter().enumerate() {
        store.set(&generation_entry(&new_generation, index), chunk)?;
    }
    if read_generation(store, &new_metadata)? != payload {
        return Err("Staged keyring secrets failed verification".to_string());
    }

    let committed = Manifest {
        version: FORMAT_VERSION,
        active: Some(new_metadata),
        pending: None,
        retired: previous_active,
        legacy_cleanup_pending,
    };
    write_manifest(store, &committed)?;

    let mut recovered = committed;
    recover_manifest(store, &mut recovered)
}

#[cfg(all(windows, feature = "system-keyring", test))]
pub(crate) fn clear_for_test(store: &impl CredentialStore) -> Result<(), String> {
    if let Some(manifest) = read_manifest(store)? {
        for generation in [&manifest.active, &manifest.pending, &manifest.retired]
            .into_iter()
            .flatten()
        {
            delete_generation(store, generation)?;
        }
    }
    store.delete(LEGACY_ENTRY)?;
    store.delete(MANIFEST_ENTRY)?;
    Ok(())
}

#[cfg(all(windows, feature = "system-keyring"))]
pub(crate) struct SystemCredentialStore {
    service: String,
}

#[cfg(all(windows, feature = "system-keyring"))]
impl SystemCredentialStore {
    pub(crate) fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(all(windows, feature = "system-keyring"))]
impl CredentialStore for SystemCredentialStore {
    fn get(&self, name: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(&self.service, name).map_err(|error| error.to_string())?;
        match entry.get_password() {
            Ok(content) => Ok(Some(content)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn set(&self, name: &str, value: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(&self.service, name).map_err(|error| error.to_string())?;
        entry.set_password(value).map_err(|error| error.to_string())
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(&self.service, name).map_err(|error| error.to_string())?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStore {
        values: Mutex<HashMap<String, String>>,
        set_count: AtomicIsize,
        fail_on_set: AtomicIsize,
        fail_delete: Mutex<Option<String>>,
    }

    impl MemoryStore {
        fn fail_on_set_number(&self, set_number: isize) {
            self.set_count.store(0, Ordering::SeqCst);
            self.fail_on_set.store(set_number, Ordering::SeqCst);
        }

        fn fail_delete_once(&self, name: String) {
            *self.fail_delete.lock().unwrap() = Some(name);
        }

        fn has(&self, name: &str) -> bool {
            self.values.lock().unwrap().contains_key(name)
        }
    }

    impl CredentialStore for MemoryStore {
        fn get(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.values.lock().unwrap().get(name).cloned())
        }

        fn set(&self, name: &str, value: &str) -> Result<(), String> {
            let count = self.set_count.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_set.load(Ordering::SeqCst) == count {
                return Err("injected set failure".to_string());
            }
            self.values
                .lock()
                .unwrap()
                .insert(name.to_string(), value.to_string());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<(), String> {
            let mut fail_delete = self.fail_delete.lock().unwrap();
            if fail_delete.as_deref() == Some(name) {
                *fail_delete = None;
                return Err("injected delete failure".to_string());
            }
            self.values.lock().unwrap().remove(name);
            Ok(())
        }
    }

    fn secrets(key: &str, value: Value) -> HashMap<String, Value> {
        HashMap::from([(key.to_string(), value)])
    }

    #[test]
    fn chunks_respect_utf16_boundaries_and_limits() {
        let payload = "a".repeat(899) + "🧪" + &"b".repeat(901);
        let chunks = split_chunks(&payload).unwrap();
        assert!(chunks.len() > 1);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.encode_utf16().count() <= MAX_CHUNK_UTF16_UNITS));
        assert_eq!(chunks.concat(), payload);
    }

    #[test]
    fn lock_name_is_stable_and_specific_to_the_vault() {
        assert_eq!(
            service_lock_name("goose-test"),
            service_lock_name("goose-test")
        );
        assert_ne!(service_lock_name("goose-test"), service_lock_name("goose"));
        assert!(!service_lock_name("goose-test").contains("goose-test"));
    }

    #[test]
    fn oversized_token_and_combined_secrets_round_trip() {
        let store = MemoryStore::default();
        let large_token = "synthetic-token-".repeat(1_200);
        let values = HashMap::from([
            ("oauth_creds_ecl".to_string(), Value::String(large_token)),
            (
                "PROVIDER_API_KEY".to_string(),
                Value::String("synthetic-key".to_string()),
            ),
        ]);
        write(&store, &values).unwrap();
        assert_eq!(read(&store).unwrap(), Some(values));
    }

    #[test]
    fn first_write_migrates_legacy_entry_without_losing_unrelated_secrets() {
        let store = MemoryStore::default();
        let existing = HashMap::from([
            (
                "old_api_key".to_string(),
                Value::String("synthetic-api-key".to_string()),
            ),
            (
                "oauth_creds".to_string(),
                Value::String("synthetic-refresh".to_string()),
            ),
        ]);
        store
            .set(LEGACY_ENTRY, &serde_json::to_string(&existing).unwrap())
            .unwrap();
        assert_eq!(read(&store).unwrap(), Some(existing.clone()));

        let mut updated = existing.clone();
        updated.insert(
            "new_key".to_string(),
            Value::String("new-value".to_string()),
        );
        write(&store, &updated).unwrap();
        assert_eq!(read(&store).unwrap(), Some(updated));
        assert!(!store.has(LEGACY_ENTRY));
    }

    #[test]
    fn interrupted_staging_keeps_old_generation_authoritative() {
        let store = MemoryStore::default();
        let old = secrets("oauth", Value::String("old-token".to_string()));
        write(&store, &old).unwrap();

        let new = secrets("oauth", Value::String("new-token-".repeat(1_200)));
        store.fail_on_set_number(2);
        assert!(write(&store, &new).is_err());
        store.fail_on_set_number(-1);
        assert_eq!(read(&store).unwrap(), Some(old));
        let manifest = read_manifest(&store).unwrap().unwrap();
        assert!(manifest.pending.is_none());
    }

    #[test]
    fn failed_commit_keeps_old_generation_authoritative() {
        let store = MemoryStore::default();
        let old = secrets("oauth", Value::String("old-token".to_string()));
        write(&store, &old).unwrap();

        let new = secrets("oauth", Value::String("new-token".to_string()));
        store.fail_on_set_number(3); // pending marker, chunk, commit marker
        assert!(write(&store, &new).is_err());
        store.fail_on_set_number(-1);
        assert_eq!(read(&store).unwrap(), Some(old));
    }

    #[test]
    fn cleanup_failure_is_reported_and_recovered_on_next_read() {
        let store = MemoryStore::default();
        let old = secrets("oauth", Value::String("old-token".to_string()));
        write(&store, &old).unwrap();
        let previous = read_manifest(&store).unwrap().unwrap().active.unwrap();
        store.fail_delete_once(generation_entry(&previous.id, 0));

        let new = secrets("oauth", Value::String("new-token".to_string()));
        assert!(write(&store, &new).is_err());
        assert_eq!(read(&store).unwrap(), Some(new));
        assert!(!store.has(&generation_entry(&previous.id, 0)));
    }

    #[test]
    fn corrupted_manifest_and_payload_fail_closed() {
        let store = MemoryStore::default();
        store.set(MANIFEST_ENTRY, "not-json").unwrap();
        store
            .set(
                LEGACY_ENTRY,
                &serde_json::to_string(&secrets("legacy", Value::Bool(true))).unwrap(),
            )
            .unwrap();
        assert!(read(&store).is_err());

        let store = MemoryStore::default();
        write(
            &store,
            &secrets("oauth", Value::String("synthetic".to_string())),
        )
        .unwrap();
        let manifest = read_manifest(&store).unwrap().unwrap();
        let active = manifest.active.unwrap();
        store
            .set(&generation_entry(&active.id, 0), "tampered")
            .unwrap();
        assert!(read(&store).is_err());
    }

    #[test]
    fn revoking_a_secret_removes_it_from_the_committed_vault() {
        let store = MemoryStore::default();
        let original = HashMap::from([
            (
                "oauth_creds_ecl".to_string(),
                Value::String("synthetic-refresh-token".to_string()),
            ),
            (
                "PROVIDER_API_KEY".to_string(),
                Value::String("synthetic-provider-key".to_string()),
            ),
        ]);
        write(&store, &original).unwrap();
        let old_generation = read_manifest(&store).unwrap().unwrap().active.unwrap();

        let remaining = secrets(
            "PROVIDER_API_KEY",
            Value::String("synthetic-provider-key".to_string()),
        );
        write(&store, &remaining).unwrap();

        assert_eq!(read(&store).unwrap(), Some(remaining));
        assert!(!store.has(&generation_entry(&old_generation.id, 0)));
    }

    #[cfg(all(windows, feature = "system-keyring"))]
    #[test]
    fn native_windows_keyring_round_trips_oversized_synthetic_oauth_secret() {
        let service = format!("goose-test-{}", Uuid::new_v4());
        let store = SystemCredentialStore::new(&service);
        let values = secrets(
            "oauth_creds_ecl",
            Value::String("synthetic-access-refresh-token-".repeat(1_200)),
        );

        let result = write(&store, &values).and_then(|_| {
            let actual = read(&store)?;
            if actual != Some(values.clone()) {
                return Err("Native Windows keyring round-trip mismatch".to_string());
            }
            Ok(())
        });
        let cleanup = clear_for_test(&store);
        result.unwrap();
        cleanup.unwrap();
    }
}

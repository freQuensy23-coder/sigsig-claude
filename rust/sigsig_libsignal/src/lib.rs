// SPDX-License-Identifier: AGPL-3.0-only
//
// PyO3 bindings around libsignal-protocol (vendored at ../../../libsignal).
//
// Every cryptographic operation goes through libsignal's audited Rust
// implementation — we merely provide Python-facing wrappers and a
// serializable in-memory store.
//
// Store layout follows libsignal's own `InMemSignalProtocolStore`: six
// sub-stores, each implementing exactly one trait, so the borrow-checker
// lets us hand them as distinct `&mut dyn` arguments to
// `message_encrypt` / `message_decrypt_prekey` / `process_prekey_bundle`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::executor::block_on;
use libsignal_core::{Aci, DeviceId, Pni, ProtocolAddress};
use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    sealed_sender_decrypt, CiphertextMessage, CiphertextMessageType, Direction,
    GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyBundleContent,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, PrivateKey, PublicKey,
    SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::{
    auth::{AuthCredentialWithPni, AuthCredentialWithPniResponse},
    groups::{GroupMasterKey, GroupSecretParams, UuidCiphertext},
    ServerPublicParams, Timestamp as ZkTimestamp,
};

// ---------------------------------------------------------------------------
// Sub-stores. Each owns one HashMap so they can be independently borrowed.
// ---------------------------------------------------------------------------

struct IdentityPart {
    identity: IdentityKeyPair,
    registration_id: u32,
    known: HashMap<String, Vec<u8>>,
}

#[derive(Default)]
struct PreKeysPart(HashMap<u32, Vec<u8>>);
#[derive(Default)]
struct SignedPreKeysPart(HashMap<u32, Vec<u8>>);
#[derive(Default)]
struct KyberPreKeysPart(HashMap<u32, Vec<u8>>);
#[derive(Default)]
struct SessionsPart(HashMap<String, Vec<u8>>);
#[derive(Default)]
struct SenderKeysPart(HashMap<(String, Uuid), Vec<u8>>);

struct Store {
    identity: IdentityPart,
    pre_keys: PreKeysPart,
    signed_pre_keys: SignedPreKeysPart,
    kyber_pre_keys: KyberPreKeysPart,
    sessions: SessionsPart,
    sender_keys: SenderKeysPart,
}

impl Store {
    fn new(identity: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity: IdentityPart {
                identity,
                registration_id,
                known: HashMap::new(),
            },
            pre_keys: Default::default(),
            signed_pre_keys: Default::default(),
            kyber_pre_keys: Default::default(),
            sessions: Default::default(),
            sender_keys: Default::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Persistable blob.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct StoreBlob {
    identity: Vec<u8>,
    registration_id: u32,
    known_identities: Vec<(String, Vec<u8>)>,
    pre_keys: Vec<(u32, Vec<u8>)>,
    signed_pre_keys: Vec<(u32, Vec<u8>)>,
    kyber_pre_keys: Vec<(u32, Vec<u8>)>,
    sessions: Vec<(String, Vec<u8>)>,
    sender_keys: Vec<((String, [u8; 16]), Vec<u8>)>,
}

impl Store {
    fn to_blob(&self) -> Result<Vec<u8>, SignalProtocolError> {
        let blob = StoreBlob {
            identity: self.identity.identity.serialize().into_vec(),
            registration_id: self.identity.registration_id,
            known_identities: self
                .identity
                .known
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            pre_keys: self
                .pre_keys
                .0
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            signed_pre_keys: self
                .signed_pre_keys
                .0
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            kyber_pre_keys: self
                .kyber_pre_keys
                .0
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            sessions: self
                .sessions
                .0
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            sender_keys: self
                .sender_keys
                .0
                .iter()
                .map(|((k, uuid), v)| ((k.clone(), *uuid.as_bytes()), v.clone()))
                .collect(),
        };
        bincode::serialize(&blob)
            .map_err(|e| SignalProtocolError::InvalidState("serialize", e.to_string()))
    }

    fn from_blob(data: &[u8]) -> Result<Self, SignalProtocolError> {
        let blob: StoreBlob = bincode::deserialize(data)
            .map_err(|e| SignalProtocolError::InvalidState("deserialize", e.to_string()))?;
        Ok(Self {
            identity: IdentityPart {
                identity: IdentityKeyPair::try_from(&blob.identity[..])?,
                registration_id: blob.registration_id,
                known: blob.known_identities.into_iter().collect(),
            },
            pre_keys: PreKeysPart(blob.pre_keys.into_iter().collect()),
            signed_pre_keys: SignedPreKeysPart(blob.signed_pre_keys.into_iter().collect()),
            kyber_pre_keys: KyberPreKeysPart(blob.kyber_pre_keys.into_iter().collect()),
            sessions: SessionsPart(blob.sessions.into_iter().collect()),
            sender_keys: SenderKeysPart(
                blob.sender_keys
                    .into_iter()
                    .map(|((k, bytes), v)| ((k, Uuid::from_bytes(bytes)), v))
                    .collect(),
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Trait impls — one per sub-store.
// ---------------------------------------------------------------------------

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityPart {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(self.identity)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let key = address.to_string();
        let bytes = identity.serialize().into_vec();
        let change = match self.known.get(&key) {
            None => IdentityChange::NewOrUnchanged,
            Some(existing) if existing == &bytes => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
        };
        self.known.insert(key, bytes);
        Ok(change)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.known.get(&address.to_string()) {
            None => Ok(true),
            Some(existing) => Ok(existing == &identity.serialize().into_vec()),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        match self.known.get(&address.to_string()) {
            None => Ok(None),
            Some(bytes) => Ok(Some(IdentityKey::decode(bytes)?)),
        }
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeysPart {
    async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let key: u32 = id.into();
        self.0
            .get(&key)
            .ok_or(SignalProtocolError::InvalidPreKeyId)
            .and_then(|bytes| PreKeyRecord::deserialize(bytes))
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(id.into(), record.serialize()?);
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.0.remove(&id.into());
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeysPart {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let key: u32 = id.into();
        self.0
            .get(&key)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
            .and_then(|bytes| SignedPreKeyRecord::deserialize(bytes))
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(id.into(), record.serialize()?);
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeysPart {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let key: u32 = id.into();
        self.0
            .get(&key)
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
            .and_then(|bytes| KyberPreKeyRecord::deserialize(bytes))
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(id.into(), record.serialize()?);
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for SessionsPart {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        match self.0.get(&address.to_string()) {
            None => Ok(None),
            Some(bytes) => Ok(Some(SessionRecord::deserialize(bytes)?)),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.insert(address.to_string(), record.serialize()?);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SenderKeysPart {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0
            .insert((sender.to_string(), distribution_id), record.serialize()?);
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        match self.0.get(&(sender.to_string(), distribution_id)) {
            None => Ok(None),
            Some(bytes) => Ok(Some(SenderKeyRecord::deserialize(bytes)?)),
        }
    }
}

// ---------------------------------------------------------------------------
// Error + helper plumbing.
// ---------------------------------------------------------------------------

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn addr(service_id: &str, device_id: u32) -> PyResult<ProtocolAddress> {
    let device: DeviceId = device_id
        .try_into()
        .map_err(|_| PyValueError::new_err("invalid device id"))?;
    Ok(ProtocolAddress::new(service_id.to_string(), device))
}

fn local_address() -> ProtocolAddress {
    // libsignal uses this only in log lines.
    ProtocolAddress::new(
        "sigsig".into(),
        DeviceId::try_from(1u32).expect("1 is valid"),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The one PyO3 class sigsig talks to.
// ---------------------------------------------------------------------------

#[pyclass]
pub struct SignalStore {
    inner: Arc<Mutex<Store>>,
}

#[pymethods]
impl SignalStore {
    #[staticmethod]
    fn from_identity(identity_key_pair_bytes: &[u8], registration_id: u32) -> PyResult<Self> {
        let identity = IdentityKeyPair::try_from(identity_key_pair_bytes).map_err(err)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Store::new(identity, registration_id))),
        })
    }

    #[staticmethod]
    fn from_raw_identity(public: &[u8], private: &[u8], registration_id: u32) -> PyResult<Self> {
        let identity_key = IdentityKey::decode(public).map_err(err)?;
        let private_key = PrivateKey::deserialize(private).map_err(err)?;
        let identity = IdentityKeyPair::new(identity_key, private_key);
        Ok(Self {
            inner: Arc::new(Mutex::new(Store::new(identity, registration_id))),
        })
    }

    #[staticmethod]
    fn deserialize(py: Python<'_>, blob: &[u8]) -> PyResult<Self> {
        let store = py.allow_threads(|| Store::from_blob(blob)).map_err(err)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    fn serialize<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        let bytes = store.to_blob().map_err(err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn registration_id(&self) -> PyResult<u32> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| err(e.to_string()))?
            .identity
            .registration_id)
    }

    fn identity_key_pair_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &store.identity.identity.serialize()))
    }

    fn identity_public<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        Ok(PyBytes::new_bound(
            py,
            &store.identity.identity.public_key().serialize(),
        ))
    }

    // --- prekey generation ------------------------------------------------

    fn generate_pre_key<'py>(
        &self,
        py: Python<'py>,
        id: u32,
    ) -> PyResult<(u32, Bound<'py, PyBytes>)> {
        let mut store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        let mut rng = OsRng.unwrap_err();
        let keypair = KeyPair::generate(&mut rng);
        let record = PreKeyRecord::new(id.into(), &keypair);
        store
            .pre_keys
            .0
            .insert(id, record.serialize().map_err(err)?);
        Ok((id, PyBytes::new_bound(py, &keypair.public_key.serialize())))
    }

    fn generate_pre_keys<'py>(
        &self,
        py: Python<'py>,
        start_id: u32,
        count: u32,
    ) -> PyResult<Vec<(u32, Bound<'py, PyBytes>)>> {
        (0..count)
            .map(|i| self.generate_pre_key(py, start_id + i))
            .collect()
    }

    fn generate_signed_pre_key<'py>(
        &self,
        py: Python<'py>,
        id: u32,
    ) -> PyResult<(u32, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let mut store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        let mut rng = OsRng.unwrap_err();
        let keypair = KeyPair::generate(&mut rng);
        let signature = store
            .identity
            .identity
            .private_key()
            .calculate_signature(&keypair.public_key.serialize(), &mut rng)
            .map_err(err)?
            .into_vec();
        let timestamp = Timestamp::from_epoch_millis(now_ms());
        let record = SignedPreKeyRecord::new(id.into(), timestamp, &keypair, &signature);
        store
            .signed_pre_keys
            .0
            .insert(id, record.serialize().map_err(err)?);
        Ok((
            id,
            PyBytes::new_bound(py, &keypair.public_key.serialize()),
            PyBytes::new_bound(py, &signature),
        ))
    }

    fn generate_kyber_pre_key<'py>(
        &self,
        py: Python<'py>,
        id: u32,
    ) -> PyResult<(u32, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let mut store = self.inner.lock().map_err(|e| err(e.to_string()))?;
        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id.into(),
            store.identity.identity.private_key(),
        )
        .map_err(err)?;
        let pub_bytes = record.public_key().map_err(err)?.serialize().to_vec();
        let sig = record.signature().map_err(err)?;
        store
            .kyber_pre_keys
            .0
            .insert(id, record.serialize().map_err(err)?);
        Ok((
            id,
            PyBytes::new_bound(py, &pub_bytes),
            PyBytes::new_bound(py, &sig),
        ))
    }

    // --- session operations -----------------------------------------------

    /// Returns true iff a session record is cached for ``(service_id, device_id)``.
    fn has_session(&self, service_id: &str, device_id: u32) -> PyResult<bool> {
        let address = addr(service_id, device_id)?;
        let guard = self.inner.lock().map_err(|e| err(e.to_string()))?;
        Ok(guard.sessions.0.contains_key(&address.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn process_pre_key_bundle(
        &self,
        py: Python<'_>,
        service_id: &str,
        device_id: u32,
        registration_id: u32,
        identity_key: &[u8],
        signed_pre_key_id: u32,
        signed_pre_key_public: &[u8],
        signed_pre_key_signature: &[u8],
        kyber_pre_key_id: u32,
        kyber_pre_key_public: &[u8],
        kyber_pre_key_signature: &[u8],
        one_time_pre_key: Option<(u32, Vec<u8>)>,
    ) -> PyResult<()> {
        let address = addr(service_id, device_id)?;
        let remote_identity = IdentityKey::decode(identity_key).map_err(err)?;
        let signed_pub = PublicKey::deserialize(signed_pre_key_public).map_err(err)?;
        let kyber_pub = kem::PublicKey::deserialize(kyber_pre_key_public).map_err(err)?;

        let content = PreKeyBundleContent {
            registration_id: Some(registration_id),
            device_id: Some(
                device_id
                    .try_into()
                    .map_err(|_| PyValueError::new_err("invalid device id"))?,
            ),
            pre_key_id: one_time_pre_key.as_ref().map(|(id, _)| (*id).into()),
            pre_key_public: match &one_time_pre_key {
                Some((_, pk)) => Some(PublicKey::deserialize(pk).map_err(err)?),
                None => None,
            },
            signed_pre_key_id: Some(signed_pre_key_id.into()),
            signed_pre_key_public: Some(signed_pub),
            signed_pre_key_signature: Some(signed_pre_key_signature.to_vec()),
            identity_key: Some(remote_identity),
            kyber_pre_key_id: Some(kyber_pre_key_id.into()),
            kyber_pre_key_public: Some(kyber_pub),
            kyber_pre_key_signature: Some(kyber_pre_key_signature.to_vec()),
        };
        let bundle = PreKeyBundle::try_from(content).map_err(err)?;

        let inner = Arc::clone(&self.inner);
        py.allow_threads(|| -> Result<(), SignalProtocolError> {
            let mut guard = inner.lock().map_err(|_| {
                SignalProtocolError::InvalidState("process_pre_key_bundle", "poisoned".into())
            })?;
            let store: &mut Store = &mut *guard;
            let mut rng = OsRng.unwrap_err();
            block_on(process_prekey_bundle(
                &address,
                &mut store.sessions,
                &mut store.identity,
                &bundle,
                SystemTime::now(),
                &mut rng,
            ))
        })
        .map_err(err)?;
        Ok(())
    }

    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        service_id: &str,
        device_id: u32,
        plaintext: &[u8],
    ) -> PyResult<(u8, Bound<'py, PyBytes>)> {
        let address = addr(service_id, device_id)?;
        let local = local_address();
        let inner = Arc::clone(&self.inner);
        let (type_byte, ciphertext) = py
            .allow_threads(|| -> Result<(u8, Vec<u8>), SignalProtocolError> {
                let mut guard = inner
                    .lock()
                    .map_err(|_| SignalProtocolError::InvalidState("encrypt", "poisoned".into()))?;
                let store: &mut Store = &mut *guard;
                let mut rng = OsRng.unwrap_err();
                let msg = block_on(message_encrypt(
                    plaintext,
                    &address,
                    &local,
                    &mut store.sessions,
                    &mut store.identity,
                    SystemTime::now(),
                    &mut rng,
                ))?;
                Ok(match msg {
                    CiphertextMessage::SignalMessage(m) => (
                        CiphertextMessageType::Whisper as u8,
                        m.serialized().to_vec(),
                    ),
                    CiphertextMessage::PreKeySignalMessage(m) => {
                        (CiphertextMessageType::PreKey as u8, m.serialized().to_vec())
                    }
                    other => {
                        return Err(SignalProtocolError::InvalidState(
                            "encrypt",
                            format!("unexpected message kind {:?}", other.message_type()),
                        ));
                    }
                })
            })
            .map_err(err)?;
        Ok((type_byte, PyBytes::new_bound(py, &ciphertext)))
    }

    fn decrypt_signal<'py>(
        &self,
        py: Python<'py>,
        service_id: &str,
        device_id: u32,
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let address = addr(service_id, device_id)?;
        let msg = SignalMessage::try_from(ciphertext).map_err(err)?;
        let inner = Arc::clone(&self.inner);
        let pt = py
            .allow_threads(|| -> Result<Vec<u8>, SignalProtocolError> {
                let mut guard = inner.lock().map_err(|_| {
                    SignalProtocolError::InvalidState("decrypt_signal", "poisoned".into())
                })?;
                let store: &mut Store = &mut *guard;
                let mut rng = OsRng.unwrap_err();
                block_on(message_decrypt_signal(
                    &msg,
                    &address,
                    &mut store.sessions,
                    &mut store.identity,
                    &mut rng,
                ))
            })
            .map_err(err)?;
        Ok(PyBytes::new_bound(py, &pt))
    }

    /// Sealed-sender decrypt. ``trust_roots`` is a list of 33-byte Curve25519
    /// public keys; a SenderCertificate signed by any of them is accepted
    /// (matching signal-cli's CertificateValidator behaviour).
    ///
    /// Returns ``(sender_uuid, sender_e164 or None, sender_device, plaintext)``.
    #[allow(clippy::too_many_arguments)]
    fn sealed_sender_decrypt<'py>(
        &self,
        py: Python<'py>,
        ciphertext: &[u8],
        trust_roots: Vec<Vec<u8>>,
        server_timestamp_ms: u64,
        local_uuid: String,
        local_device_id: u32,
    ) -> PyResult<(String, Option<String>, u32, Bound<'py, PyBytes>)> {
        if trust_roots.is_empty() {
            return Err(PyValueError::new_err("need at least one trust root"));
        }
        let trust_roots: Vec<PublicKey> = trust_roots
            .iter()
            .map(|raw| PublicKey::deserialize(raw))
            .collect::<Result<_, _>>()
            .map_err(err)?;
        let timestamp = Timestamp::from_epoch_millis(server_timestamp_ms);
        let local_device: DeviceId = local_device_id
            .try_into()
            .map_err(|_| PyValueError::new_err("invalid local device id"))?;
        let ciphertext = ciphertext.to_vec();
        let inner = Arc::clone(&self.inner);
        let result = py
            .allow_threads(
                || -> Result<(String, Option<String>, u32, Vec<u8>), SignalProtocolError> {
                    let mut guard = inner.lock().map_err(|_| {
                        SignalProtocolError::InvalidState(
                            "sealed_sender_decrypt",
                            "poisoned".into(),
                        )
                    })?;
                    let store: &mut Store = &mut *guard;
                    let mut last_err: Option<SignalProtocolError> = None;
                    for root in &trust_roots {
                        let res = block_on(sealed_sender_decrypt(
                            &ciphertext,
                            root,
                            timestamp,
                            None,
                            local_uuid.clone(),
                            local_device,
                            &mut store.identity,
                            &mut store.sessions,
                            &mut store.pre_keys,
                            &store.signed_pre_keys,
                            &mut store.kyber_pre_keys,
                        ));
                        match res {
                            Ok(d) => {
                                return Ok((
                                    d.sender_uuid,
                                    d.sender_e164,
                                    u32::from(d.device_id),
                                    d.message,
                                ));
                            }
                            Err(e) => last_err = Some(e),
                        }
                    }
                    Err(last_err.expect("tried at least one trust root"))
                },
            )
            .map_err(err)?;
        let (uuid, e164, device, plaintext) = result;
        Ok((uuid, e164, device, PyBytes::new_bound(py, &plaintext)))
    }

    fn decrypt_prekey<'py>(
        &self,
        py: Python<'py>,
        service_id: &str,
        device_id: u32,
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let address = addr(service_id, device_id)?;
        let local = local_address();
        let msg = PreKeySignalMessage::try_from(ciphertext).map_err(err)?;
        let inner = Arc::clone(&self.inner);
        let pt = py
            .allow_threads(|| -> Result<Vec<u8>, SignalProtocolError> {
                let mut guard = inner.lock().map_err(|_| {
                    SignalProtocolError::InvalidState("decrypt_prekey", "poisoned".into())
                })?;
                let store: &mut Store = &mut *guard;
                let mut rng = OsRng.unwrap_err();
                block_on(message_decrypt_prekey(
                    &msg,
                    &address,
                    &local,
                    &mut store.sessions,
                    &mut store.identity,
                    &mut store.pre_keys,
                    &store.signed_pre_keys,
                    &mut store.kyber_pre_keys,
                    &mut rng,
                ))
            })
            .map_err(err)?;
        Ok(PyBytes::new_bound(py, &pt))
    }
}

// ---------------------------------------------------------------------------
// Module-level helpers.
// ---------------------------------------------------------------------------

#[pyfunction]
fn generate_registration_id() -> u32 {
    use rand::RngCore;
    let mut rng = OsRng.unwrap_err();
    (rng.next_u32() % 16383) + 1
}

#[pyfunction]
fn generate_identity_key_pair(py: Python<'_>) -> PyResult<Bound<'_, PyBytes>> {
    let mut rng = OsRng.unwrap_err();
    let kp = IdentityKeyPair::generate(&mut rng);
    Ok(PyBytes::new_bound(py, &kp.serialize()))
}

#[pyfunction]
fn identity_key_pair_from_raw<'py>(
    py: Python<'py>,
    public: &[u8],
    private: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let identity = IdentityKey::decode(public).map_err(err)?;
    let private_key = PrivateKey::deserialize(private).map_err(err)?;
    let kp = IdentityKeyPair::new(identity, private_key);
    Ok(PyBytes::new_bound(py, &kp.serialize()))
}

// ---------------------------------------------------------------------------
// zkgroup — thin wrappers used by Groups V2 state fetch.
// ---------------------------------------------------------------------------

fn uuid_bytes(raw: &[u8]) -> PyResult<[u8; 16]> {
    raw.try_into()
        .map_err(|_| PyValueError::new_err("uuid must be 16 bytes"))
}

fn array_32(raw: &[u8]) -> PyResult<[u8; 32]> {
    raw.try_into()
        .map_err(|_| PyValueError::new_err("expected 32 bytes"))
}

/// Derive the 32×N-byte ``GroupSecretParams`` blob from a 32-byte master key.
#[pyfunction]
fn zkgroup_group_secret_params<'py>(
    py: Python<'py>,
    master_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mk = GroupMasterKey::new(array_32(master_key)?);
    let gsp = GroupSecretParams::derive_from_master_key(mk);
    Ok(PyBytes::new_bound(py, &zkgroup::serialize(&gsp)))
}

/// Serialized ``GroupPublicParams`` — used as the Basic-auth username (hex)
/// in requests to ``/v2/groups/…``.
#[pyfunction]
fn zkgroup_group_public_params<'py>(
    py: Python<'py>,
    secret_params: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let gsp: GroupSecretParams = zkgroup::deserialize(secret_params).map_err(err)?;
    Ok(PyBytes::new_bound(
        py,
        &zkgroup::serialize(&gsp.get_public_params()),
    ))
}

/// The 16-byte group identifier.
#[pyfunction]
fn zkgroup_group_id<'py>(py: Python<'py>, secret_params: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let gsp: GroupSecretParams = zkgroup::deserialize(secret_params).map_err(err)?;
    Ok(PyBytes::new_bound(
        py,
        &gsp.get_public_params().get_group_identifier(),
    ))
}

/// Turn a server-issued ``AuthCredentialWithPniResponse`` into a usable
/// ``AuthCredentialWithPni`` by verifying it against ``server_public_params``
/// and binding it to our ACI/PNI + redemption day.
#[pyfunction]
fn zkgroup_receive_auth_credential<'py>(
    py: Python<'py>,
    server_public_params: &[u8],
    credential_response: &[u8],
    aci_uuid_bytes: &[u8],
    pni_uuid_bytes: &[u8],
    redemption_time_seconds: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    let spp: ServerPublicParams = zkgroup::deserialize(server_public_params).map_err(err)?;
    let response = AuthCredentialWithPniResponse::new(credential_response).map_err(err)?;
    let aci = Aci::from_uuid_bytes(uuid_bytes(aci_uuid_bytes)?);
    let pni = Pni::from_uuid_bytes(uuid_bytes(pni_uuid_bytes)?);
    let redemption = ZkTimestamp::from_epoch_seconds(redemption_time_seconds);
    let credential = response.receive(&spp, aci, pni, redemption).map_err(err)?;
    Ok(PyBytes::new_bound(py, &zkgroup::serialize(&credential)))
}

/// Build a zero-knowledge ``AuthCredentialPresentation`` to authenticate the
/// holder to ``/v2/groups/…`` as "some member of this group".
#[pyfunction]
fn zkgroup_auth_presentation<'py>(
    py: Python<'py>,
    server_public_params: &[u8],
    group_secret_params: &[u8],
    auth_credential: &[u8],
    randomness: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let spp: ServerPublicParams = zkgroup::deserialize(server_public_params).map_err(err)?;
    let gsp: GroupSecretParams = zkgroup::deserialize(group_secret_params).map_err(err)?;
    let credential = AuthCredentialWithPni::new(auth_credential).map_err(err)?;
    let rng: [u8; 32] = array_32(randomness)?;
    let presentation = credential.present(&spp, &gsp, rng);
    Ok(PyBytes::new_bound(py, &zkgroup::serialize(&presentation)))
}

/// Decrypt a ``UuidCiphertext`` (wire form from a decrypted Group) into an
/// ACI UUID string.
#[pyfunction]
fn zkgroup_decrypt_uuid_ciphertext(
    group_secret_params: &[u8],
    ciphertext: &[u8],
) -> PyResult<String> {
    let gsp: GroupSecretParams = zkgroup::deserialize(group_secret_params).map_err(err)?;
    let ct: UuidCiphertext = zkgroup::deserialize(ciphertext).map_err(err)?;
    let sid = gsp.decrypt_service_id(ct).map_err(err)?;
    Ok(sid.service_id_string())
}

#[pymodule]
fn _libsignal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SignalStore>()?;
    m.add_function(wrap_pyfunction!(generate_registration_id, m)?)?;
    m.add_function(wrap_pyfunction!(generate_identity_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(identity_key_pair_from_raw, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_group_secret_params, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_group_public_params, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_group_id, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_receive_auth_credential, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_auth_presentation, m)?)?;
    m.add_function(wrap_pyfunction!(zkgroup_decrypt_uuid_ciphertext, m)?)?;
    Ok(())
}

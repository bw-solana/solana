//! Agave's fixed Falcon-512 padded profile, with chain and role binding.
//!
//! This deliberately uses original Falcon rather than an evolving FN-DSA draft.
use {
    openssl::hash::{Hasher, MessageDigest},
    pqcrypto_falcon::{falconpadded512, ffi},
    std::{
        cell::RefCell,
        collections::{HashSet, VecDeque},
        error::Error,
        fmt,
        sync::{
            Mutex, OnceLock,
            atomic::{AtomicU64, Ordering},
        },
    },
    zeroize::Zeroizing,
};

pub const FALCON_PUBLIC_KEY_BYTES: usize = 897;
pub const FALCON_SIGNATURE_BYTES: usize = 666;
const FALCON_SECRET_KEY_BYTES: usize = 1281;
pub const MAX_SIGNED_MESSAGE_BYTES: usize = 1_048_576;

const VERIFICATION_CACHE_SHARDS: usize = 64;
const VERIFICATION_CACHE_ENTRIES_PER_SHARD: usize = 1024;
pub const MAX_CACHED_FALCON_VERIFICATIONS: usize =
    VERIFICATION_CACHE_SHARDS * VERIFICATION_CACHE_ENTRIES_PER_SHARD;

#[derive(Default)]
struct VerifiedSignatures {
    keys: HashSet<[u8; 48]>,
    order: VecDeque<[u8; 48]>,
}

impl VerifiedSignatures {
    fn insert(&mut self, key: [u8; 48]) {
        if self.keys.contains(&key) {
            return;
        }
        if self.order.len() == VERIFICATION_CACHE_ENTRIES_PER_SHARD {
            let evicted = self.order.pop_front().expect("full verification cache");
            self.keys.remove(&evicted);
        }
        self.keys.insert(key);
        self.order.push_back(key);
    }
}

static VERIFICATION_CACHE: OnceLock<[Mutex<VerifiedSignatures>; VERIFICATION_CACHE_SHARDS]> =
    OnceLock::new();
static VERIFICATION_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

fn verification_cache_shard(key: &[u8; 48]) -> &'static Mutex<VerifiedSignatures> {
    &VERIFICATION_CACHE.get_or_init(|| std::array::from_fn(|_| Mutex::default()))
        [usize::from(key[0]) & (VERIFICATION_CACHE_SHARDS - 1)]
}

fn cached_verification(key: &[u8; 48]) -> bool {
    verification_cache_shard(key)
        .lock()
        .ok()
        .is_some_and(|cache| cache.keys.contains(key))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FalconVerificationCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
    pub maximum_entries: usize,
}

/// This bounded transaction/batch-domain cache remembers signature math only. Callers must still
/// check current policy, account locks, nonce, replay, balances, resource budgets, and every shred's
/// structure, Merkle proof and authorized role/context.
pub fn falcon_verification_cache_stats() -> FalconVerificationCacheStats {
    FalconVerificationCacheStats {
        hits: VERIFICATION_CACHE_HITS.load(Ordering::Relaxed),
        misses: VERIFICATION_CACHE_MISSES.load(Ordering::Relaxed),
        entries: VERIFICATION_CACHE.get().map_or(0, |cache| {
            cache
                .iter()
                .filter_map(|shard| shard.lock().ok())
                .map(|shard| shard.keys.len())
                .sum()
        }),
        maximum_entries: MAX_CACHED_FALCON_VERIFICATIONS,
    }
}

fn verification_cache_key(
    public: &[u8; FALCON_PUBLIC_KEY_BYTES],
    chain: &[u8; 32],
    domain: Domain,
    framed: &[u8],
    signature: &[u8; FALCON_SIGNATURE_BYTES],
) -> [u8; 48] {
    hash_commitment(
        b"agave/pq/falcon/verified-math/v1",
        &[
            public,
            chain,
            &(domain as u16).to_le_bytes(),
            framed,
            signature,
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FalconBackend {
    Clean,
    #[cfg(target_arch = "x86_64")]
    Avx2,
}

impl FalconBackend {
    fn select() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            // These are all compiler flags enabled by pqcrypto-falcon 0.4.1's
            // build_avx2, including instructions the compiler may introduce.
            // The standard detection also checks operating-system AVX support.
            if std::is_x86_feature_detected!("avx2")
                && std::is_x86_feature_detected!("bmi1")
                && std::is_x86_feature_detected!("bmi2")
                && std::is_x86_feature_detected!("aes")
                && std::is_x86_feature_detected!("popcnt")
                && std::is_x86_feature_detected!("pclmulqdq")
            {
                return Self::Avx2;
            }
        }
        Self::Clean
    }

    fn current() -> Self {
        static SELECTED: OnceLock<FalconBackend> = OnceLock::new();
        *SELECTED.get_or_init(Self::select)
    }

    fn keypair(
        self,
        public: &mut [u8; FALCON_PUBLIC_KEY_BYTES],
        secret: &mut [u8; FALCON_SECRET_KEY_BYTES],
    ) -> i32 {
        // SAFETY: output buffers have the exact fixed profile capacities. AVX2
        // is selected only after checking every vendor-required CPU feature.
        // The vendor API uses OS randomness and retains no pointers.
        unsafe {
            match self {
                Self::Clean => ffi::PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(
                    public.as_mut_ptr(),
                    secret.as_mut_ptr(),
                ),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => ffi::PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_keypair(
                    public.as_mut_ptr(),
                    secret.as_mut_ptr(),
                ),
            }
        }
    }

    fn sign(
        self,
        signature: &mut [u8; FALCON_SIGNATURE_BYTES],
        length: &mut usize,
        framed: &[u8],
        secret: &[u8; FALCON_SECRET_KEY_BYTES],
    ) -> i32 {
        // SAFETY: buffers have the fixed profile lengths, the secret is a valid
        // generated credential, and all input slices remain alive for this call.
        // Backend selection checks CPU features before invoking vendor AVX2.
        unsafe {
            match self {
                Self::Clean => ffi::PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
                    signature.as_mut_ptr(),
                    length,
                    framed.as_ptr(),
                    framed.len(),
                    secret.as_ptr(),
                ),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => ffi::PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_signature(
                    signature.as_mut_ptr(),
                    length,
                    framed.as_ptr(),
                    framed.len(),
                    secret.as_ptr(),
                ),
            }
        }
    }

    fn verify(
        self,
        signature: &[u8; FALCON_SIGNATURE_BYTES],
        framed: &[u8],
        public: &[u8; FALCON_PUBLIC_KEY_BYTES],
    ) -> i32 {
        // SAFETY: canonical public key and signature buffers have the fixed
        // profile lengths, and the vendor functions read without retaining them.
        // Backend selection checks CPU features before invoking vendor AVX2.
        unsafe {
            match self {
                Self::Clean => ffi::PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                    signature.as_ptr(),
                    FALCON_SIGNATURE_BYTES,
                    framed.as_ptr(),
                    framed.len(),
                    public.as_ptr(),
                ),
                #[cfg(target_arch = "x86_64")]
                Self::Avx2 => ffi::PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_verify(
                    signature.as_ptr(),
                    FALCON_SIGNATURE_BYTES,
                    framed.as_ptr(),
                    framed.len(),
                    public.as_ptr(),
                ),
            }
        }
    }
}

/// The selected vendor implementation; the wire profile is identical.
pub fn falcon_backend_name() -> &'static str {
    match FalconBackend::current() {
        FalconBackend::Clean => "pqcrypto-falcon-0.4.1/CLEAN",
        #[cfg(target_arch = "x86_64")]
        FalconBackend::Avx2 => "pqcrypto-falcon-0.4.1/AVX2",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Domain {
    Transaction = 1,
    NetworkHandshake = 2,
    Gossip = 3,
    Repair = 4,
    ValidatorBinding = 5,
    LeaderBatch = 6,
    Checkpoint = 7,
    ConsensusRoot = 8,
    ConsensusMaterial = 9,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSignatureEncoding,
    InvalidSignature,
    MessageTooLarge,
    BackendFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for CryptoError {}

#[derive(Clone, Eq, PartialEq)]
pub struct FalconPublicKey([u8; FALCON_PUBLIC_KEY_BYTES]);

impl fmt::Debug for FalconPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FalconPublicKey")
            .field(&hash_commitment(b"falcon-key", &[&self.0]))
            .finish()
    }
}

impl FalconPublicKey {
    /// Rejects wrong profiles and noncanonical 14-bit field elements before FFI.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FALCON_PUBLIC_KEY_BYTES || bytes[0] != 0x09 {
            return Err(CryptoError::InvalidPublicKey);
        }
        let mut bits = Bits::new(&bytes[1..]);
        for _ in 0..512 {
            if bits.read(14).ok_or(CryptoError::InvalidPublicKey)? >= 12289 {
                return Err(CryptoError::InvalidPublicKey);
            }
        }
        let mut encoded = [0u8; FALCON_PUBLIC_KEY_BYTES];
        encoded.copy_from_slice(bytes);
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn verify(
        &self,
        chain: &[u8; 32],
        domain: Domain,
        message: &[u8],
        signature: &FalconSignature,
    ) -> Result<(), CryptoError> {
        let framed = signature_message(chain, domain, message)?;
        if !matches!(domain, Domain::Transaction | Domain::LeaderBatch) {
            return self.verify_framed(&framed, signature, FalconBackend::current());
        }
        let cache_key = verification_cache_key(&self.0, chain, domain, &framed, &signature.0);
        if cached_verification(&cache_key) {
            VERIFICATION_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        VERIFICATION_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
        self.verify_framed(&framed, signature, FalconBackend::current())?;
        // Only successful vendor verification is cached. If a cache lock is
        // poisoned, bypass caching; it never changes a verification decision.
        if let Ok(mut cache) = verification_cache_shard(&cache_key).lock() {
            cache.insert(cache_key);
        }
        Ok(())
    }

    #[cfg(test)]
    fn verify_with_backend(
        &self,
        chain: &[u8; 32],
        domain: Domain,
        message: &[u8],
        signature: &FalconSignature,
        backend: FalconBackend,
    ) -> Result<(), CryptoError> {
        let framed = signature_message(chain, domain, message)?;
        self.verify_framed(&framed, signature, backend)
    }

    fn verify_framed(
        &self,
        framed: &[u8],
        signature: &FalconSignature,
        backend: FalconBackend,
    ) -> Result<(), CryptoError> {
        let result = backend.verify(&signature.0, framed, &self.0);
        if result == 0 {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FalconSignature([u8; FALCON_SIGNATURE_BYTES]);

thread_local! {
    // One successful canonical encoding only. This does not remember message,
    // key, role or signature-math decisions, and it never stores secret bytes.
    static LAST_CANONICAL_SIGNATURE: RefCell<Option<FalconSignature>> = const { RefCell::new(None) };
    #[cfg(test)]
    static CANONICAL_SIGNATURE_SCALAR_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl fmt::Debug for FalconSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FalconSignature")
            .field(&hash_commitment(b"falcon-signature", &[&self.0]))
            .finish()
    }
}

impl FalconSignature {
    /// Validates compressed coefficients and zero padding, not just length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FALCON_SIGNATURE_BYTES || bytes[0] != 0x39 {
            return Err(CryptoError::InvalidSignatureEncoding);
        }
        if let Ok(Some(signature)) = LAST_CANONICAL_SIGNATURE.try_with(|last| {
            last.try_borrow().ok().and_then(|last| {
                last.as_ref()
                    .filter(|signature| signature.as_bytes() == bytes)
                    .cloned()
            })
        }) {
            return Ok(signature);
        }
        // Cache access is best effort, including reentry and TLS teardown.
        // The complete original scalar validator remains the fallback.
        #[cfg(test)]
        CANONICAL_SIGNATURE_SCALAR_CALLS.with(|calls| calls.set(calls.get() + 1));
        let signature = Self::from_bytes_uncached(bytes)?;
        let _ = LAST_CANONICAL_SIGNATURE.try_with(|last| {
            if let Ok(mut last) = last.try_borrow_mut() {
                *last = Some(signature.clone());
            }
        });
        Ok(signature)
    }

    fn from_bytes_uncached(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FALCON_SIGNATURE_BYTES || bytes[0] != 0x39 {
            return Err(CryptoError::InvalidSignatureEncoding);
        }
        let mut bits = Bits::new(&bytes[41..]);
        for _ in 0..512 {
            let negative = bits.read(1).ok_or(CryptoError::InvalidSignatureEncoding)?;
            let mut magnitude = bits.read(7).ok_or(CryptoError::InvalidSignatureEncoding)?;
            while bits.read(1).ok_or(CryptoError::InvalidSignatureEncoding)? == 0 {
                magnitude += 128;
                if magnitude > 2047 {
                    return Err(CryptoError::InvalidSignatureEncoding);
                }
            }
            if negative != 0 && magnitude == 0 {
                return Err(CryptoError::InvalidSignatureEncoding);
            }
        }
        // Residual bits in the last encoded byte and every padding byte are zero.
        while bits.remaining() != 0 {
            if bits.read(1) != Some(0) {
                return Err(CryptoError::InvalidSignatureEncoding);
            }
        }
        let mut encoded = [0u8; FALCON_SIGNATURE_BYTES];
        encoded.copy_from_slice(bytes);
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Private material is neither clonable nor printable and is cleared on drop.
pub struct FalconKeypair {
    public: FalconPublicKey,
    secret: Zeroizing<[u8; FALCON_SECRET_KEY_BYTES]>,
}

impl FalconKeypair {
    /// Persist a test-node credential without exposing secret bytes through a
    /// public serialization API. Existing paths are never overwritten.
    pub fn save_private(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let path = path.as_ref();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(b"PQFKEY01")?;
        file.write_all(self.public.as_bytes())?;
        file.write_all(self.secret.as_ref())?;
        file.sync_all()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Load a bounded private credential and verify that its public and secret
    /// halves match. The temporary input buffer is erased on drop.
    pub fn load_private(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        use std::{io::Read, os::unix::fs::PermissionsExt};
        let mut file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        let invalid =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Falcon credential");
        const BYTES: usize = 8 + FALCON_PUBLIC_KEY_BYTES + FALCON_SECRET_KEY_BYTES;
        if !metadata.is_file()
            || metadata.len() != BYTES as u64
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(vec![0u8; BYTES]);
        file.read_exact(&mut bytes)?;
        if &bytes[..8] != b"PQFKEY01" {
            return Err(invalid());
        }
        let public = FalconPublicKey::from_bytes(&bytes[8..8 + FALCON_PUBLIC_KEY_BYTES])
            .map_err(|_| invalid())?;
        let mut secret = Zeroizing::new([0u8; FALCON_SECRET_KEY_BYTES]);
        secret.copy_from_slice(&bytes[8 + FALCON_PUBLIC_KEY_BYTES..]);
        let key = Self { public, secret };
        let signature = key
            .sign(
                &[0; 32],
                Domain::ValidatorBinding,
                b"pq-private-credential-consistency/v1",
            )
            .map_err(|_| invalid())?;
        key.public
            .verify(
                &[0; 32],
                Domain::ValidatorBinding,
                b"pq-private-credential-consistency/v1",
                &signature,
            )
            .map_err(|_| invalid())?;
        Ok(key)
    }

    pub fn generate() -> Self {
        Self::generate_with_backend(FalconBackend::current())
    }

    fn generate_with_backend(backend: FalconBackend) -> Self {
        assert_eq!(falconpadded512::public_key_bytes(), FALCON_PUBLIC_KEY_BYTES);
        assert_eq!(falconpadded512::signature_bytes(), FALCON_SIGNATURE_BYTES);
        assert_eq!(falconpadded512::secret_key_bytes(), FALCON_SECRET_KEY_BYTES);
        let mut public = [0u8; FALCON_PUBLIC_KEY_BYTES];
        let mut secret = Zeroizing::new([0u8; FALCON_SECRET_KEY_BYTES]);
        let result = backend.keypair(&mut public, &mut secret);
        assert_eq!(result, 0, "Falcon key generation failed");
        Self {
            public: FalconPublicKey::from_bytes(&public)
                .expect("backend generated an invalid Falcon public key"),
            secret,
        }
    }

    pub fn public_key(&self) -> FalconPublicKey {
        self.public.clone()
    }

    pub fn sign(
        &self,
        chain: &[u8; 32],
        domain: Domain,
        message: &[u8],
    ) -> Result<FalconSignature, CryptoError> {
        self.sign_with_backend(chain, domain, message, FalconBackend::current())
    }

    fn sign_with_backend(
        &self,
        chain: &[u8; 32],
        domain: Domain,
        message: &[u8],
        backend: FalconBackend,
    ) -> Result<FalconSignature, CryptoError> {
        let framed = signature_message(chain, domain, message)?;
        let mut signature = [0u8; FALCON_SIGNATURE_BYTES];
        let mut length = 0usize;
        let result = backend.sign(&mut signature, &mut length, &framed, &self.secret);
        if result != 0 || length != FALCON_SIGNATURE_BYTES {
            return Err(CryptoError::BackendFailure);
        }
        FalconSignature::from_bytes(&signature)
    }
}

/// Incremental raw-byte SHA-384 with clonable, independent continuation state.
///
/// This adds no protocol framing. Callers must retain their existing domain and
/// byte encoding exactly. Backend failures are fatal, as in `hash_commitment`;
/// an absent, truncated or substituted digest is never returned.
#[derive(Clone)]
pub struct Sha384Stream(Hasher);

impl Default for Sha384Stream {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384Stream {
    pub fn new() -> Self {
        Self(Hasher::new(MessageDigest::sha384()).expect("PQ SHA384 stream initialization"))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes).expect("PQ SHA384 stream update");
    }

    pub fn finalize(mut self) -> [u8; 48] {
        self.0
            .finish()
            .expect("PQ SHA384 stream finalization")
            .as_ref()
            .try_into()
            .expect("PQ SHA384 stream full output length")
    }
}

/// SHA-384 commitments provide 384-bit outputs, with unambiguous field framing.
///
/// This native implementation preserves the protocol's complete SHA-384 output and framing.
/// An unavailable or failed cryptographic backend is an internal fatal error: callers must never
/// continue with an absent, truncated or substituted commitment.
pub fn hash_commitment(domain: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher =
        Hasher::new(MessageDigest::sha384()).expect("PQ SHA384 backend initialization");
    let mut update = |bytes: &[u8]| {
        hasher.update(bytes).expect("PQ SHA384 backend update");
    };
    update(b"agave-pq-commitment-v1");
    update(&(domain.len() as u64).to_le_bytes());
    update(domain);
    update(&(parts.len() as u64).to_le_bytes());
    for part in parts {
        update(&(part.len() as u64).to_le_bytes());
        update(part);
    }
    hasher
        .finish()
        .expect("PQ SHA384 backend finalization")
        .as_ref()
        .try_into()
        .expect("PQ SHA384 full output length")
}

fn signature_message(
    chain: &[u8; 32],
    domain: Domain,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(CryptoError::MessageTooLarge);
    }
    let mut framed = Vec::with_capacity(message.len() + 64);
    framed.extend_from_slice(b"agave-pq-signature-v1");
    framed.extend_from_slice(chain);
    framed.extend_from_slice(&(domain as u16).to_le_bytes());
    framed.extend_from_slice(&(message.len() as u64).to_le_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

struct Bits<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Bits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.offset
    }
    fn read(&mut self, count: usize) -> Option<u16> {
        if count > 16 || self.remaining() < count {
            return None;
        }
        if count == 0 {
            return Some(0);
        }
        if count == 1 {
            let value = (self.bytes[self.offset / 8] >> (7 - self.offset % 8)) & 1;
            self.offset += 1;
            return Some(u16::from(value));
        }
        // At most sixteen bits span three bytes. Padding absent window bytes
        // with zero is safe because the remaining-length check above proves
        // every requested bit exists. Canonical coefficient checks are unchanged.
        let byte = self.offset / 8;
        let window = (u32::from(self.bytes[byte]) << 16)
            | (u32::from(self.bytes.get(byte + 1).copied().unwrap_or(0)) << 8)
            | u32::from(self.bytes.get(byte + 2).copied().unwrap_or(0));
        let value = (window >> (24 - self.offset % 8 - count)) & ((1 << count) - 1);
        self.offset += count;
        Some(value as u16)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        rand::{RngCore, SeedableRng, rngs::StdRng},
        sha2::{Digest, Sha384},
    };

    fn sha2_commitment_oracle(domain: &[u8], parts: &[&[u8]]) -> [u8; 48] {
        let mut framed = b"agave-pq-commitment-v1".to_vec();
        framed.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        framed.extend_from_slice(domain);
        framed.extend_from_slice(&(parts.len() as u64).to_le_bytes());
        for part in parts {
            framed.extend_from_slice(&(part.len() as u64).to_le_bytes());
            framed.extend_from_slice(part);
        }
        Sha384::digest(&framed).into()
    }

    fn digest_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn sha384_stream_known_padding_and_large_chunking_matches_sha2() {
        for (bytes, expected) in [
            (
                &b""[..],
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                &b"abc"[..],
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
        ] {
            let mut stream = Sha384Stream::default();
            stream.update(bytes);
            let digest = stream.finalize();
            assert_eq!(digest_hex(&digest), expected);
            assert_eq!(digest, <[u8; 48]>::from(Sha384::digest(bytes)));
        }
        let mut rng = StdRng::seed_from_u64(0x5354_5245_414d_0038);
        for size in [
            0, 1, 111, 112, 113, 127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 13_476_746,
        ] {
            let mut bytes = vec![0u8; size];
            rng.fill_bytes(&mut bytes);
            let expected: [u8; 48] = Sha384::digest(&bytes).into();
            let chunk_sizes: &[usize] = if size > 4097 {
                &[4096, 65_536, 1_048_576, 13_476_746]
            } else {
                &[1, 7, 127, 128, 129, 4096]
            };
            for &chunk in chunk_sizes {
                let mut stream = Sha384Stream::new();
                stream.update(&[]);
                for part in bytes.chunks(chunk) {
                    stream.update(part);
                }
                stream.update(&[]);
                assert_eq!(stream.finalize(), expected, "size={size} chunk={chunk}");
            }
        }
    }

    #[test]
    fn sha384_stream_clone_forks_independent_suffixes_at_padding_boundaries() {
        let mut bytes = vec![0u8; 13_476_746];
        StdRng::seed_from_u64(0x434c_4f4e_4538_0034).fill_bytes(&mut bytes);
        for length in [0, 1, 111, 112, 113, 127, 128, 129, 4096, bytes.len()] {
            let prefix = &bytes[..length];
            let mut base = Sha384Stream::new();
            for part in prefix.chunks(4096) {
                base.update(part);
            }
            let mut left = base.clone();
            let mut right = base.clone();
            left.update(b"left fork");
            right.update(b"right ");
            assert_eq!(
                base.clone().finalize(),
                <[u8; 48]>::from(Sha384::digest(prefix))
            );
            right.update(b"fork");
            let oracle = |suffix: &[u8]| {
                let mut rust = Sha384::new();
                rust.update(prefix);
                rust.update(suffix);
                <[u8; 48]>::from(rust.finalize())
            };
            let left = left.finalize();
            let right = right.finalize();
            assert_eq!(left, oracle(b"left fork"));
            assert_eq!(right, oracle(b"right fork"));
            assert_ne!(left, right);
            assert_eq!(base.finalize(), <[u8; 48]>::from(Sha384::digest(prefix)));
        }
    }

    #[test]
    fn sha384_stream_continuations_move_across_worker_threads_without_aliasing() {
        let mut bytes = vec![0u8; 13_476_746];
        StdRng::seed_from_u64(0x5345_4e44_0038_0034).fill_bytes(&mut bytes);
        let mut stream = Sha384Stream::new();
        for part in bytes.chunks(65_536) {
            stream.update(part);
        }
        let worker_stream = stream.clone();
        let worker = std::thread::spawn(move || {
            let mut stream = worker_stream;
            stream.update(b"worker suffix");
            stream.finalize()
        });
        let mut coordinator = stream.clone();
        coordinator.update(b"coordinator suffix");
        let oracle = |suffix: &[u8]| {
            let mut rust = Sha384::new();
            rust.update(&bytes);
            rust.update(suffix);
            <[u8; 48]>::from(rust.finalize())
        };
        assert_eq!(worker.join().unwrap(), oracle(b"worker suffix"));
        assert_eq!(coordinator.finalize(), oracle(b"coordinator suffix"));
        assert_eq!(stream.finalize(), <[u8; 48]>::from(Sha384::digest(&bytes)));
    }

    /// Storage hash throughput only: no ledger database, signing or traffic.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Run explicitly in release mode; storage hash microbenchmark only"]
    fn sha384_stream_storage_hash_benchmark() {
        fn thread_cpu_ns() -> u64 {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .expect("Linux benchmark thread CPU accounting")
                .split_whitespace()
                .next()
                .expect("Linux benchmark thread runtime")
                .parse()
                .expect("Linux benchmark thread runtime nanoseconds")
        }
        const ITERATIONS: usize = 20;
        let mut bytes = vec![0u8; 13_476_746];
        StdRng::seed_from_u64(0x4841_5348_0041_0042).fill_bytes(&mut bytes);
        let domain = b"agave/pq/durable-recovery-journal-body/v2";
        let mut rust_prefix = Sha384::new();
        rust_prefix.update(domain);
        let mut native_prefix = Sha384Stream::new();
        native_prefix.update(domain);
        let mut oracle = Sha384::new();
        oracle.update(domain);
        oracle.update(&bytes);
        let expected: [u8; 48] = oracle.finalize().into();
        let measure = |native: bool| {
            let mut outputs = Vec::with_capacity(ITERATIONS);
            let cpu_before = thread_cpu_ns();
            let started = std::time::Instant::now();
            for _ in 0..ITERATIONS {
                let digest = if native {
                    let mut stream = native_prefix.clone();
                    stream.update(std::hint::black_box(bytes.as_slice()));
                    stream.finalize()
                } else {
                    let mut stream = rust_prefix.clone();
                    stream.update(std::hint::black_box(bytes.as_slice()));
                    <[u8; 48]>::from(stream.finalize())
                };
                outputs.push(std::hint::black_box(digest));
            }
            let wall_ns = started.elapsed().as_nanos();
            let cpu_ns = thread_cpu_ns()
                .checked_sub(cpu_before)
                .expect("Linux thread runtime regressed");
            (outputs, wall_ns, cpu_ns)
        };
        let mut rust_wall_ns = 0u128;
        let mut native_wall_ns = 0u128;
        let mut rust_cpu_ns = 0u64;
        let mut native_cpu_ns = 0u64;
        for trial in 0usize..4 {
            let native_first = trial.is_multiple_of(2);
            let (native, rust) = if native_first {
                (measure(true), measure(false))
            } else {
                let rust = measure(false);
                (measure(true), rust)
            };
            // Every complete output is compared outside both timed loops.
            assert_eq!(native.0.len(), ITERATIONS);
            assert_eq!(rust.0.len(), ITERATIONS);
            for (left, right) in native.0.iter().zip(&rust.0) {
                assert_eq!(*left, expected);
                assert_eq!(*right, expected);
            }
            rust_wall_ns = rust_wall_ns.saturating_add(rust.1);
            native_wall_ns = native_wall_ns.saturating_add(native.1);
            rust_cpu_ns = rust_cpu_ns.saturating_add(rust.2);
            native_cpu_ns = native_cpu_ns.saturating_add(native.2);
            println!(
                "{}",
                serde_json::json!({
                    "benchmark": "raw-storage-sha384",
                    "trial": trial,
                    "native_first": native_first,
                    "payload_bytes": bytes.len(),
                    "iterations_per_backend": ITERATIONS,
                    "rust_sha2_wall_ns": rust.1,
                    "openssl_wall_ns": native.1,
                    "rust_sha2_thread_cpu_ns": rust.2,
                    "openssl_thread_cpu_ns": native.2,
                    "all_full48_outputs_equal": true,
                })
            );
        }
        assert!(native_wall_ns > 0 && native_cpu_ns > 0);
        println!(
            "{}",
            serde_json::json!({
                "benchmark": "raw-storage-sha384-total",
                "payload_bytes": bytes.len(),
                "trials": 4,
                "iterations_per_backend_per_trial": ITERATIONS,
                "rust_sha2_wall_ns": rust_wall_ns,
                "openssl_wall_ns": native_wall_ns,
                "rust_sha2_thread_cpu_ns": rust_cpu_ns,
                "openssl_thread_cpu_ns": native_cpu_ns,
                "rust_over_openssl_wall_ratio": rust_wall_ns as f64 / native_wall_ns as f64,
                "rust_over_openssl_thread_cpu_ratio": rust_cpu_ns as f64 / native_cpu_ns as f64,
                "qualification": "Raw journal-sized byte hashing from cloned common-domain prefixes only. Linux thread CPU uses schedstat runtime; timing excludes data generation, digest comparisons and database/fsync/signing/native execution. No cluster TPS or signature-verification gain is inferred.",
            })
        );
    }

    #[test]
    fn openssl_sha384_known_vectors_and_chunked_random_inputs_match_sha2() {
        let million_a = vec![b'a'; 1_000_000];
        let known = [
            (
                &b""[..],
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                &b"abc"[..],
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                million_a.as_slice(),
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
            ),
        ];
        for (bytes, expected) in known {
            let mut hasher = Hasher::new(MessageDigest::sha384()).unwrap();
            hasher.update(bytes).unwrap();
            let actual = hasher.finish().unwrap();
            assert_eq!(actual.len(), 48);
            assert_eq!(digest_hex(actual.as_ref()), expected);
            assert_eq!(actual.as_ref(), Sha384::digest(bytes).as_slice());
        }

        let mut rng = StdRng::seed_from_u64(0x5348_4133_3834_000c);
        for size in [
            0,
            1,
            2,
            15,
            31,
            47,
            48,
            63,
            64,
            111,
            112,
            113,
            127,
            128,
            129,
            255,
            256,
            257,
            1023,
            1024,
            1025,
            4095,
            4096,
            4097,
            131_071,
            131_072,
            131_073,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
        ] {
            let mut bytes = vec![0; size];
            rng.fill_bytes(&mut bytes);
            let expected: [u8; 48] = Sha384::digest(&bytes).into();
            for chunk in [1, 7, 127, 128, 129, 1024, 8192] {
                let mut hasher = Hasher::new(MessageDigest::sha384()).unwrap();
                for part in bytes.chunks(chunk) {
                    hasher.update(part).unwrap();
                }
                let actual = hasher.finish().unwrap();
                assert_eq!(actual.as_ref(), expected, "size={size} chunk={chunk}");
            }
        }
    }

    #[test]
    fn openssl_commitments_match_sha2_for_random_domains_parts_and_large_payloads() {
        // Fixed protocol vectors generated independently with Python's SHA384 implementation.
        for (domain, parts, expected) in [
            (
                &b""[..],
                vec![],
                "1f0ae34fd71b17b37e33f69869af156fbe1d669711446078f589cfaf4cfc33f328e6e23036f03589821ceb9852bd3d91",
            ),
            (
                &b"a"[..],
                vec![&b"b"[..], &b"c"[..]],
                "c4ee22539e244e27563daa1fe20602844882103d6695f4510f6b3b84adcdc73392135290d0d5c360f4e6a4c82b0a9f2f",
            ),
            (
                &b"a"[..],
                vec![&b"bc"[..]],
                "1ac7dc63c6b166dddf6d2b82541d5e47d491e0e9513d82e95079f8b95cecb4aeae6f9415798df8366e9dddad3d17f090",
            ),
            (
                &b"\x00\xff"[..],
                vec![&b""[..], &b"abc"[..], &b""[..]],
                "b1c2e0c78d6bfccf495fa8117d8fee6a28b6cd8550d0a46b29d780d535e2cdab86ba08b9d4c230120e3f482e032a02df",
            ),
        ] {
            assert_eq!(digest_hex(&hash_commitment(domain, &parts)), expected);
            assert_eq!(
                digest_hex(&sha2_commitment_oracle(domain, &parts)),
                expected
            );
        }

        let mut rng = StdRng::seed_from_u64(0x5041_5254_5348_4133);
        let chain = [0x34; 32];
        let parent = [0x56; 48];
        let slot = 123456u64.to_le_bytes();
        for size in [
            0,
            1,
            2,
            15,
            31,
            47,
            48,
            63,
            64,
            111,
            112,
            113,
            127,
            128,
            129,
            255,
            256,
            257,
            1023,
            1024,
            1025,
            4095,
            4096,
            4097,
            131_071,
            131_072,
            131_073,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
        ] {
            let mut bytes = vec![0; size];
            rng.fill_bytes(&mut bytes);
            let mut random_domain = vec![0; size.min(257)];
            rng.fill_bytes(&mut random_domain);
            for domain in [&b""[..], &b"agave-pq-candidate-v1"[..], &random_domain] {
                let split = bytes.len() / 2;
                for parts in [
                    vec![bytes.as_slice()],
                    vec![chain.as_slice(), slot.as_slice(), parent.as_slice(), &bytes],
                    vec![&b""[..], &bytes[..split], &bytes[split..], &b""[..]],
                    vec![],
                ] {
                    assert_eq!(
                        hash_commitment(domain, &parts),
                        sha2_commitment_oracle(domain, &parts),
                        "size={size} domain={domain:?} parts={}",
                        parts.len()
                    );
                }
            }
        }
    }

    #[test]
    fn successful_math_cache_binds_every_field_and_never_caches_failures() {
        for domain in [Domain::Transaction, Domain::LeaderBatch] {
            let key = FalconKeypair::generate();
            let public = key.public_key();
            let chain = [0x61; 32];
            let message = b"cache authorization math only";
            let signature = key.sign(&chain, domain, message).unwrap();
            let cache_key = |public: &FalconPublicKey,
                             chain: &[u8; 32],
                             domain,
                             message: &[u8],
                             signature: &FalconSignature| {
                verification_cache_key(
                    &public.0,
                    chain,
                    domain,
                    &signature_message(chain, domain, message).unwrap(),
                    &signature.0,
                )
            };
            let original = cache_key(&public, &chain, domain, message, &signature);
            assert!(!cached_verification(&original));
            public.verify(&chain, domain, message, &signature).unwrap();
            assert!(cached_verification(&original));
            public.verify(&chain, domain, message, &signature).unwrap();
            let repair_signature = key.sign(&chain, Domain::Repair, message).unwrap();
            public
                .verify(&chain, Domain::Repair, message, &repair_signature)
                .unwrap();
            assert!(!cached_verification(&cache_key(
                &public,
                &chain,
                Domain::Repair,
                message,
                &repair_signature
            )));
            let other_public = FalconKeypair::generate().public_key();
            let mut nonce = signature.0;
            nonce[17] ^= 1;
            let changed_signature = FalconSignature::from_bytes(&nonce).unwrap();
            for (key, chain, domain, message, signature) in [
                (&other_public, chain, domain, message.as_slice(), &signature),
                (&public, [0x62; 32], domain, message.as_slice(), &signature),
                (
                    &public,
                    chain,
                    Domain::Repair,
                    message.as_slice(),
                    &signature,
                ),
                (
                    &public,
                    chain,
                    if domain == Domain::Transaction {
                        Domain::LeaderBatch
                    } else {
                        Domain::Transaction
                    },
                    message.as_slice(),
                    &signature,
                ),
                (&public, chain, domain, b"changed".as_slice(), &signature),
                (
                    &public,
                    chain,
                    domain,
                    message.as_slice(),
                    &changed_signature,
                ),
            ] {
                let changed = cache_key(key, &chain, domain, message, signature);
                assert_ne!(changed, original);
                assert_eq!(
                    key.verify(&chain, domain, message, signature),
                    Err(CryptoError::InvalidSignature)
                );
                assert!(!cached_verification(&changed));
            }
            assert_eq!(
                public.verify(
                    &chain,
                    domain,
                    &vec![0; MAX_SIGNED_MESSAGE_BYTES + 1],
                    &signature
                ),
                Err(CryptoError::MessageTooLarge)
            );
        }
    }

    #[test]
    fn concurrent_batch_cache_keeps_independent_contexts_and_signatures_separate() {
        let key = FalconKeypair::generate();
        let public = key.public_key();
        let messages = [
            b"batch slot=41 root=A".as_slice(),
            b"batch slot=42 root=B".as_slice(),
        ];
        let chains = [[0x74; 32], [0x75; 32]];
        let signatures = std::array::from_fn::<_, 2, _>(|index| {
            key.sign(&chains[index], Domain::LeaderBatch, messages[index])
                .unwrap()
        });
        std::thread::scope(|scope| {
            for worker in 0..16 {
                let signatures = &signatures;
                let public = &public;
                scope.spawn(move || {
                    let index = worker % 2;
                    for _ in 0..16 {
                        public
                            .verify(
                                &chains[index],
                                Domain::LeaderBatch,
                                messages[index],
                                &signatures[index],
                            )
                            .unwrap();
                        assert_eq!(
                            public.verify(
                                &chains[index],
                                Domain::LeaderBatch,
                                messages[index],
                                &signatures[1 - index]
                            ),
                            Err(CryptoError::InvalidSignature)
                        );
                        assert_eq!(
                            public.verify(
                                &chains[1 - index],
                                Domain::LeaderBatch,
                                messages[index],
                                &signatures[index]
                            ),
                            Err(CryptoError::InvalidSignature)
                        );
                    }
                });
            }
        });
        for index in 0..2 {
            let framed =
                signature_message(&chains[index], Domain::LeaderBatch, messages[index]).unwrap();
            assert!(cached_verification(&verification_cache_key(
                &public.0,
                &chains[index],
                Domain::LeaderBatch,
                &framed,
                &signatures[index].0
            )));
        }
        let stats = falcon_verification_cache_stats();
        assert!(stats.entries <= MAX_CACHED_FALCON_VERIFICATIONS);
    }

    #[test]
    fn verification_cache_has_bounded_fifo_entries_without_duplicate_growth() {
        let mut cache = VerifiedSignatures::default();
        let key = |index: usize| hash_commitment(b"cache-entry-test", &[&index.to_le_bytes()]);
        for index in 0..VERIFICATION_CACHE_ENTRIES_PER_SHARD + 65 {
            cache.insert(key(index));
            cache.insert(key(index));
            assert_eq!(cache.keys.len(), cache.order.len());
            assert!(cache.keys.len() <= VERIFICATION_CACHE_ENTRIES_PER_SHARD);
        }
        assert_eq!(cache.keys.len(), VERIFICATION_CACHE_ENTRIES_PER_SHARD);
        assert!(!cache.keys.contains(&key(64)));
        assert!(cache.keys.contains(&key(65)));
        assert!(
            cache
                .keys
                .contains(&key(VERIFICATION_CACHE_ENTRIES_PER_SHARD + 64))
        );
    }

    #[test]
    fn concurrent_cached_math_remains_valid_and_bounded() {
        let key = FalconKeypair::generate();
        let signature = key
            .sign(&[0x72; 32], Domain::Transaction, b"concurrent")
            .unwrap();
        let public = key.public_key();
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    for _ in 0..16 {
                        public
                            .verify(&[0x72; 32], Domain::Transaction, b"concurrent", &signature)
                            .unwrap();
                        assert_eq!(
                            public.verify(
                                &[0x73; 32],
                                Domain::Transaction,
                                b"concurrent",
                                &signature
                            ),
                            Err(CryptoError::InvalidSignature)
                        );
                    }
                });
            }
        });
        let stats = falcon_verification_cache_stats();
        assert!(stats.hits > 0);
        assert!(stats.misses > 0);
        assert!(stats.entries <= stats.maximum_entries);
    }

    #[test]
    fn portable_and_optimized_backends_share_keys_and_exact_signature_profile() {
        let mut backends = vec![FalconBackend::Clean];
        let selected = FalconBackend::current();
        if selected != FalconBackend::Clean {
            backends.push(selected);
        }
        assert_eq!(selected, FalconBackend::select());
        let directory = tempfile::tempdir().unwrap();
        let wrong_key = FalconKeypair::generate_with_backend(FalconBackend::Clean).public_key();
        let domains = [
            Domain::Transaction,
            Domain::NetworkHandshake,
            Domain::Gossip,
            Domain::Repair,
            Domain::ValidatorBinding,
            Domain::LeaderBatch,
            Domain::Checkpoint,
            Domain::ConsensusRoot,
            Domain::ConsensusMaterial,
        ];
        let messages = [vec![], (0..=255).collect(), vec![0xa5; 65_536]];
        for (key_index, &key_backend) in backends.iter().enumerate() {
            let key = FalconKeypair::generate_with_backend(key_backend);
            let public = key.public_key();
            let path = directory.path().join(format!("backend-{key_index}.key"));
            key.save_private(&path).unwrap();
            let loaded = FalconKeypair::load_private(&path).unwrap();
            assert_eq!(loaded.public_key(), public);
            for &signing_backend in &backends {
                for domain in domains {
                    for message in &messages {
                        let signature = loaded
                            .sign_with_backend(&[0x5a; 32], domain, message, signing_backend)
                            .unwrap();
                        assert_eq!(signature.as_bytes().len(), FALCON_SIGNATURE_BYTES);
                        let parsed = FalconSignature::from_bytes(signature.as_bytes()).unwrap();
                        let mut changed_nonce = signature.0;
                        changed_nonce[17] ^= 1;
                        let changed_nonce = FalconSignature::from_bytes(&changed_nonce).unwrap();
                        let changed_domain = if domain == Domain::Transaction {
                            Domain::NetworkHandshake
                        } else {
                            Domain::Transaction
                        };
                        let mut changed_message = message.clone();
                        changed_message.push(0);
                        for &verification_backend in &backends {
                            public
                                .verify_with_backend(
                                    &[0x5a; 32],
                                    domain,
                                    message,
                                    &parsed,
                                    verification_backend,
                                )
                                .unwrap();
                            assert_eq!(
                                wrong_key.verify_with_backend(
                                    &[0x5a; 32],
                                    domain,
                                    message,
                                    &parsed,
                                    verification_backend,
                                ),
                                Err(CryptoError::InvalidSignature)
                            );
                            for (chain, role, bytes, sig) in [
                                ([0x5b; 32], domain, message.as_slice(), &parsed),
                                ([0x5a; 32], changed_domain, message.as_slice(), &parsed),
                                ([0x5a; 32], domain, changed_message.as_slice(), &parsed),
                                ([0x5a; 32], domain, message.as_slice(), &changed_nonce),
                            ] {
                                assert_eq!(
                                    public.verify_with_backend(
                                        &chain,
                                        role,
                                        bytes,
                                        sig,
                                        verification_backend,
                                    ),
                                    Err(CryptoError::InvalidSignature),
                                    "{key_backend:?}/{signing_backend:?}/{verification_backend:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn canonical_bit_windows_match_reference_at_every_boundary() {
        for length in [
            0,
            1,
            2,
            3,
            16,
            FALCON_PUBLIC_KEY_BYTES,
            FALCON_SIGNATURE_BYTES,
        ] {
            let bytes: Vec<_> = (0..length)
                .map(|index| (index as u8).wrapping_mul(137).wrapping_add(5))
                .collect();
            for offset in 0..=bytes.len() * 8 {
                for count in 0..=16 {
                    let mut reader = Bits {
                        bytes: &bytes,
                        offset,
                    };
                    let expected = if count > bytes.len() * 8 - offset {
                        None
                    } else {
                        Some((offset..offset + count).fold(0u16, |value, bit| {
                            (value << 1) | u16::from((bytes[bit / 8] >> (7 - bit % 8)) & 1)
                        }))
                    };
                    assert_eq!(reader.read(count), expected, "{length}/{offset}/{count}");
                    assert_eq!(reader.offset, offset + expected.map_or(0, |_| count));
                }
            }
        }
    }

    #[test]
    fn private_credentials_persist_without_overwrite_and_validate_key_pair() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential");
        let key = FalconKeypair::generate();
        key.save_private(&path).unwrap();
        assert!(key.save_private(&path).is_err());
        let loaded = FalconKeypair::load_private(&path).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        let signature = loaded.sign(&[4; 32], Domain::Repair, b"restart").unwrap();
        key.public_key()
            .verify(&[4; 32], Domain::Repair, b"restart", &signature)
            .unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let other = FalconKeypair::generate();
        bytes[8..8 + FALCON_PUBLIC_KEY_BYTES].copy_from_slice(other.public_key().as_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(FalconKeypair::load_private(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FalconKeypair::load_private(&path).is_err());
        std::fs::write(&path, b"short").unwrap();
        assert!(FalconKeypair::load_private(&path).is_err());
    }

    #[test]
    fn fixed_profile_signatures_bind_chain_role_and_message() {
        let key = FalconKeypair::generate();
        let pk = key.public_key();
        assert_eq!(pk.as_bytes().len(), 897);
        let sig = key
            .sign(&[1; 32], Domain::Transaction, b"pay alice")
            .unwrap();
        assert_eq!(sig.as_bytes().len(), 666);
        pk.verify(&[1; 32], Domain::Transaction, b"pay alice", &sig)
            .unwrap();
        for (chain, role, message) in [
            ([2; 32], Domain::Transaction, &b"pay alice"[..]),
            ([1; 32], Domain::Gossip, &b"pay alice"[..]),
            ([1; 32], Domain::Transaction, &b"pay bob"[..]),
        ] {
            assert_eq!(
                pk.verify(&chain, role, message, &sig),
                Err(CryptoError::InvalidSignature)
            );
        }
        let other = FalconKeypair::generate().public_key();
        assert!(
            other
                .verify(&[1; 32], Domain::Transaction, b"pay alice", &sig)
                .is_err()
        );
    }

    // Independent scalar oracle: consume one bit at a time rather than use
    // Bits or either production parser/cache entry point.
    fn legacy_canonical_signature(bytes: &[u8]) -> Result<FalconSignature, CryptoError> {
        if bytes.len() != FALCON_SIGNATURE_BYTES || bytes[0] != 0x39 {
            return Err(CryptoError::InvalidSignatureEncoding);
        }
        let mut bits = bytes[41..]
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1));
        for _ in 0..512 {
            let negative = bits.next().ok_or(CryptoError::InvalidSignatureEncoding)?;
            let mut magnitude = 0u16;
            for _ in 0..7 {
                magnitude = (magnitude << 1)
                    | u16::from(bits.next().ok_or(CryptoError::InvalidSignatureEncoding)?);
            }
            while bits.next().ok_or(CryptoError::InvalidSignatureEncoding)? == 0 {
                magnitude += 128;
                if magnitude > 2047 {
                    return Err(CryptoError::InvalidSignatureEncoding);
                }
            }
            if negative != 0 && magnitude == 0 {
                return Err(CryptoError::InvalidSignatureEncoding);
            }
        }
        if bits.any(|bit| bit != 0) {
            return Err(CryptoError::InvalidSignatureEncoding);
        }
        let mut encoded = [0; FALCON_SIGNATURE_BYTES];
        encoded.copy_from_slice(bytes);
        Ok(FalconSignature(encoded))
    }

    fn canonical_signature_fixture(negative: bool, magnitude: u16) -> [u8; FALCON_SIGNATURE_BYTES] {
        // Encoding fixture only, not a vendor-verified signature. One extreme
        // coefficient plus 511 zero coefficients fits the padded profile.
        let mut bytes = [0; FALCON_SIGNATURE_BYTES];
        bytes[0] = 0x39;
        let mut cursor = 41 * 8;
        let mut put = |bit: u8| {
            bytes[cursor / 8] |= bit << (7 - cursor % 8);
            cursor += 1;
        };
        for index in 0..512 {
            let value = if index == 0 { magnitude } else { 0 };
            put(u8::from(index == 0 && negative));
            for shift in (0..7).rev() {
                put(((value >> shift) & 1) as u8);
            }
            for _ in 0..value / 128 {
                put(0);
            }
            put(1);
        }
        bytes
    }

    fn reset_canonical_signature_cache() {
        LAST_CANONICAL_SIGNATURE.with(|last| *last.borrow_mut() = None);
        CANONICAL_SIGNATURE_SCALAR_CALLS.with(|calls| calls.set(0));
    }

    fn canonical_scalar_calls() -> usize {
        CANONICAL_SIGNATURE_SCALAR_CALLS.with(|calls| calls.get())
    }

    #[test]
    fn canonical_signature_cache_matches_independent_scalar_bytes_and_errors() {
        let key = FalconKeypair::generate();
        let signature = key
            .sign(
                &[0x92; 32],
                Domain::LeaderBatch,
                b"canonical encoding oracle",
            )
            .unwrap();
        let mut cases = vec![signature.as_bytes().to_vec()];
        for magnitude in [0, 1, 127, 128, 2047, 2048] {
            for negative in [false, true] {
                let bytes = canonical_signature_fixture(negative, magnitude);
                assert_eq!(
                    legacy_canonical_signature(&bytes).is_ok(),
                    magnitude <= 2047 && (!negative || magnitude != 0)
                );
                cases.push(bytes.to_vec());
            }
        }
        let zero = canonical_signature_fixture(false, 0);
        let mut padding = zero;
        padding[FALCON_SIGNATURE_BYTES - 1] = 1;
        cases.push(padding.to_vec());
        let mut residual = canonical_signature_fixture(false, 128);
        residual[617] |= 1;
        assert!(legacy_canonical_signature(&residual).is_err());
        cases.push(residual.to_vec());
        // 208 valid 24-bit coefficients leave only eight bits for the next
        // coefficient, so its required terminal bit is absent inside 666B.
        let mut coefficient_truncated = [0; FALCON_SIGNATURE_BYTES];
        coefficient_truncated[0] = 0x39;
        for chunk in coefficient_truncated[41..665].as_chunks_mut::<3>().0 {
            chunk.copy_from_slice(&[0x7f, 0, 1]);
        }
        assert!(legacy_canonical_signature(&coefficient_truncated).is_err());
        cases.push(coefficient_truncated.to_vec());
        // Unterminated unary data, nonzero residual bits and every header.
        let mut unterminated = [0; FALCON_SIGNATURE_BYTES];
        unterminated[0] = 0x39;
        cases.push(unterminated.to_vec());
        for header in 0..=u8::MAX {
            let mut changed = zero;
            changed[0] = header;
            cases.push(changed.to_vec());
        }
        for length in [0, 1, 40, 41, 615, 665, 667, 1024] {
            let mut changed = zero.to_vec();
            changed.resize(length, 0);
            cases.push(changed);
        }
        // Every bit, including all nonce bytes, coefficient bits and padding.
        for offset in 0..FALCON_SIGNATURE_BYTES {
            for shift in 0..8 {
                let mut changed = zero;
                changed[offset] ^= 1 << shift;
                cases.push(changed.to_vec());
            }
        }
        for (index, bytes) in cases.iter().enumerate() {
            let expected = legacy_canonical_signature(bytes);
            assert_eq!(FalconSignature::from_bytes_uncached(bytes), expected);
            reset_canonical_signature_cache();
            assert_eq!(FalconSignature::from_bytes(bytes), expected, "cold {index}");
            let work = canonical_scalar_calls();
            assert_eq!(FalconSignature::from_bytes(bytes), expected, "warm {index}");
            let full_shape = bytes.len() == FALCON_SIGNATURE_BYTES && bytes[0] == 0x39;
            assert_eq!(
                canonical_scalar_calls() - work,
                usize::from(expected.is_err() && full_shape),
                "only successful canonical encodings are cached, case {index}"
            );
        }
    }

    #[test]
    fn canonical_signature_cache_is_exact_full_bytes_one_entry_and_success_only() {
        reset_canonical_signature_cache();
        let first = canonical_signature_fixture(false, 0);
        let parsed = FalconSignature::from_bytes(&first).unwrap();
        assert_eq!(canonical_scalar_calls(), 1);
        assert_eq!(FalconSignature::from_bytes(&first).unwrap(), parsed);
        assert_eq!(canonical_scalar_calls(), 1);
        let mut invalid_tail = first;
        invalid_tail[FALCON_SIGNATURE_BYTES - 1] = 1;
        assert_eq!(&invalid_tail[..665], &first[..665]);
        for _ in 0..2 {
            assert_eq!(
                FalconSignature::from_bytes(&invalid_tail),
                Err(CryptoError::InvalidSignatureEncoding)
            );
        }
        assert_eq!(canonical_scalar_calls(), 3);
        LAST_CANONICAL_SIGNATURE.with(|last| assert_eq!(last.borrow().as_ref(), Some(&parsed)));
        // A different nonce is canonical but must miss, not return the first
        // entry merely because coefficients and most bytes are identical.
        let mut second = first;
        second[40] ^= 1;
        let second_parsed = FalconSignature::from_bytes(&second).unwrap();
        assert_ne!(second_parsed, parsed);
        assert_eq!(second_parsed.as_bytes(), second);
        assert_eq!(canonical_scalar_calls(), 4);
        assert_eq!(FalconSignature::from_bytes(&second).unwrap(), second_parsed);
        assert_eq!(canonical_scalar_calls(), 4);
        assert_eq!(FalconSignature::from_bytes(&first).unwrap(), parsed);
        assert_eq!(
            canonical_scalar_calls(),
            5,
            "second entry replaced the first"
        );
        assert_eq!(std::mem::size_of::<Option<FalconSignature>>(), 667);
        assert!(
            std::mem::size_of::<RefCell<Option<FalconSignature>>>()
                <= FALCON_SIGNATURE_BYTES + 2 * std::mem::size_of::<isize>()
        );
    }

    #[test]
    fn canonical_signature_cache_borrow_conflicts_fall_back_without_mutation() {
        reset_canonical_signature_cache();
        let first = canonical_signature_fixture(false, 0);
        let mut second = first;
        second[1] = 1;
        let original = FalconSignature::from_bytes(&first).unwrap();
        LAST_CANONICAL_SIGNATURE.with(|last| {
            let pinned = last.borrow_mut();
            assert_eq!(FalconSignature::from_bytes(&first).unwrap(), original);
            assert_eq!(
                canonical_scalar_calls(),
                2,
                "read borrow failed: scalar fallback"
            );
            let mut malformed = first;
            malformed[665] = 1;
            assert_eq!(
                FalconSignature::from_bytes(&malformed),
                Err(CryptoError::InvalidSignatureEncoding)
            );
            assert_eq!(pinned.as_ref(), Some(&original));
        });
        LAST_CANONICAL_SIGNATURE.with(|last| {
            let pinned = last.borrow();
            assert_eq!(
                FalconSignature::from_bytes(&second),
                legacy_canonical_signature(&second)
            );
            assert_eq!(
                pinned.as_ref(),
                Some(&original),
                "write borrow failed: cache unchanged"
            );
        });
        let work = canonical_scalar_calls();
        assert_eq!(FalconSignature::from_bytes(&first).unwrap(), original);
        assert_eq!(canonical_scalar_calls(), work);
        assert_eq!(
            FalconSignature::from_bytes(&second),
            legacy_canonical_signature(&second)
        );
        assert_eq!(canonical_scalar_calls(), work + 1);
    }

    #[test]
    fn canonical_signature_cache_threads_have_independent_single_entries() {
        reset_canonical_signature_cache();
        let parent = canonical_signature_fixture(false, 0);
        FalconSignature::from_bytes(&parent).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    reset_canonical_signature_cache();
                    let mut first = parent;
                    first[1] = worker + 1;
                    let mut second = first;
                    second[40] ^= 1;
                    let parsed = FalconSignature::from_bytes(&first).unwrap();
                    assert_eq!(canonical_scalar_calls(), 1);
                    barrier.wait();
                    for _ in 0..32 {
                        assert_eq!(FalconSignature::from_bytes(&first).unwrap(), parsed);
                    }
                    assert_eq!(canonical_scalar_calls(), 1);
                    FalconSignature::from_bytes(&second).unwrap();
                    assert_eq!(canonical_scalar_calls(), 2);
                    LAST_CANONICAL_SIGNATURE.with(|last| {
                        assert_eq!(last.borrow().as_ref().unwrap().as_bytes(), second);
                    });
                });
            }
        });
        let work = canonical_scalar_calls();
        FalconSignature::from_bytes(&parent).unwrap();
        assert_eq!(
            canonical_scalar_calls(),
            work,
            "workers did not replace parent TLS"
        );
    }

    #[test]
    fn canonical_signature_cache_warm_encoding_never_authorizes_vendor_math() {
        let key = FalconKeypair::generate();
        let wrong_key = FalconKeypair::generate().public_key();
        let public = key.public_key();
        let chain = [0x93; 32];
        let message = b"encoding is not authentication";
        let signed = key.sign(&chain, Domain::LeaderBatch, message).unwrap();
        reset_canonical_signature_cache();
        let signature = FalconSignature::from_bytes(signed.as_bytes()).unwrap();
        let warm = FalconSignature::from_bytes(signed.as_bytes()).unwrap();
        assert_eq!(signature, warm);
        assert_eq!(canonical_scalar_calls(), 1);
        let mut backends = vec![FalconBackend::Clean];
        let selected = FalconBackend::current();
        if selected != FalconBackend::Clean {
            backends.push(selected);
        }
        for backend in backends {
            public
                .verify_with_backend(&chain, Domain::LeaderBatch, message, &warm, backend)
                .unwrap();
            for (key, chain, domain, bytes) in [
                (&public, [0x94; 32], Domain::LeaderBatch, message.as_slice()),
                (&public, chain, Domain::Repair, message.as_slice()),
                (&public, chain, Domain::LeaderBatch, b"changed".as_slice()),
                (&wrong_key, chain, Domain::LeaderBatch, message.as_slice()),
            ] {
                assert_eq!(
                    key.verify_with_backend(&chain, domain, bytes, &warm, backend),
                    Err(CryptoError::InvalidSignature)
                );
            }
            let mut changed = warm.0;
            changed[17] ^= 1;
            let changed = FalconSignature::from_bytes(&changed).unwrap();
            assert_eq!(
                public.verify_with_backend(&chain, Domain::LeaderBatch, message, &changed, backend),
                Err(CryptoError::InvalidSignature)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Run explicitly in release mode; canonical parsing microbenchmark only"]
    fn canonical_signature_cache_warm_repeat_benchmark() {
        fn thread_cpu_ns() -> u64 {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        }
        const ITERATIONS: usize = 20_000;
        let signature = FalconKeypair::generate()
            .sign(&[0x95; 32], Domain::LeaderBatch, b"same public signature")
            .unwrap();
        let oracle = legacy_canonical_signature(signature.as_bytes()).unwrap();
        let measure = |cached: bool| {
            let mut outputs = Vec::with_capacity(ITERATIONS);
            let cpu_before = thread_cpu_ns();
            let started = std::time::Instant::now();
            for _ in 0..ITERATIONS {
                let bytes = std::hint::black_box(signature.as_bytes());
                let parsed = if cached {
                    FalconSignature::from_bytes(bytes)
                } else {
                    FalconSignature::from_bytes_uncached(bytes)
                }
                .unwrap();
                outputs.push(std::hint::black_box(parsed));
            }
            let wall_ns = started.elapsed().as_nanos();
            let cpu_ns = thread_cpu_ns().checked_sub(cpu_before).unwrap();
            (outputs, wall_ns, cpu_ns)
        };
        let mut cached_wall_ns = 0u128;
        let mut scalar_wall_ns = 0u128;
        let mut cached_cpu_ns = 0u64;
        let mut scalar_cpu_ns = 0u64;
        for trial in 0usize..4 {
            reset_canonical_signature_cache();
            assert_eq!(
                FalconSignature::from_bytes(signature.as_bytes()).unwrap(),
                oracle
            );
            let cached_first = trial.is_multiple_of(2);
            let (cached, scalar) = if cached_first {
                (measure(true), measure(false))
            } else {
                let scalar = measure(false);
                (measure(true), scalar)
            };
            for output in cached.0.iter().chain(scalar.0.iter()) {
                assert_eq!(*output, oracle);
            }
            cached_wall_ns += cached.1;
            scalar_wall_ns += scalar.1;
            cached_cpu_ns += cached.2;
            scalar_cpu_ns += scalar.2;
            println!(
                "{}",
                serde_json::json!({
                    "benchmark": "canonical-signature-repeat", "trial": trial,
                    "iterations_per_path": ITERATIONS, "cached_first": cached_first,
                    "cached_wall_ns": cached.1, "scalar_wall_ns": scalar.1,
                    "cached_thread_cpu_ns": cached.2, "scalar_thread_cpu_ns": scalar.2,
                    "all_40000_full666_outputs_equal": true,
                })
            );
        }
        println!(
            "{}",
            serde_json::json!({
                "benchmark": "canonical-signature-repeat-total", "trials": 4,
                "iterations_per_path_per_trial": ITERATIONS,
                "cached_wall_ns": cached_wall_ns, "scalar_wall_ns": scalar_wall_ns,
                "cached_thread_cpu_ns": cached_cpu_ns, "scalar_thread_cpu_ns": scalar_cpu_ns,
                "scalar_over_cached_wall_ratio": scalar_wall_ns as f64 / cached_wall_ns as f64,
                "scalar_over_cached_thread_cpu_ratio": scalar_cpu_ns as f64 / cached_cpu_ns as f64,
                "qualification": "Warm exact-repeat public canonical parsing only, including returned signature copies. Linux schedstat thread CPU. No authentication/verification, network, persistence or native-execution work is skipped; no fleet TPS inference.",
            })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Run explicitly in release mode; alternating canonical parse misses only"]
    fn canonical_signature_cache_alternating_miss_benchmark() {
        fn thread_cpu_ns() -> u64 {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        }
        const ITERATIONS: usize = 20_000;
        let key = FalconKeypair::generate();
        let chain = [0x96; 32];
        let messages = [
            b"alternating public signature A",
            b"alternating public signature B",
        ];
        let signatures =
            messages.map(|message| key.sign(&chain, Domain::LeaderBatch, message).unwrap());
        assert_ne!(signatures[0], signatures[1]);
        let oracle = std::array::from_fn::<_, 2, _>(|index| {
            let parsed = legacy_canonical_signature(signatures[index].as_bytes()).unwrap();
            assert_eq!(parsed, signatures[index]);
            key.public_key()
                .verify_with_backend(
                    &chain,
                    Domain::LeaderBatch,
                    messages[index],
                    &parsed,
                    FalconBackend::current(),
                )
                .unwrap();
            parsed
        });
        let measure = |cached: bool| {
            reset_canonical_signature_cache();
            let mut outputs = Vec::with_capacity(ITERATIONS);
            let cpu_before = thread_cpu_ns();
            let started = std::time::Instant::now();
            for index in 0..ITERATIONS {
                // Identical ordered input sequence for both paths. Every
                // cached-path call differs from its last successful entry.
                let bytes = std::hint::black_box(signatures[index & 1].as_bytes());
                let parsed = if cached {
                    FalconSignature::from_bytes(bytes)
                } else {
                    FalconSignature::from_bytes_uncached(bytes)
                }
                .unwrap();
                outputs.push(std::hint::black_box(parsed));
            }
            let wall_ns = started.elapsed().as_nanos();
            let cpu_ns = thread_cpu_ns().checked_sub(cpu_before).unwrap();
            assert_eq!(
                canonical_scalar_calls(),
                if cached { ITERATIONS } else { 0 },
                "every cached-path call was a scalar-validation miss"
            );
            (outputs, wall_ns, cpu_ns)
        };
        let mut cached_wall_ns = 0u128;
        let mut scalar_wall_ns = 0u128;
        let mut cached_cpu_ns = 0u64;
        let mut scalar_cpu_ns = 0u64;
        for trial in 0usize..4 {
            let cached_first = trial.is_multiple_of(2);
            let (cached, scalar) = if cached_first {
                (measure(true), measure(false))
            } else {
                let scalar = measure(false);
                (measure(true), scalar)
            };
            assert_eq!(cached.0.len(), ITERATIONS);
            assert_eq!(scalar.0.len(), ITERATIONS);
            for (index, (left, right)) in cached.0.iter().zip(&scalar.0).enumerate() {
                assert_eq!(*left, oracle[index & 1]);
                assert_eq!(*right, oracle[index & 1]);
            }
            cached_wall_ns += cached.1;
            scalar_wall_ns += scalar.1;
            cached_cpu_ns += cached.2;
            scalar_cpu_ns += scalar.2;
            println!(
                "{}",
                serde_json::json!({
                    "benchmark": "canonical-signature-alternating-miss", "trial": trial,
                    "iterations_per_path": ITERATIONS, "cached_first": cached_first,
                    "genuine_distinct_canonical_signatures": 2, "cache_hits": 0,
                    "cached_path_scalar_calls": ITERATIONS,
                    "cached_wall_ns": cached.1, "scalar_wall_ns": scalar.1,
                    "cached_thread_cpu_ns": cached.2, "scalar_thread_cpu_ns": scalar.2,
                    "all_40000_ordered_full666_outputs_equal": true,
                })
            );
        }
        println!(
            "{}",
            serde_json::json!({
                "benchmark": "canonical-signature-alternating-miss-total", "trials": 4,
                "iterations_per_path_per_trial": ITERATIONS,
                "cached_wall_ns": cached_wall_ns, "scalar_wall_ns": scalar_wall_ns,
                "cached_thread_cpu_ns": cached_cpu_ns, "scalar_thread_cpu_ns": scalar_cpu_ns,
                "cached_miss_over_scalar_wall_ratio": cached_wall_ns as f64 / scalar_wall_ns as f64,
                "cached_miss_over_scalar_thread_cpu_ratio": cached_cpu_ns as f64 / scalar_cpu_ns as f64,
                "qualification": "Alternating two genuine canonical public signatures, forcing one-entry cache miss each call; both paths use identical input order. Cached miss path includes cfg(test) scalar-call counter bookkeeping, absent in production and baseline. Wall/schedstat CPU exclude signature generation, verification and full666 output checks. No speed assertions or fleet TPS/hit-rate inference.",
            })
        );
    }

    #[test]
    fn strict_key_and_signature_encodings() {
        let key = FalconKeypair::generate();
        let mut pk = key.public_key().as_bytes().to_vec();
        pk[0] = 0x0a;
        assert_eq!(
            FalconPublicKey::from_bytes(&pk),
            Err(CryptoError::InvalidPublicKey)
        );
        pk[0] = 0x09;
        pk[1] = 0xff;
        pk[2] |= 0xfc;
        assert_eq!(
            FalconPublicKey::from_bytes(&pk),
            Err(CryptoError::InvalidPublicKey)
        );
        assert!(FalconPublicKey::from_bytes(&[]).is_err());
        let sig = key.sign(&[0; 32], Domain::Repair, b"repair").unwrap();
        assert_eq!(FalconSignature::from_bytes(sig.as_bytes()).unwrap(), sig);
        assert!(FalconSignature::from_bytes(&sig.as_bytes()[..665]).is_err());
        let mut changed = sig.as_bytes().to_vec();
        changed[665] |= 1;
        assert!(FalconSignature::from_bytes(&changed).is_err());
        changed[0] = 0x49;
        assert!(FalconSignature::from_bytes(&changed).is_err());
    }

    #[test]
    fn commitment_framing_and_message_bounds() {
        assert_ne!(
            hash_commitment(b"a", &[b"bc"]),
            hash_commitment(b"ab", &[b"c"])
        );
        assert_ne!(
            hash_commitment(b"a", &[b"b", b"c"]),
            hash_commitment(b"a", &[b"bc"])
        );
        let key = FalconKeypair::generate();
        assert_eq!(
            key.sign(
                &[0; 32],
                Domain::Transaction,
                &vec![0; MAX_SIGNED_MESSAGE_BYTES + 1]
            ),
            Err(CryptoError::MessageTooLarge)
        );
    }
}

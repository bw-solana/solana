//! Native rustls TLS 1.3 profile: padded Falcon-512 certificate possession,
//! ML-KEM-768, HKDF-SHA384, AES-256-GCM. There is no classical fallback.
//!
//! The Falcon scheme uses a private-use identifier; peers must use this exact
//! profile. Certificates are canonical, pinned X.509 credential containers.
//! Their outer placeholder signatures do not establish authority: the trusted
//! registry and the Falcon CertificateVerify signature do that.

use {
    agave_pq_crypto::crypto::{
        Domain, FALCON_SIGNATURE_BYTES, FalconKeypair, FalconPublicKey, FalconSignature,
    },
    ml_kem::{
        Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768,
        kem::{Decapsulate, Encapsulate},
    },
    rand08::rngs::OsRng,
    rustls::{
        ClientConfig, DigitallySignedStruct, DistinguishedName, Error, NamedGroup, PeerMisbehaved,
        ProtocolVersion, ServerConfig, SignatureAlgorithm, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{
            ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, KeyProvider, SharedSecret,
            SupportedKxGroup, WebPkiSupportedAlgorithms,
        },
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
        sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    },
    solana_pubkey::Pubkey,
    std::{collections::BTreeMap, fmt, sync::Arc},
    zeroize::Zeroize,
};

pub const FALCON_TLS_SCHEME: SignatureScheme = SignatureScheme::Unknown(0xfefe);
pub const PQ_ALPN: &[u8] = b"agave-pq-validator-v1";
type KemSecret = <MlKem768 as KemCore>::DecapsulationKey;
type KemPublic = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Debug)]
struct MlKemGroup;

static ML_KEM_GROUP: MlKemGroup = MlKemGroup;

impl SupportedKxGroup for MlKemGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (secret, public) = MlKem768::generate(&mut OsRng);
        Ok(Box::new(MlKemActive {
            secret,
            public: public.as_bytes().to_vec(),
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        validate_kem_public(client_share)?;
        let encoded = Encoded::<KemPublic>::try_from(client_share)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let public = KemPublic::from_bytes(&encoded);
        let (ciphertext, mut secret) = public
            .encapsulate(&mut OsRng)
            .map_err(|_| Error::General("ML-KEM encapsulation failed".into()))?;
        let shared = SharedSecret::from(secret.as_slice());
        secret.as_mut_slice().zeroize();
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: ciphertext.to_vec(),
            secret: shared,
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct MlKemActive {
    secret: KemSecret,
    public: Vec<u8>,
}

impl ActiveKeyExchange for MlKemActive {
    fn complete(self: Box<Self>, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
        let encoded = Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let mut secret = self
            .secret
            .decapsulate(&encoded)
            .map_err(|_| Error::General("ML-KEM decapsulation failed".into()))?;
        let shared = SharedSecret::from(secret.as_slice());
        secret.as_mut_slice().zeroize();
        Ok(shared)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

fn validate_kem_public(bytes: &[u8]) -> Result<(), Error> {
    let invalid = || Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
    if bytes.len() != 1184 {
        return Err(invalid());
    }
    for pair in bytes[..1152].as_chunks::<3>().0 {
        let a = u16::from(pair[0]) | ((u16::from(pair[1]) & 15) << 8);
        let b = (u16::from(pair[1]) >> 4) | (u16::from(pair[2]) << 4);
        if a >= 3329 || b >= 3329 {
            return Err(invalid());
        }
    }
    Ok(())
}

#[derive(Debug)]
struct NoDerKeys;
static NO_DER_KEYS: NoDerKeys = NoDerKeys;

impl KeyProvider for NoDerKeys {
    fn load_private_key(&self, _key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "PQ credentials require the pinned Falcon resolver".into(),
        ))
    }
}

pub fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384];
    provider.kx_groups = vec![&ML_KEM_GROUP];
    provider.signature_verification_algorithms = WebPkiSupportedAlgorithms {
        all: &[],
        mapping: &[],
    };
    provider.key_provider = &NO_DER_KEYS;
    provider
}

struct FalconTlsKey {
    chain: [u8; 32],
    key: Arc<FalconKeypair>,
}

impl fmt::Debug for FalconTlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FalconTlsKey").finish_non_exhaustive()
    }
}

impl SigningKey for FalconTlsKey {
    fn choose_scheme(&self, schemes: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        schemes.contains(&FALCON_TLS_SCHEME).then(|| {
            Box::new(Self {
                chain: self.chain,
                key: Arc::clone(&self.key),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0xfe)
    }
}

impl Signer for FalconTlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key
            .sign(&self.chain, Domain::NetworkHandshake, message)
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(|_| Error::General("Falcon CertificateVerify signing failed".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        FALCON_TLS_SCHEME
    }
}

/// Certificates are generated from the independently trusted registry. Exact
/// byte matching avoids ambiguity between certificate parsing and attribution.
#[derive(Debug)]
pub(super) struct PinnedCredentials {
    chain: [u8; 32],
    certificates: BTreeMap<Vec<u8>, (Pubkey, FalconPublicKey)>,
    expected: Option<Pubkey>,
}

impl PinnedCredentials {
    pub(super) fn new(
        chain: [u8; 32],
        registry: &BTreeMap<Pubkey, FalconPublicKey>,
        expected: Option<Pubkey>,
    ) -> Self {
        Self {
            chain,
            certificates: registry
                .iter()
                .map(|(identity, key)| {
                    (
                        certificate(chain, *identity, key).as_ref().to_vec(),
                        (*identity, key.clone()),
                    )
                })
                .collect(),
            expected,
        }
    }

    pub(super) fn identity(&self, cert: &CertificateDer<'_>) -> Result<Pubkey, Error> {
        let (identity, _) = self
            .certificates
            .get(cert.as_ref())
            .ok_or_else(|| Error::General("unregistered PQ TLS credential".into()))?;
        if self.expected.is_some_and(|expected| expected != *identity) {
            return Err(Error::General("PQ TLS server identity mismatch".into()));
        }
        Ok(*identity)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.identity(cert)?;
        if dss.scheme != FALCON_TLS_SCHEME {
            return Err(Error::General(
                "classical TLS signature rejected in PQ mode".into(),
            ));
        }
        let (_, key) = self
            .certificates
            .get(cert.as_ref())
            .ok_or_else(|| Error::General("unregistered PQ TLS credential".into()))?;
        let signature = FalconSignature::from_bytes(dss.signature())
            .map_err(|_| Error::General("invalid Falcon TLS signature encoding".into()))?;
        key.verify(&self.chain, Domain::NetworkHandshake, message, &signature)
            .map_err(|_| Error::General("invalid Falcon CertificateVerify signature".into()))?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for PinnedCredentials {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General(
                "PQ TLS accepts one pinned certificate".into(),
            ));
        }
        self.identity(cert)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled in PQ mode".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![FALCON_TLS_SCHEME]
    }
}

impl ClientCertVerifier for PinnedCredentials {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if !intermediates.is_empty() {
            return Err(Error::General(
                "PQ TLS accepts one pinned certificate".into(),
            ));
        }
        self.identity(cert)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is disabled in PQ mode".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![FALCON_TLS_SCHEME]
    }
}

fn resolver(
    chain: [u8; 32],
    identity: Pubkey,
    signer: Arc<FalconKeypair>,
) -> Arc<SingleCertAndKey> {
    let cert = certificate(chain, identity, &signer.public_key());
    Arc::new(SingleCertAndKey::from(CertifiedKey::new(
        vec![cert],
        Arc::new(FalconTlsKey { chain, key: signer }),
    )))
}

pub(super) fn server_config(
    chain: [u8; 32],
    identity: Pubkey,
    signer: Arc<FalconKeypair>,
    registry: &BTreeMap<Pubkey, FalconPublicKey>,
) -> Result<ServerConfig, Error> {
    let mut tls = ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PinnedCredentials::new(chain, registry, None)))
        .with_cert_resolver(resolver(chain, identity, signer));
    tls.alpn_protocols = vec![PQ_ALPN.to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(tls)
}

pub(super) fn client_config(
    chain: [u8; 32],
    identity: Pubkey,
    signer: Arc<FalconKeypair>,
    registry: &BTreeMap<Pubkey, FalconPublicKey>,
    expected: Pubkey,
) -> Result<ClientConfig, Error> {
    let mut tls = ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCredentials::new(
            chain,
            registry,
            Some(expected),
        )))
        .with_client_cert_resolver(resolver(chain, identity, signer));
    tls.alpn_protocols = vec![PQ_ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(tls)
}

fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(bytes.len() as u8);
    } else if bytes.len() < 256 {
        out.extend_from_slice(&[0x81, bytes.len() as u8]);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
    out
}

fn certificate(
    chain: [u8; 32],
    identity: Pubkey,
    public: &FalconPublicKey,
) -> CertificateDer<'static> {
    // OID 1.3.9999.3.6 is used only inside this pinned experimental container.
    let algorithm = der(0x30, &[0x06, 0x05, 0x2b, 0xce, 0x0f, 0x03, 0x06]);
    let mut credential = vec![0]; // BIT STRING's unused-bit count
    credential.extend_from_slice(b"AGAVEPQ1");
    credential.extend_from_slice(&chain);
    credential.extend_from_slice(identity.as_ref());
    credential.extend_from_slice(public.as_bytes());
    let mut spki = algorithm.clone();
    spki.extend_from_slice(&der(0x03, &credential));
    let mut tbs = vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
    tbs.extend_from_slice(&algorithm);
    tbs.extend_from_slice(&[0x30, 0x00]); // issuer
    let mut validity = der(0x17, b"700101000000Z");
    validity.extend_from_slice(&der(0x18, b"40960101000000Z"));
    tbs.extend_from_slice(&der(0x30, &validity));
    tbs.extend_from_slice(&[0x30, 0x00]); // subject
    tbs.extend_from_slice(&der(0x30, &spki));
    let mut outer = der(0x30, &tbs);
    outer.extend_from_slice(&algorithm);
    outer.extend_from_slice(&der(0x03, &vec![0; FALCON_SIGNATURE_BYTES + 1]));
    CertificateDer::from(der(0x30, &outer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_group_round_trip_and_modulus_check() {
        let active = ML_KEM_GROUP.start().unwrap();
        let server = ML_KEM_GROUP.start_and_complete(active.pub_key()).unwrap();
        let client = active.complete(&server.pub_key).unwrap();
        assert_eq!(client.secret_bytes(), server.secret.secret_bytes());
        let mut bad = vec![0; 1184];
        bad[..3].fill(0xff);
        assert!(ML_KEM_GROUP.start_and_complete(&bad).is_err());
        assert!(ML_KEM_GROUP.start_and_complete(&[]).is_err());
    }

    #[test]
    fn pinned_certificate_rejects_chain_key_and_identity_substitution() {
        let key = FalconKeypair::generate();
        let identity = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let registry = BTreeMap::from([(identity, key.public_key())]);
        let pin = PinnedCredentials::new([7; 32], &registry, Some(identity));
        let cert = certificate([7; 32], identity, &key.public_key());
        assert_eq!(pin.identity(&cert).unwrap(), identity);
        assert!(
            pin.identity(&certificate([8; 32], identity, &key.public_key()))
                .is_err()
        );
        assert!(
            pin.identity(&certificate([7; 32], other, &key.public_key()))
                .is_err()
        );
        assert!(
            pin.identity(&certificate(
                [7; 32],
                identity,
                &FalconKeypair::generate().public_key()
            ))
            .is_err()
        );
        assert!(
            PinnedCredentials::new([7; 32], &registry, Some(other))
                .identity(&cert)
                .is_err()
        );
    }
}

//! AWS KMS-backed [`KeyProvider`] (feature `kms-aws`).
//!
//! In this mode the certificate private key is generated inside AWS KMS and
//! never exists outside the service: AcmeX persists only the [`KeyRef`] (whose
//! `key_id` carries the KMS key id), CSRs are signed through the KMS `Sign`
//! API, and [`KeyProvider::export`] always returns `None`.
//!
//! # Algorithm mapping
//!
//! [`KeyAlgorithm`] maps onto asymmetric KMS `KeySpec`s that support
//! `SIGN_VERIFY`, paired with the signing algorithm whose output format matches
//! what rcgen expects for the corresponding [`rcgen::SignatureAlgorithm`]:
//!
//! | AcmeX        | KMS KeySpec      | KMS SigningAlgorithm       | rcgen algorithm          |
//! |--------------|------------------|----------------------------|--------------------------|
//! | `EcP256`     | `ECC_NIST_P256`  | `ECDSA_SHA_256`            | `PKCS_ECDSA_P256_SHA256` |
//! | `EcP384`     | `ECC_NIST_P384`  | `ECDSA_SHA_384`            | `PKCS_ECDSA_P384_SHA384` |
//! | `EcP521`     | `ECC_NIST_P521`  | `ECDSA_SHA_512`            | `PKCS_ECDSA_P521_SHA512` |
//! | `Rsa2048`    | `RSA_2048`       | `RSASSA_PKCS1_V1_5_SHA_256`| `PKCS_RSA_SHA256`        |
//! | `Rsa4096`    | `RSA_4096`       | `RSASSA_PKCS1_V1_5_SHA_512`| `PKCS_RSA_SHA512`        |
//!
//! The formats align without conversion: KMS returns ECDSA signatures as
//! DER-encoded ANSI X9.62 objects (exactly what rcgen's `*_ASN1_SIGNING`
//! algorithms produce/consume) and RSA PKCS#1 v1.5 signatures as the raw
//! signature block. KMS signs the raw CSR to-be-signed bytes
//! (`MessageType::RAW`), matching the message rcgen hands to
//! [`rcgen::SigningKey::sign`].
//!
//! Ed25519 is rejected: KMS `ED25519_SHA_512` signing semantics are not the
//! pure-Ed25519 signature rcgen requires for `PKCS_ED25519` CSRs.
//!
//! # Key identity
//!
//! [`KeyRef::key_id`] stores the bare KMS key id (the UUID form). KMS ARNs
//! contain `/` and are therefore not representable in a [`KeyId`]; callers
//! needing ARNs can derive them from the id plus their account/region.
//!
//! # Destruction semantics
//!
//! KMS does not support immediate destruction. [`KeyProvider::destroy_confirmed`]
//! calls `ScheduleKeyDeletion`: the key becomes unusable immediately and the
//! key material is deleted by AWS after the pending-deletion window
//! (7-30 days, configured on [`KmsKeyProviderConfig`]). The conservative
//! [`KeyProvider::destroy`] probe never schedules anything.
//!
//! # Runtime requirements
//!
//! CSR generation bridges rcgen's synchronous signing trait to the async KMS
//! client with `tokio::task::block_in_place`, which requires a multi-threaded
//! tokio runtime (the default flavor used by the AcmeX server and worker).

use std::fmt;

use async_trait::async_trait;
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, SigningAlgorithmSpec};
use aws_sdk_kms::types::{KeyUsageType, MessageType, Tag};
use rcgen::{Error as RcgenError, PublicKeyData, SigningKey};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::{
    CreateCsr, CreateKey, CsrArtifact, DestroyAuthorization, DestroyOutcome, ExportAuthorization,
    KeyProvider, KeyRef, PublicKeyInfo, SecretBytes,
};
use crate::domain::{KeyAlgorithm, KeyId, KeyManagementMode};
use crate::error::{AcmeError, Result};

/// AWS KMS's upper bound for the `Sign` message payload (bytes).
const MAX_KMS_SIGN_MESSAGE_BYTES: usize = 4096;

/// Provider id recorded in [`KeyRef::provider`] unless overridden.
pub const DEFAULT_PROVIDER_ID: &str = "kms-aws";

/// Smallest `ScheduleKeyDeletion` pending window AWS accepts (days).
pub const MIN_KEY_DELETION_WINDOW_DAYS: i32 = 7;

/// Largest `ScheduleKeyDeletion` pending window AWS accepts (days).
pub const MAX_KEY_DELETION_WINDOW_DAYS: i32 = 30;

/// Default pending-deletion window for `destroy_confirmed` (days).
pub const DEFAULT_KEY_DELETION_WINDOW_DAYS: i32 = 7;

/// Construction parameters for [`KmsKeyProvider`].
///
/// Credentials always come from the ambient AWS configuration chain (env,
/// shared config, IMDS, SSO, ...) exactly like the Route53 provider; there is
/// deliberately no credential field so secrets cannot be persisted in AcmeX
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsKeyProviderConfig {
    /// Provider id stored in [`KeyRef::provider`].
    pub provider_id: String,
    /// AWS region override (otherwise resolved from the environment).
    pub region: Option<String>,
    /// Endpoint override for the KMS client (tests and VPC endpoints).
    pub endpoint_url: Option<String>,
    /// Pending-deletion window for `ScheduleKeyDeletion`, in days (7-30).
    pub key_deletion_window_days: i32,
    /// Extra resource tags applied to created KMS keys.
    ///
    /// `owner=acmex` is always applied on top of these.
    pub extra_tags: Vec<(String, String)>,
}

impl Default for KmsKeyProviderConfig {
    fn default() -> Self {
        Self {
            provider_id: DEFAULT_PROVIDER_ID.to_string(),
            region: None,
            endpoint_url: None,
            key_deletion_window_days: DEFAULT_KEY_DELETION_WINDOW_DAYS,
            extra_tags: Vec::new(),
        }
    }
}

impl KmsKeyProviderConfig {
    /// Validates the configuration before any AWS call is made.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_KEY_DELETION_WINDOW_DAYS..=MAX_KEY_DELETION_WINDOW_DAYS)
            .contains(&self.key_deletion_window_days)
        {
            return Err(AcmeError::invalid_input(format!(
                "KMS key_deletion_window_days must be between {MIN_KEY_DELETION_WINDOW_DAYS} and \
                 {MAX_KEY_DELETION_WINDOW_DAYS}, found {}",
                self.key_deletion_window_days
            )));
        }
        if self.provider_id.is_empty() {
            return Err(AcmeError::invalid_input(
                "KMS provider_id must not be empty",
            ));
        }
        Ok(())
    }
}

/// [`KeyProvider`] whose key material lives inside AWS KMS.
///
/// The provider is clone-friendly and shares one KMS client across clones;
/// every method takes `&self` and is safe to call concurrently.
#[derive(Clone)]
pub struct KmsKeyProvider {
    config: KmsKeyProviderConfig,
    client: aws_sdk_kms::Client,
}

impl KmsKeyProvider {
    /// Creates a provider using the ambient AWS configuration chain, honoring
    /// the [`KmsKeyProviderConfig::region`] and
    /// [`KmsKeyProviderConfig::endpoint_url`] overrides.
    pub async fn new(config: KmsKeyProviderConfig) -> Result<Self> {
        config.validate()?;
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = config.region.as_deref() {
            loader = loader.region(aws_config::Region::new(region.to_owned()));
        }
        let sdk_config = loader.load().await;
        let mut builder = aws_sdk_kms::config::Builder::from(&sdk_config);
        builder.set_endpoint_url(config.endpoint_url.clone());
        let client = aws_sdk_kms::Client::from_conf(builder.build());
        Ok(Self { config, client })
    }

    /// Creates a provider from a pre-built KMS client.
    ///
    /// Intended for tests and for callers that manage SDK client construction
    /// themselves; production code should prefer [`KmsKeyProvider::new`].
    pub fn from_client(config: KmsKeyProviderConfig, client: aws_sdk_kms::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, client })
    }

    fn ensure_own_key(&self, key: &KeyRef) -> Result<()> {
        if key.provider != self.config.provider_id {
            return Err(AcmeError::invalid_input(format!(
                "key `{}` belongs to provider `{}`, not `{}`",
                key.key_id, key.provider, self.config.provider_id
            )));
        }
        Ok(())
    }

    fn tag(name: &str, value: &str) -> Result<Tag> {
        Tag::builder()
            .tag_key(name)
            .tag_value(value)
            .build()
            .map_err(|err| AcmeError::configuration(format!("build KMS tag `{name}`: {err}")))
    }

    async fn fetch_public_key_spki(&self, key_id: &str) -> Result<Vec<u8>> {
        let output = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|err| classify_kms_error("GetPublicKey", err))?;
        let spki_der = output
            .public_key()
            .ok_or_else(|| AcmeError::crypto("AWS KMS GetPublicKey returned no public key"))?
            .as_ref();
        Ok(spki_der.to_vec())
    }
}

impl fmt::Debug for KmsKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The KMS client (which owns the resolved credentials) is deliberately
        // omitted from the output.
        f.debug_struct("KmsKeyProvider")
            .field("provider_id", &self.config.provider_id)
            .field("region", &self.config.region)
            .field("endpoint_url", &self.config.endpoint_url)
            .field(
                "key_deletion_window_days",
                &self.config.key_deletion_window_days,
            )
            .field("extra_tags", &self.config.extra_tags)
            .finish()
    }
}

/// Maps an AcmeX key algorithm onto its KMS key spec, KMS signing algorithm
/// and the rcgen signature algorithm used in the generated CSR.
///
/// The rcgen and KMS signing algorithms are chosen so their signature byte
/// formats match without conversion (see the module docs).
fn algorithm_mapping(
    algorithm: KeyAlgorithm,
) -> Result<(
    KeySpec,
    SigningAlgorithmSpec,
    &'static rcgen::SignatureAlgorithm,
)> {
    match algorithm {
        KeyAlgorithm::EcP256 => Ok((
            KeySpec::EccNistP256,
            SigningAlgorithmSpec::EcdsaSha256,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )),
        KeyAlgorithm::EcP384 => Ok((
            KeySpec::EccNistP384,
            SigningAlgorithmSpec::EcdsaSha384,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        )),
        KeyAlgorithm::EcP521 => Ok((
            KeySpec::EccNistP521,
            SigningAlgorithmSpec::EcdsaSha512,
            &rcgen::PKCS_ECDSA_P521_SHA512,
        )),
        KeyAlgorithm::Rsa2048 => Ok((
            KeySpec::Rsa2048,
            SigningAlgorithmSpec::RsassaPkcs1V15Sha256,
            &rcgen::PKCS_RSA_SHA256,
        )),
        KeyAlgorithm::Rsa4096 => Ok((
            KeySpec::Rsa4096,
            SigningAlgorithmSpec::RsassaPkcs1V15Sha512,
            &rcgen::PKCS_RSA_SHA512,
        )),
        KeyAlgorithm::Ed25519 => Err(AcmeError::invalid_input(
            "the AWS KMS provider does not support Ed25519: KMS ED25519_SHA_512 signing does not \
             match the pure-Ed25519 CSR signature rcgen requires",
        )),
    }
}

/// Extracts the subject public key BIT STRING payload from a DER-encoded
/// `SubjectPublicKeyInfo`.
///
/// rcgen's CSR builder expects exactly these bytes in
/// [`PublicKeyData::der_bytes`]: for EC keys the raw uncompressed point, for
/// RSA keys the DER-encoded PKCS#1 `RSAPublicKey` — in both cases the BIT
/// STRING contents of the SPKI, which is what KMS's `GetPublicKey` returns.
fn extract_subject_public_key_bits(spki_der: &[u8]) -> Result<Vec<u8>> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|err| AcmeError::crypto(format!("parse KMS SubjectPublicKeyInfo: {err}")))?;
    if spki.subject_public_key.unused_bits != 0 {
        return Err(AcmeError::crypto(
            "KMS public key BIT STRING carries unused bits",
        ));
    }
    Ok(spki.subject_public_key.data.to_vec())
}

/// rcgen remote signer backed by the KMS `Sign` API.
///
/// No private key material ever exists on the AcmeX side: the signer holds the
/// public key bits (for the CSR's SubjectPublicKeyInfo) and forwards every
/// signature request to KMS.
struct KmsRemoteSigner<'a> {
    client: &'a aws_sdk_kms::Client,
    key_id: String,
    signing_algorithm: SigningAlgorithmSpec,
    rcgen_algorithm: &'static rcgen::SignatureAlgorithm,
    public_key_bits: Vec<u8>,
}

impl fmt::Debug for KmsRemoteSigner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsRemoteSigner")
            .field("key_id", &self.key_id)
            .field("signing_algorithm", &self.signing_algorithm)
            .field("public_key_bits_len", &self.public_key_bits.len())
            .finish()
    }
}

impl PublicKeyData for KmsRemoteSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_bits
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.rcgen_algorithm
    }
}

impl SigningKey for KmsRemoteSigner<'_> {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, RcgenError> {
        if msg.len() > MAX_KMS_SIGN_MESSAGE_BYTES {
            tracing::error!(
                len = msg.len(),
                limit = MAX_KMS_SIGN_MESSAGE_BYTES,
                "CSR to-be-signed data exceeds the AWS KMS Sign message limit"
            );
            return Err(RcgenError::RemoteKeyError);
        }
        // The CSR TBS bytes travel to KMS but are never logged.
        let future = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .message(Blob::new(msg.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(self.signing_algorithm.clone())
            .send();
        // rcgen's SigningKey is synchronous while KMS is asynchronous; bridge
        // with block_in_place, which requires a multi-threaded tokio runtime.
        // The SDK error is boxed so the bridge closure keeps a small return
        // type; classification unpacks it.
        let multi_thread = matches!(
            tokio::runtime::Handle::try_current(),
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        );
        if !multi_thread {
            // Fail with an operator-readable message instead of the panic
            // block_in_place would raise on a current-thread runtime.
            tracing::error!(
                "AWS KMS CSR signing requires a multi-threaded tokio runtime (the AcmeX default)"
            );
            return Err(RcgenError::RemoteKeyError);
        }
        let result: std::result::Result<_, Box<SdkError<aws_sdk_kms::operation::sign::SignError>>> =
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(future)
                    .map_err(Box::new)
            });
        match result {
            Ok(output) => output
                .signature()
                .map(|signature| signature.as_ref().to_vec())
                .ok_or(RcgenError::RemoteKeyError),
            Err(err) => {
                let classified = classify_kms_error("Sign", *err);
                // Only the classified error (message text from KMS) is logged;
                // neither the message nor the signature bytes ever are.
                tracing::error!(error = %classified, "AWS KMS CSR signing failed");
                Err(RcgenError::RemoteKeyError)
            }
        }
    }
}

#[async_trait]
impl KeyProvider for KmsKeyProvider {
    async fn create_key(&self, request: CreateKey) -> Result<KeyRef> {
        if request.policy.mode != KeyManagementMode::Managed {
            return Err(AcmeError::invalid_input(
                "the AWS KMS provider can only create managed keys",
            ));
        }
        if request.policy.exportable {
            return Err(AcmeError::invalid_input(
                "keys held in AWS KMS are never exportable; set exportable=false",
            ));
        }
        let (key_spec, _, _) = algorithm_mapping(request.policy.algorithm)?;

        let mut tags = vec![Self::tag("owner", "acmex")?];
        if let Some(requested) = &request.key_id {
            tags.push(Self::tag("acmex-key-id", requested.as_str())?);
        }
        for (name, value) in &self.config.extra_tags {
            tags.push(Self::tag(name, value)?);
        }

        let output = self
            .client
            .create_key()
            .key_spec(key_spec)
            .key_usage(KeyUsageType::SignVerify)
            .description("Managed by AcmeX (AWS KMS KeyProvider)")
            .set_tags(Some(tags))
            .send()
            .await
            .map_err(|err| classify_kms_error("CreateKey", err))?;
        let metadata = output
            .key_metadata()
            .ok_or_else(|| AcmeError::crypto("AWS KMS CreateKey returned no key metadata"))?;
        // Store the bare key id: ARNs contain `/`, which KeyId forbids.
        let key_id = KeyId::new(metadata.key_id()).map_err(|err| {
            AcmeError::crypto(format!("KMS key id is not a valid KeyRef id: {err}"))
        })?;
        tracing::info!(
            provider = %self.config.provider_id,
            key_id = %key_id,
            "created AWS KMS signing key"
        );
        Ok(KeyRef {
            provider: self.config.provider_id.clone(),
            key_id,
            algorithm: request.policy.algorithm,
            // KMS key material can never leave the service.
            exportable: false,
        })
    }

    async fn create_csr(&self, mut request: CreateCsr) -> Result<CsrArtifact> {
        if let Some(external) = request.external_csr.take() {
            return super::validate_external_csr(request, external);
        }
        if request.policy.mode != KeyManagementMode::Managed {
            return Err(AcmeError::invalid_input(
                "external CSR mode requires caller-provided CSR material",
            ));
        }
        if request.policy.exportable {
            return Err(AcmeError::invalid_input(
                "keys held in AWS KMS are never exportable; set exportable=false",
            ));
        }

        let key_ref = match request.key_ref {
            Some(key_ref) => {
                self.ensure_own_key(&key_ref)?;
                key_ref
            }
            None => {
                self.create_key(CreateKey {
                    policy: request.policy.clone(),
                    key_id: None,
                })
                .await?
            }
        };
        let (_, signing_algorithm, rcgen_algorithm) = algorithm_mapping(request.policy.algorithm)?;

        let spki_der = self.fetch_public_key_spki(key_ref.key_id.as_str()).await?;
        let public_key_bits = extract_subject_public_key_bits(&spki_der)?;

        let signer = KmsRemoteSigner {
            client: &self.client,
            key_id: key_ref.key_id.as_str().to_owned(),
            signing_algorithm,
            rcgen_algorithm,
            public_key_bits,
        };
        let params = super::certificate_params_for_identifiers(request.identifiers.as_slice())?;
        let csr = params
            .serialize_request(&signer)
            .map_err(|err| AcmeError::crypto(format!("generate managed CSR via AWS KMS: {err}")))?;
        let public_key_sha256 = super::spki_fingerprint_from_csr(csr.der())?;
        Ok(CsrArtifact {
            csr_der: csr.der().to_vec(),
            key_ref,
            identifiers: request.identifiers,
            external: false,
            public_key_sha256,
        })
    }

    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo> {
        self.ensure_own_key(key)?;
        let spki_der = self.fetch_public_key_spki(key.key_id.as_str()).await?;
        let (_, spki) = SubjectPublicKeyInfo::from_der(&spki_der)
            .map_err(|err| AcmeError::crypto(format!("parse KMS public key SPKI: {err}")))?;
        let spki_sha256 = super::sha256_hex(spki.raw);
        let spki_pem = ::pem::encode(&::pem::Pem::new("PUBLIC KEY", spki_der));
        Ok(PublicKeyInfo {
            key_ref: key.clone(),
            spki_sha256,
            spki_pem,
        })
    }

    async fn export(
        &self,
        key: &KeyRef,
        authorization: ExportAuthorization,
    ) -> Result<Option<SecretBytes>> {
        // The purpose of this provider is that private key material never
        // leaves KMS: export is always `None`, even with a granted
        // authorization, because there is nothing to export.
        self.ensure_own_key(key)?;
        let _ = authorization;
        Ok(None)
    }

    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome> {
        // Conservative probe: existence check only, never schedules deletion.
        self.ensure_own_key(key)?;
        match self
            .client
            .describe_key()
            .key_id(key.key_id.as_str())
            .send()
            .await
        {
            Ok(_) => Ok(DestroyOutcome::Refused),
            Err(err) => {
                let classified = classify_kms_error("DescribeKey", err);
                match classified {
                    AcmeError::NotFound(_) => Ok(DestroyOutcome::NotFound),
                    other => Err(other),
                }
            }
        }
    }

    async fn destroy_confirmed(
        &self,
        key: &KeyRef,
        authorization: DestroyAuthorization,
    ) -> Result<DestroyOutcome> {
        self.ensure_own_key(key)?;
        if !authorization.confirmed {
            tracing::warn!(
                key_id = %key.key_id,
                actor = %authorization.actor,
                "KMS key destroy refused: missing explicit confirmation"
            );
            return Ok(DestroyOutcome::Refused);
        }
        match self
            .client
            .schedule_key_deletion()
            .key_id(key.key_id.as_str())
            .pending_window_in_days(self.config.key_deletion_window_days)
            .send()
            .await
        {
            Ok(output) => {
                tracing::info!(
                    key_id = %key.key_id,
                    actor = %authorization.actor,
                    reason = %authorization.reason,
                    state = ?output.key_state(),
                    window_days = self.config.key_deletion_window_days,
                    "AWS KMS key deletion scheduled: key unusable now, material removed after the pending window"
                );
                Ok(DestroyOutcome::Destroyed)
            }
            Err(err) => {
                let classified = classify_kms_error("ScheduleKeyDeletion", err);
                match classified {
                    // Already gone (or id unknown): report honestly.
                    AcmeError::NotFound(_) => Ok(DestroyOutcome::NotFound),
                    other => Err(other),
                }
            }
        }
    }
}

/// Classifies an AWS KMS SDK error into an [`AcmeError`].
///
/// KMS error messages are service-generated and never contain key material,
/// signatures or credentials, so they are safe to surface; the raw SDK error
/// is only rendered for non-service (transport-level) failures.
fn classify_kms_error<E>(operation: &str, err: SdkError<E>) -> AcmeError
where
    E: ProvideErrorMetadata + fmt::Debug,
{
    let context = format!("AWS KMS {operation} failed");
    match &err {
        SdkError::TimeoutError(_) => AcmeError::timeout(context),
        SdkError::ServiceError(_) => {
            classify_service_code(operation, err.code(), err.message().unwrap_or(""))
        }
        // Construction failures, dispatch failures, malformed responses and
        // any future variant are transient transport-level problems.
        _ => AcmeError::transport(format!("{context}: {err}")),
    }
}

/// Code-table classification of a KMS service error.
fn classify_service_code(operation: &str, code: Option<&str>, message: &str) -> AcmeError {
    let context = format!("AWS KMS {operation} failed");
    match code {
        Some("NotFoundException") => AcmeError::not_found(format!("{context}: {message}")),
        Some(
            "ThrottlingException"
            | "TooManyRequestsException"
            | "LimitExceededException"
            | "RequestLimitExceeded",
        ) => AcmeError::RateLimited(None),
        Some("DependencyTimeoutException") => AcmeError::timeout(format!("{context}: {message}")),
        // Operator-actionable conditions: disabled key, pending deletion,
        // wrong region/ARN, insufficient KMS key policy, unsupported
        // operation, and friends. Fixing them requires an AWS-side change.
        Some(
            "DisabledException"
            | "KMSInvalidStateException"
            | "PendingDeletionException"
            | "InvalidArnException"
            | "InvalidGrantTokenException"
            | "InvalidKeyUsageException"
            | "InvalidMarkerException"
            | "MalformedPolicyDocumentException"
            | "NotAuthorizedException"
            | "UnsupportedOperationException"
            | "DryRunOperationException",
        ) => AcmeError::configuration(format!("{context}: {message}")),
        // KmsInternalException, KeyUnavailableException ("you can retry"),
        // unmodeled codes and missing codes are treated as transient.
        _ => AcmeError::transport(format!(
            "{context}: {}",
            if message.is_empty() {
                "unknown error"
            } else {
                message
            }
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
        PKCS_RSA_SHA256, PKCS_RSA_SHA512,
    };

    fn spki_der_of(key_pair: &KeyPair) -> Vec<u8> {
        let pem = key_pair.public_key_pem();
        let block = ::pem::parse(pem.as_bytes()).expect("parse public key PEM");
        block.contents().to_vec()
    }

    #[test]
    fn algorithm_mapping_covers_all_supported_algorithms() {
        let (spec, signing, rcgen_alg) =
            algorithm_mapping(KeyAlgorithm::EcP256).expect("EcP256 mapping");
        assert_eq!(spec, KeySpec::EccNistP256);
        assert_eq!(signing, SigningAlgorithmSpec::EcdsaSha256);
        assert_eq!(rcgen_alg, &PKCS_ECDSA_P256_SHA256);

        let (spec, signing, rcgen_alg) =
            algorithm_mapping(KeyAlgorithm::EcP384).expect("EcP384 mapping");
        assert_eq!(spec, KeySpec::EccNistP384);
        assert_eq!(signing, SigningAlgorithmSpec::EcdsaSha384);
        assert_eq!(rcgen_alg, &PKCS_ECDSA_P384_SHA384);

        let (spec, signing, rcgen_alg) =
            algorithm_mapping(KeyAlgorithm::EcP521).expect("EcP521 mapping");
        assert_eq!(spec, KeySpec::EccNistP521);
        assert_eq!(signing, SigningAlgorithmSpec::EcdsaSha512);
        assert_eq!(rcgen_alg, &PKCS_ECDSA_P521_SHA512);

        let (spec, signing, rcgen_alg) =
            algorithm_mapping(KeyAlgorithm::Rsa2048).expect("Rsa2048 mapping");
        assert_eq!(spec, KeySpec::Rsa2048);
        assert_eq!(signing, SigningAlgorithmSpec::RsassaPkcs1V15Sha256);
        assert_eq!(rcgen_alg, &PKCS_RSA_SHA256);

        let (spec, signing, rcgen_alg) =
            algorithm_mapping(KeyAlgorithm::Rsa4096).expect("Rsa4096 mapping");
        assert_eq!(spec, KeySpec::Rsa4096);
        assert_eq!(signing, SigningAlgorithmSpec::RsassaPkcs1V15Sha512);
        assert_eq!(rcgen_alg, &PKCS_RSA_SHA512);
    }

    #[test]
    fn algorithm_mapping_rejects_ed25519() {
        let outcome = algorithm_mapping(KeyAlgorithm::Ed25519);
        assert!(matches!(outcome, Err(AcmeError::InvalidInput(_))));
    }

    #[test]
    fn extracted_bits_match_rcgen_public_keys() {
        // For EC keys rcgen expects the raw uncompressed point and for RSA the
        // DER-encoded PKCS#1 RSAPublicKey; in both cases that is the SPKI BIT
        // STRING payload, which the extractor must return verbatim.
        let ecdsa = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 keygen");
        assert_eq!(
            extract_subject_public_key_bits(&spki_der_of(&ecdsa)).expect("extract P-256"),
            ecdsa.public_key_raw()
        );

        let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 keygen");
        assert_eq!(
            extract_subject_public_key_bits(&spki_der_of(&p384)).expect("extract P-384"),
            p384.public_key_raw()
        );

        let rsa = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .expect("RSA keygen");
        assert_eq!(
            extract_subject_public_key_bits(&spki_der_of(&rsa)).expect("extract RSA"),
            rsa.public_key_raw()
        );
    }

    #[test]
    fn extract_rejects_non_der_input() {
        let outcome = extract_subject_public_key_bits(b"not der");
        assert!(matches!(outcome, Err(AcmeError::Crypto(_))));
    }

    #[test]
    fn service_error_codes_are_classified() {
        assert!(matches!(
            classify_service_code("GetPublicKey", Some("NotFoundException"), "no such key"),
            AcmeError::NotFound(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("DisabledException"), "key disabled"),
            AcmeError::Configuration(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("KMSInvalidStateException"), "bad state"),
            AcmeError::Configuration(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("PendingDeletionException"), "pending"),
            AcmeError::Configuration(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("NotAuthorizedException"), "nope"),
            AcmeError::Configuration(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("ThrottlingException"), "slow down"),
            AcmeError::RateLimited(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("LimitExceededException"), "quota"),
            AcmeError::RateLimited(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("DependencyTimeoutException"), "timeout"),
            AcmeError::Timeout(_)
        ));
        // Unmodeled and unknown codes are transient.
        assert!(matches!(
            classify_service_code("Sign", Some("KmsInternalException"), "internal"),
            AcmeError::Transport(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", Some("SomethingNew"), "mystery"),
            AcmeError::Transport(_)
        ));
        assert!(matches!(
            classify_service_code("Sign", None, ""),
            AcmeError::Transport(_)
        ));
    }

    #[test]
    fn config_validates_deletion_window_and_provider_id() {
        let mut config = KmsKeyProviderConfig::default();
        assert!(config.validate().is_ok());

        config.key_deletion_window_days = 6;
        assert!(matches!(config.validate(), Err(AcmeError::InvalidInput(_))));
        config.key_deletion_window_days = 31;
        assert!(matches!(config.validate(), Err(AcmeError::InvalidInput(_))));

        config.key_deletion_window_days = 30;
        config.provider_id = String::new();
        assert!(matches!(config.validate(), Err(AcmeError::InvalidInput(_))));
    }

    #[test]
    fn provider_debug_output_is_redacted() {
        let config = KmsKeyProviderConfig {
            endpoint_url: Some("http://127.0.0.1:1".to_string()),
            ..KmsKeyProviderConfig::default()
        };
        let sdk_config = aws_sdk_kms::config::Config::builder()
            .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_kms::config::Credentials::new(
                "secret-access-key-id",
                "secret-secret-key",
                None,
                None,
                "kms-unit-test",
            ))
            .region(aws_sdk_kms::config::Region::new("us-east-1"))
            .build();
        let provider =
            KmsKeyProvider::from_client(config, aws_sdk_kms::Client::from_conf(sdk_config))
                .expect("provider");
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("kms-aws"),
            "provider id must appear: {debug}"
        );
        assert!(
            !debug.contains("secret-access-key-id"),
            "credentials must not appear in Debug: {debug}"
        );
        assert!(
            !debug.contains("secret-secret-key"),
            "credentials must not appear in Debug: {debug}"
        );
    }
}

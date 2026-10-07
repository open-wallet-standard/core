//! Midnight transaction proving — local zkir or remote proof server.
//!
//! [`Prover`] defaults to in-process proving via `zkir_v2`'s [`LocalProvingProvider`]: it resolves
//! dust/zswap proving + verifier keys (and their IR) from a caller-supplied directory — the
//! wallet's vault-rooted `chains/midnight/proving-keys` store (see `cache_io::proving_keys_dir`) —
//! fetching any missing files on demand.
//!
//! When `rpc["midnight:<net>:prover"]` is set, [`Prover::remote`] posts `/check` and `/prove` to
//! that proof server instead. Builtin circuit keys are supplied by the server; non-builtin
//! locations still resolve from the local key store when one is attached.
//!
//! Remote proving sends proof preimages (including private witnesses) to the configured server —
//! only point `:prover` at a host you trust.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use midnight_base_crypto::data_provider::{self, MidnightDataProvider};
use midnight_base_crypto::rng::SplittableRng as _;
use midnight_ledger::structure::{ProofPreimageVersioned, ProofVersioned};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, Proof, ProofPreimage, ProvingKeyMaterial, ProvingProvider, Resolver, WrappedIr,
};
use zkir_v2::LocalProvingProvider;

/// Default HTTP timeout for a single proof-server `/check` or `/prove` call (matches midnight-js).
const PROOF_SERVER_TIMEOUT: Duration = Duration::from_secs(300);

const BUILTIN_KEY_LOCATIONS: &[&str] = &[
    "midnight/zswap/spend",
    "midnight/zswap/output",
    "midnight/zswap/sign",
    "midnight/dust/spend",
];

static PROOF_SERVER_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

/// Shared HTTP client for Midnight proof-server `/check` and `/prove` (long timeout).
fn proof_server_http_client() -> &'static reqwest::Client {
    PROOF_SERVER_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(PROOF_SERVER_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

#[derive(Clone)]
enum ProverBackend {
    Local {
        /// Boxed: `StdRng` dwarfs the remote variant's fields, and a `Prover` is mostly passed
        /// around as the enum, so inlining it would pad every `Remote` prover by ~200 bytes.
        rng: Box<StdRng>,
        provider: MidnightDataProvider,
    },
    Remote {
        base_url: reqwest::Url,
        /// Local key store for non-builtin circuits; builtins are served by the proof server.
        provider: Option<MidnightDataProvider>,
    },
}

/// Proving provider for Midnight authorize / prove paths.
///
/// Construct with [`Prover::new`] (local) or [`Prover::remote`] (HTTP proof server). Prefer
/// [`crate::balance_tx::midnight_prover`], which picks the backend from config.
#[derive(Clone)]
pub struct Prover {
    backend: ProverBackend,
}

struct KeyResolver(MidnightDataProvider);

impl Resolver for KeyResolver {
    async fn resolve_key(&self, key: KeyLocation) -> std::io::Result<Option<ProvingKeyMaterial>> {
        let file_root: String = match &*key.0 {
            "midnight/dust/spend" => format!("dust/{}/spend", midnight_ledger_static::version!()),
            "midnight/zswap/spend" => format!("zswap/{}/spend", midnight_ledger_static::version!()),
            "midnight/zswap/output" => {
                format!("zswap/{}/output", midnight_ledger_static::version!())
            }
            "midnight/zswap/sign" => format!("zswap/{}/sign", midnight_ledger_static::version!()),
            _ => return Ok(None),
        };

        fn read_to_vec(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
            let mut res = Vec::new();
            reader.read_to_end(&mut res)?;
            Ok(res)
        }

        let prover_key = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.prover"),
                    &format!("failed to find prover key {file_root}.prover"),
                )
                .await?,
        )?;
        let verifier_key = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.verifier"),
                    &format!("failed to find verifier key {file_root}.verifier"),
                )
                .await?,
        )?;
        let ir_source = read_to_vec(
            &mut self
                .0
                .get_file(
                    &format!("{file_root}.bzkir"),
                    &format!("failed to find IR {file_root}.bzkir"),
                )
                .await?,
        )?;

        Ok(Some(ProvingKeyMaterial {
            ir_source,
            prover_key,
            verifier_key,
        }))
    }
}

fn data_provider_for_dir(dir: std::path::PathBuf) -> MidnightDataProvider {
    MidnightDataProvider {
        fetch_mode: data_provider::FetchMode::OnDemand,
        base_url: data_provider::BASE_URL.clone(),
        output_mode: data_provider::OutputMode::Log,
        expected_data: {
            let mut v = midnight_ledger::dust::DUST_EXPECTED_FILES.to_vec();
            v.extend_from_slice(midnight_zswap::ZSWAP_EXPECTED_FILES);
            v
        },
        dir,
    }
}

fn is_builtin_key(loc: &KeyLocation) -> bool {
    BUILTIN_KEY_LOCATIONS.contains(&loc.0.as_ref())
}

/// Parse and validate a proof-server base URL (`http` / `https` only).
fn parse_proof_server_url(url: &str) -> Result<reqwest::Url, std::io::Error> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(std::io::Error::other(
            "Midnight proof server URL must not be empty",
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|e| {
        std::io::Error::other(format!("invalid Midnight proof server URL '{url}': {e}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        other => Err(std::io::Error::other(format!(
            "invalid Midnight proof server URL scheme (expected http:// or https://): {other}"
        ))),
    }
}

/// Append `/check` or `/prove` to a proof-server base URL, preserving path prefixes and query
/// strings (same join rules as midnight-js `buildEndpointUrl`).
fn proof_server_endpoint(base_url: &reqwest::Url, endpoint: &str) -> reqwest::Url {
    let mut url = base_url.clone();
    let pathname = url.path().trim_end_matches('/');
    url.set_path(&format!("{pathname}{endpoint}"));
    url
}

impl Prover {
    /// Build a local prover that resolves circuit keys from `dir`, fetching any missing files from
    /// Midnight's data provider on demand. `dir` is the wallet's proving-key store; derive it with
    /// `cache_io::proving_keys_dir`.
    pub fn new(dir: std::path::PathBuf) -> Self {
        Self {
            backend: ProverBackend::Local {
                rng: Box::new(StdRng::from_entropy()),
                provider: data_provider_for_dir(dir),
            },
        }
    }

    /// Build a prover that posts `/check` and `/prove` to a Midnight proof server.
    ///
    /// Builtin zswap/dust keys are supplied by the server. When `keys_dir` is set, non-builtin
    /// circuit locations are resolved from that store (same layout as [`Prover::new`]).
    ///
    /// Proof preimages (private witnesses) are sent to `base_url` — use only a trusted host.
    pub fn remote(
        base_url: impl AsRef<str>,
        keys_dir: Option<std::path::PathBuf>,
    ) -> Result<Self, std::io::Error> {
        let base_url = parse_proof_server_url(base_url.as_ref())?;
        Ok(Self {
            backend: ProverBackend::Remote {
                base_url,
                provider: keys_dir.map(data_provider_for_dir),
            },
        })
    }

    async fn resolve_remote_key_material(
        provider: &Option<MidnightDataProvider>,
        loc: &KeyLocation,
    ) -> Result<Option<ProvingKeyMaterial>, anyhow::Error> {
        if is_builtin_key(loc) {
            return Ok(None);
        }
        let Some(provider) = provider else {
            anyhow::bail!(
                "proof server requires local proving keys for non-builtin circuit '{}', \
                 but no proving-key directory is available",
                loc.0
            );
        };
        KeyResolver(provider.clone())
            .resolve_key(loc.clone())
            .await?
            .ok_or_else(|| anyhow::anyhow!("failed to find key '{}'", loc.0))
            .map(Some)
    }

    async fn check_request_body(
        provider: &Option<MidnightDataProvider>,
        preimage: &ProofPreimage,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let ir = Self::resolve_remote_key_material(provider, &preimage.key_location)
            .await?
            .map(|data| WrappedIr(data.ir_source));
        let versioned = ProofPreimageVersioned::V2(Arc::new(preimage.clone()));
        let mut res = Vec::new();
        tagged_serialize(&(versioned, ir), &mut res)?;
        Ok(res)
    }

    async fn proving_request_body(
        provider: &Option<MidnightDataProvider>,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let data = Self::resolve_remote_key_material(provider, &preimage.key_location).await?;
        let versioned = ProofPreimageVersioned::V2(Arc::new(preimage.clone()));
        let mut res = Vec::new();
        tagged_serialize(&(versioned, data, overwrite_binding_input), &mut res)?;
        Ok(res)
    }

    async fn post_proof_server(url: reqwest::Url, body: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        let resp = proof_server_http_client()
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("proof server error ({status}): {text}")
        }
    }
}

impl ProvingProvider for Prover {
    async fn check(&self, preimage: &ProofPreimage) -> Result<Vec<Option<usize>>, anyhow::Error> {
        match &self.backend {
            ProverBackend::Local { provider, .. } => {
                let resolver = KeyResolver(provider.clone());
                let lp = LocalProvingProvider {
                    rng: StdRng::from_entropy(),
                    resolver: &resolver,
                    params: provider,
                };
                lp.check(preimage).await
            }
            ProverBackend::Remote { base_url, provider } => {
                let ser = Self::check_request_body(provider, preimage).await?;
                let url = proof_server_endpoint(base_url, "/check");
                let bytes = Self::post_proof_server(url, ser).await?;
                let res: Vec<Option<u64>> = tagged_deserialize(&mut bytes.as_slice())?;
                Ok(res.into_iter().map(|i| i.map(|i| i as usize)).collect())
            }
        }
    }

    async fn prove(
        self,
        preimage: &ProofPreimage,
        overwrite_binding_input: Option<Fr>,
    ) -> Result<Proof, anyhow::Error> {
        match self.backend {
            ProverBackend::Local { mut rng, provider } => {
                let resolver = KeyResolver(provider.clone());
                let lp = LocalProvingProvider {
                    rng: rng.split(),
                    resolver: &resolver,
                    params: &provider,
                };
                lp.prove(preimage, overwrite_binding_input).await
            }
            ProverBackend::Remote { base_url, provider } => {
                let ser = Self::proving_request_body(&provider, preimage, overwrite_binding_input)
                    .await?;
                let url = proof_server_endpoint(&base_url, "/prove");
                let bytes = Self::post_proof_server(url, ser).await?;
                let proof: ProofVersioned = tagged_deserialize(&mut bytes.as_slice())?;
                match proof {
                    ProofVersioned::V2(proof) => Ok(proof),
                    _ => anyhow::bail!("proof server returned an unsupported proof version"),
                }
            }
        }
    }

    fn split(&mut self) -> Self {
        match &mut self.backend {
            ProverBackend::Local { rng, provider } => Self {
                backend: ProverBackend::Local {
                    rng: Box::new(rng.split()),
                    provider: provider.clone(),
                },
            },
            ProverBackend::Remote { base_url, provider } => Self {
                backend: ProverBackend::Remote {
                    base_url: base_url.clone(),
                    provider: provider.clone(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_rejects_empty_and_non_http_urls() {
        assert!(Prover::remote("", None).is_err());
        assert!(Prover::remote("   ", None).is_err());
        assert!(Prover::remote("ftp://proof.example", None).is_err());
        assert!(Prover::remote("localhost:6300", None).is_err());
    }

    #[test]
    fn remote_accepts_http_urls() {
        assert!(Prover::remote("http://127.0.0.1:6300", None).is_ok());
        assert!(Prover::remote("https://proof.example/api/v1/", None).is_ok());
        assert!(Prover::remote("http://127.0.0.1:6300?token=abc", None).is_ok());
    }

    #[test]
    fn proof_server_endpoint_joins_path_and_preserves_query() {
        let root = reqwest::Url::parse("http://localhost:6300/").unwrap();
        assert_eq!(
            proof_server_endpoint(&root, "/prove").as_str(),
            "http://localhost:6300/prove"
        );

        let prefixed = reqwest::Url::parse("http://localhost:6300/api/v1").unwrap();
        assert_eq!(
            proof_server_endpoint(&prefixed, "/check").as_str(),
            "http://localhost:6300/api/v1/check"
        );

        let with_query = reqwest::Url::parse("http://localhost:6300?token=abc").unwrap();
        assert_eq!(
            proof_server_endpoint(&with_query, "/prove").as_str(),
            "http://localhost:6300/prove?token=abc"
        );
    }
}

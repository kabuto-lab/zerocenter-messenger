//! Default bootstrap discovery.
//!
//! Without any `--bootstrap` or `--relay` flags, a fresh ME55 install
//! needs a way to find SOME peer in order to join the network. This
//! module hands the node a list of dial-able multiaddrs at startup.
//!
//! Resolution order (each source is queried; results merged + deduped):
//!
//! 1. **CLI `--bootstrap`** (highest priority, user override; handled
//!    in `entry.rs` / `node.rs`, not here).
//! 2. **Local PEX cache** — last N "good" peers we successfully
//!    exchanged with, persisted in `peer_cache` SQLite table.
//! 3. **Signed HTTPS manifest** at
//!    `https://bootstrap.me55.network/manifest.json`. Ed25519 signature
//!    over the canonical JSON bytes verified against the pinned
//!    [`MAINTAINER_PUBKEY`] before any entries are used. Soft failure:
//!    network unreachable → skip, log, fall through.
//! 4. **DNSADDR TXT lookup** at
//!    `_dnsaddr.bootstrap.me55.network`. Treated as best-effort
//!    discovery — entries from this source are NOT signature-verified
//!    (DNS doesn't carry our signature), so they are merged in only
//!    when other sources have provided no peers OR the user opts in
//!    via a future `--dnsaddr-bootstrap` flag (not yet wired). For
//!    now: helpful fallback, never primary.
//! 5. **Hardcoded fallback** — [`DEFAULT_BOOTSTRAPS`]. Updated per
//!    release; deliberately a small set so the binary doesn't carry a
//!    stale 50-entry list.

use anyhow::{anyhow, Result};
use libp2p::Multiaddr;
use serde::Deserialize;

/// Hardcoded default bootstrap+relay multiaddrs. Empty placeholder in
/// development — populated for releases once we have public nodes
/// (Beget VPS + Oracle Cloud Free) running with stable PeerIds.
///
/// Each entry must include the `/p2p/<PeerId>` suffix so it can be
/// added to the Kademlia routing table without an extra resolution
/// round-trip.
pub const DEFAULT_BOOTSTRAPS: &[&str] = &[
    // bootstrap-1 — Beget VPS (RU), provisioned 2026-05-24 per
    // BEGET_SETUP.md. IP-pinned for now; will move behind
    // /dns4/bootstrap-1.me55.network once DNS is set up.
    "/ip4/45.9.40.37/tcp/4001/p2p/12D3KooWQ643AEmTK2CHDmhLAgXQ1oCZ12pNZHVvGgrrUTEVcPD9",
    // Future slots (uncomment + replace when added):
    // "/dns4/bootstrap-2.me55.network/tcp/4001/p2p/12D3KooW...",
    // "/dns4/bootstrap-3.me55.network/tcp/4001/p2p/12D3KooW...",
];

/// Pinned Ed25519 public key of the project maintainer. Used to verify
/// the detached signature on the fetched bootstrap manifest. Placeholder
/// of all-zeros pre-release; once the maintainer keypair is generated
/// via `tools/sign-manifest.sh keygen` the real pubkey gets pasted here
/// and the binary is rebuilt.
pub const MAINTAINER_PUBKEY: [u8; 32] = [0u8; 32];

/// Default DNSADDR TXT domain. Queried via the system DNS resolver
/// (`hickory-resolver`). Resolution failure is treated as "no entries"
/// — fine on hostile / DNS-blocked networks.
pub const DEFAULT_DNSADDR_DOMAIN: &str = "_dnsaddr.bootstrap.me55.network";

/// Default URL for the signed HTTPS manifest.
pub const DEFAULT_MANIFEST_URL: &str = "https://bootstrap.me55.network/manifest.json";

/// One entry in the bootstrap manifest.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BootstrapEntry {
    /// Full multiaddr including `/p2p/<PeerId>` suffix.
    pub multiaddr: String,
    /// ISO 3166 region code(s) for transparency about jurisdiction.
    /// Not load-bearing; informational for users in adversarial nets.
    #[serde(default)]
    pub regions: Vec<String>,
    /// Unix timestamp when this entry was first added to the manifest.
    /// Surface for monitoring / staleness checks.
    #[serde(default)]
    pub added_at: i64,
}

/// Canonical signed bootstrap manifest. Wire shape is JSON; signature
/// is detached and verified against the pinned [`MAINTAINER_PUBKEY`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BootstrapManifest {
    /// Schema version. Bump when the JSON shape changes incompatibly.
    pub version: u32,
    /// When the maintainer signed this manifest. Manifests older than
    /// some sanity bound (~30 days) get rejected to bound the damage
    /// of an old captured manifest being replayed.
    pub issued_at: i64,
    /// Drop-dead expiry — clients that fetch a manifest past this time
    /// fall back to the hardcoded list with a warn log.
    pub expires_at: i64,
    /// Effective bootstrap list.
    pub bootstraps: Vec<BootstrapEntry>,
    /// Minimum client version the maintainer asserts is safe to run
    /// against this network. Clients older than this should print a
    /// loud upgrade-recommended warning. Empty = no minimum.
    #[serde(default)]
    pub min_client_version: String,
}

/// Reasonable cap on manifest size. The signed JSON has no reason to
/// exceed this; bounding the fetch body protects against a hostile
/// manifest host trying to OOM us.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Reasonable cap on staleness: refuse to honor a manifest issued
/// more than this many seconds ago, even if its `expires_at` says
/// otherwise (defence against a manifest with an absurdly distant
/// expiry signed long ago by a maintainer key that has since rotated).
const MAX_MANIFEST_AGE_SECS: i64 = 90 * 24 * 3600;

/// Parse [`DEFAULT_BOOTSTRAPS`] into `Multiaddr` values. Entries that
/// fail to parse are silently skipped — they're our own constants, so
/// a panic here would just kill startup for an obviously wrong build.
/// Returns an empty vec while [`DEFAULT_BOOTSTRAPS`] is empty.
pub fn hardcoded_defaults() -> Vec<Multiaddr> {
    DEFAULT_BOOTSTRAPS
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// DNSADDR lookup. Resolves TXT records at `domain` and parses each
/// value as `dnsaddr=<multiaddr>` per the libp2p convention. Returns
/// an empty vec on any error (network unreachable, NXDOMAIN, parse
/// failure for every entry, etc) — DNS-blocked environments are
/// expected; we just fall through to the hardcoded list.
///
/// Async because hickory-resolver wants an async runtime; ME55 startup
/// is already inside tokio.
pub async fn dnsaddr_lookup(domain: &str) -> Vec<Multiaddr> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    // Default to system resolver config — `from_system_conf` may fail
    // on platforms without /etc/resolv.conf or equivalent. Fall back
    // to Cloudflare DoH endpoints in that case (no extra dep needed:
    // hickory ships `ResolverConfig::cloudflare()` etc).
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => {
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
        }
    };
    let Ok(response) = resolver.txt_lookup(domain).await else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for record in response.iter() {
        for chunk in record.txt_data() {
            // TXT values can be split across multiple <character-string>
            // chunks; concatenate then parse.
            let s = std::str::from_utf8(chunk).unwrap_or("");
            if let Some(addr_str) = s.strip_prefix("dnsaddr=") {
                if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                    out.push(addr);
                }
            }
        }
    }
    out
}

/// Fetch the signed HTTPS manifest, verify the detached signature
/// against [`MAINTAINER_PUBKEY`], and return the parsed
/// [`BootstrapManifest`] on success. Soft failure: returns Err so the
/// caller can log and fall through.
///
/// The signature is fetched from `<url>.sig` (raw 64 bytes).
pub async fn fetch_signed_manifest(
    url: &str,
    pinned_pubkey: &[u8; 32],
) -> Result<BootstrapManifest> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Refuse to do anything if the pinned key is the all-zero
    // placeholder — that would mean accepting a manifest signed by
    // anybody, which is worse than no manifest at all.
    if pinned_pubkey == &[0u8; 32] {
        return Err(anyhow!(
            "MAINTAINER_PUBKEY is the placeholder zero — skipping manifest fetch"
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Manifest body
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("manifest fetch HTTP {}", resp.status()));
    }
    let body = resp.bytes().await?;
    if body.len() > MAX_MANIFEST_BYTES {
        return Err(anyhow!(
            "manifest body too large: {} > {}",
            body.len(),
            MAX_MANIFEST_BYTES
        ));
    }

    // Detached signature, raw 64 bytes
    let sig_url = format!("{}.sig", url);
    let sig_resp = client.get(&sig_url).send().await?;
    if !sig_resp.status().is_success() {
        return Err(anyhow!("manifest sig fetch HTTP {}", sig_resp.status()));
    }
    let sig_bytes = sig_resp.bytes().await?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!(
            "manifest sig wrong length: got {} expected 64",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let verifying = VerifyingKey::from_bytes(pinned_pubkey)
        .map_err(|e| anyhow!("pinned pubkey decode: {}", e))?;
    let sig = Signature::from_bytes(&sig_arr);
    verifying
        .verify(&body, &sig)
        .map_err(|_| anyhow!("manifest signature did not verify against pinned pubkey"))?;

    // Parse + sanity-check
    let manifest: BootstrapManifest = serde_json::from_slice(&body)
        .map_err(|e| anyhow!("manifest JSON parse: {}", e))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if manifest.expires_at < now {
        return Err(anyhow!(
            "manifest expired at {} (now {})",
            manifest.expires_at,
            now
        ));
    }
    if (now - manifest.issued_at) > MAX_MANIFEST_AGE_SECS {
        return Err(anyhow!(
            "manifest issued_at too old: {} (now {}, max age {}s)",
            manifest.issued_at,
            now,
            MAX_MANIFEST_AGE_SECS
        ));
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_parses_cleanly() {
        for s in DEFAULT_BOOTSTRAPS {
            assert!(
                s.parse::<Multiaddr>().is_ok(),
                "default bootstrap entry {:?} doesn't parse",
                s
            );
        }
    }

    #[test]
    fn hardcoded_defaults_matches_constant_count() {
        assert_eq!(hardcoded_defaults().len(), DEFAULT_BOOTSTRAPS.len());
    }

    #[test]
    fn manifest_json_parses() {
        let json = br#"{
            "version": 1,
            "issued_at": 1748016000,
            "expires_at": 1750608000,
            "bootstraps": [
                {
                    "multiaddr": "/dns4/bootstrap-1.me55.network/tcp/4001/p2p/12D3KooWQYhTKfcv2VyG6tBzqGUaTQbqM7sBJG9PsbcsW7BCsTvT",
                    "regions": ["RU"],
                    "added_at": 1748000000
                }
            ],
            "min_client_version": ""
        }"#;
        let m: BootstrapManifest = serde_json::from_slice(json).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.bootstraps.len(), 1);
        assert_eq!(m.bootstraps[0].regions, vec!["RU".to_string()]);
    }

    #[test]
    fn placeholder_pubkey_refuses_to_verify() {
        // Sanity: while MAINTAINER_PUBKEY is all zeros, calling
        // fetch_signed_manifest must refuse rather than accept
        // arbitrary signed-by-anyone manifests.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(fetch_signed_manifest(
                "http://127.0.0.1:1/manifest.json",
                &[0u8; 32],
            ))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("placeholder zero"),
            "expected placeholder refusal, got: {}",
            err
        );
    }
}

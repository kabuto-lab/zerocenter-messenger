//! `me55-tools` — maintainer-side CLI for the Phase 1.A.2 bootstrap
//! manifest signing flow.
//!
//! Subcommands:
//!   me55-tools keygen   --out PATH
//!       Generate a fresh Ed25519 maintainer keypair, save the 32-byte
//!       private key to PATH (mode 0600 on unix). Run ONCE.
//!
//!   me55-tools pubkey   --in PATH
//!       Print the Ed25519 public key (hex) for pasting into
//!       `src/network/bootstrap.rs::MAINTAINER_PUBKEY`. After pasting,
//!       rebuild the binary so clients verify manifests against this
//!       pubkey.
//!
//!   me55-tools sign     --key PATH --in MANIFEST_JSON
//!       Compute a detached Ed25519 signature over the raw bytes of
//!       MANIFEST_JSON, write the 64-byte signature to
//!       MANIFEST_JSON.sig. The runtime fetches both files separately
//!       and verifies the sig against MAINTAINER_PUBKEY.
//!
//!   me55-tools verify   --pubkey HEX --in MANIFEST_JSON
//!       Verify a manifest file's signature locally. Useful for CI
//!       checks before publishing the manifest to the HTTPS endpoint.
//!
//! The maintainer private key is sensitive: anyone with it can sign a
//! malicious manifest pointing every fresh ME55 install at adversary
//! bootstrap nodes. Store offline (USB, paper backup) and consider
//! threshold-signing (e.g. frost-ed25519) before broad release.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "me55-tools",
    about = "Maintainer-side tools for the ME55 bootstrap manifest",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a fresh Ed25519 maintainer keypair, write private to file.
    Keygen {
        /// Path to write the 32-byte private key (raw bytes).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the pubkey of a saved private key as 64-char hex.
    Pubkey {
        /// Path to the private key file produced by `keygen`.
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
    },
    /// Detached-sign a manifest file with a private key.
    Sign {
        /// Path to private key file.
        #[arg(long)]
        key: PathBuf,
        /// Path to manifest JSON (signed verbatim; .sig written alongside).
        #[arg(long, value_name = "MANIFEST_JSON")]
        r#in: PathBuf,
    },
    /// Verify a manifest + .sig pair against a hex-encoded pubkey.
    Verify {
        /// 64-char hex Ed25519 pubkey to verify against.
        #[arg(long)]
        pubkey: String,
        /// Path to manifest JSON; .sig must exist alongside.
        #[arg(long, value_name = "MANIFEST_JSON")]
        r#in: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => keygen(out),
        Cmd::Pubkey { r#in } => pubkey(r#in),
        Cmd::Sign { key, r#in } => sign_manifest(key, r#in),
        Cmd::Verify { pubkey, r#in } => verify_manifest(pubkey, r#in),
    }
}

fn keygen(out: PathBuf) -> Result<()> {
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let sk_bytes = sk.to_bytes();

    // Restrict permissions before writing the key on unix. On Windows
    // we just write — file ACL inheritance picks up the user-only default.
    std::fs::write(&out, sk_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&out)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&out, perms)?;
    }
    let vk = sk.verifying_key();
    println!("Generated maintainer keypair");
    println!("Private key saved to: {}", out.display());
    println!("Public key (paste into src/network/bootstrap.rs::MAINTAINER_PUBKEY):");
    println!("  {}", hex::encode(vk.to_bytes()));
    println!();
    println!("As a Rust constant:");
    println!("  pub const MAINTAINER_PUBKEY: [u8; 32] = [");
    let bytes = vk.to_bytes();
    for chunk in bytes.chunks(8) {
        let line: Vec<String> = chunk.iter().map(|b| format!("0x{:02X}", b)).collect();
        println!("      {},", line.join(", "));
    }
    println!("  ];");
    Ok(())
}

fn pubkey(path: PathBuf) -> Result<()> {
    let sk = load_private(&path)?;
    let vk = sk.verifying_key();
    println!("{}", hex::encode(vk.to_bytes()));
    Ok(())
}

fn sign_manifest(key: PathBuf, input: PathBuf) -> Result<()> {
    let sk = load_private(&key)?;
    let body = std::fs::read(&input)?;
    let sig: Signature = sk.sign(&body);
    let sig_path = sig_path_for(&input);
    std::fs::write(&sig_path, sig.to_bytes())?;
    println!(
        "Signed {} ({} bytes) → {} (64 bytes)",
        input.display(),
        body.len(),
        sig_path.display()
    );
    Ok(())
}

fn verify_manifest(pubkey_hex: String, input: PathBuf) -> Result<()> {
    let pk_bytes = hex::decode(pubkey_hex.trim())
        .map_err(|e| anyhow!("pubkey hex decode: {}", e))?;
    if pk_bytes.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes (got {})", pk_bytes.len()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| anyhow!("pubkey decode: {}", e))?;

    let body = std::fs::read(&input)?;
    let sig_path = sig_path_for(&input);
    let sig_bytes = std::fs::read(&sig_path)?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("sig must be 64 bytes (got {})", sig_bytes.len()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    vk.verify(&body, &sig)
        .map_err(|_| anyhow!("signature did NOT verify"))?;
    println!(
        "OK: {} ({} bytes) verified against pubkey {}",
        input.display(),
        body.len(),
        hex::encode(vk.to_bytes())
    );
    Ok(())
}

fn load_private(path: &PathBuf) -> Result<SigningKey> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "private key file must be exactly 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

fn sig_path_for(input: &PathBuf) -> PathBuf {
    let mut out = input.clone();
    let mut name = input.file_name().unwrap_or_default().to_owned();
    name.push(".sig");
    out.set_file_name(name);
    out
}

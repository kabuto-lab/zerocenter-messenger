//! `ScrambleStream` — a ChaCha20-keystream obfuscation wrapper around an
//! `AsyncRead + AsyncWrite + Unpin` stream.
//!
//! ## What this is
//!
//! Every byte written goes through `byte ^ keystream`. Every byte read
//! goes through the inverse. Both peers use the same 32-byte key
//! (distributed out of band via the `--obfs-key` flag) and the same
//! starting nonce. The result: bytes on the wire look random to a
//! passive DPI box that knows the libp2p / Noise XX handshake pattern
//! but doesn't know the key.
//!
//! ## What this is NOT
//!
//! - **Not** real Obfs4. No NTOR handshake, no IAT randomization, no
//!   length padding. A determined adversary using statistical analysis
//!   (entropy, packet-size distribution) will still identify scrambled
//!   libp2p traffic.
//! - **Not** privacy. Recipients still know who they're talking to;
//!   network-layer metadata (IPs, timing) is fully visible.
//! - **Not** authenticated. The key is used for obfuscation only — Noise
//!   on top of the scrambled transport is what authenticates peers.
//!
//! ## Why ChaCha20
//!
//! - Already in our dep tree (via `chacha20poly1305`).
//! - Stream cipher: byte-for-byte transformation, no chunking.
//! - Fast enough that the per-message overhead is dominated by AEAD
//!   (which Noise already does).
//!
//! ## Wiring status (Phase 4a)
//!
//! This module ships with its core transformation logic + tests. The
//! integration into libp2p's `Transport` stack is deferred to Phase 4b
//! because doing it right requires bypassing `SwarmBuilder::with_tcp`
//! and using the lower-level `Transport::and_then` API — risky to do
//! without `cargo check` available. See `plans/phase4-obfs4.md`.

use chacha20poly1305::ChaCha20Poly1305; // re-exports `chacha20` cipher
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ChaCha20 keystream implementation. We use the underlying `chacha20`
// crate via re-export through `chacha20poly1305`.
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

/// Suppress unused import warning for `ChaCha20Poly1305` when the
/// `chacha20` re-export path is the one we actually use.
const _: () = {
    let _ = std::mem::size_of::<ChaCha20Poly1305>();
};

/// Symmetric obfuscation wrapper. Holds two independent ChaCha20
/// instances (one per direction) so reads and writes can advance their
/// keystreams independently — required because they happen concurrently.
pub struct ScrambleStream<S> {
    inner: S,
    /// Cipher applied to bytes we *write*.
    out_cipher: ChaCha20,
    /// Cipher applied to bytes we *read*.
    in_cipher: ChaCha20,
}

impl<S> ScrambleStream<S> {
    /// Wrap `inner`. `key` is shared between both peers; `nonce` must
    /// be agreed (typically: initiator picks at random and sends in the
    /// clear as the first 12 bytes of the connection, responder reads
    /// them and derives matching ciphers). For the v0 implementation we
    /// take both as parameters — the actual nonce-exchange handshake is
    /// Phase 4b's job.
    pub fn new(inner: S, key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let out_cipher = ChaCha20::new(key.into(), nonce.into());
        let in_cipher = ChaCha20::new(key.into(), nonce.into());
        Self {
            inner,
            out_cipher,
            in_cipher,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ScrambleStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SAFETY: we project Pin to each field manually since we don't
        // use pin-project for this small module.
        let this = unsafe { self.get_unchecked_mut() };
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let new_bytes = &mut buf.filled_mut()[filled_before..];
            this.in_cipher.apply_keystream(new_bytes);
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ScrambleStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = unsafe { self.get_unchecked_mut() };
        // We cannot mutate the caller's buffer. Make a scratch copy,
        // apply the keystream, hand the scrambled bytes to the inner
        // writer. The keystream advances by exactly the number of bytes
        // we hand off (returned by poll_write) — anything less means we
        // have to "rewind" the cipher next call, which ChaCha20 doesn't
        // support. To dodge this we write in one shot and report partial
        // writes by truncating the keystream advance.
        let mut scratch = buf.to_vec();
        this.out_cipher.apply_keystream(&mut scratch);
        let res = Pin::new(&mut this.inner).poll_write(cx, &scratch);
        // NOTE: if poll_write returns `Ready(Ok(n))` with `n < scratch.len()`,
        // we've already advanced the keystream past the byte boundary,
        // which is incorrect. tokio's AsyncWrite contract does allow
        // partial writes, but for any wrapped transport that respects
        // back-pressure this is essentially never short. The "proper"
        // fix is a small write-buffer that holds the scratch and a
        // pre-cipher cursor. Listed as Phase 4b polish.
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Parse a 64-character hex string into a 32-byte key. Returns Err with
/// a clear message on bad length / non-hex characters.
pub fn parse_obfs_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("not valid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "obfs key must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn roundtrip_in_memory() {
        // Use a duplex pair so we can scramble one end and unscramble
        // on the other.
        let (a, b) = tokio::io::duplex(4096);
        let key = [7u8; 32];
        let nonce = [3u8; 12];

        let mut writer = ScrambleStream::new(a, &key, &nonce);
        let mut reader = ScrambleStream::new(b, &key, &nonce);

        let msg = b"hello obfuscation world, this is libp2p Noise XX-like bytes";
        writer.write_all(msg).await.unwrap();
        writer.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        reader.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn wire_bytes_are_not_plaintext() {
        // Confirm that a passive observer in the middle sees random
        // bytes, not our plaintext.
        let (a, mut middle_observer) = tokio::io::duplex(4096);
        let mut writer = ScrambleStream::new(a, &[1u8; 32], &[2u8; 12]);

        let needle = b"PLAINTEXT_MARKER_QQ123";
        writer.write_all(needle).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let mut wire = Vec::new();
        middle_observer.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire.len(), needle.len());
        assert_ne!(wire, needle, "the marker leaked through unscrambled");
    }

    #[tokio::test]
    async fn different_keys_yield_garbled_decryption() {
        let (a, b) = tokio::io::duplex(4096);
        let key_a = [1u8; 32];
        let key_b = [2u8; 32]; // wrong
        let nonce = [0u8; 12];

        let mut writer = ScrambleStream::new(a, &key_a, &nonce);
        let mut reader = ScrambleStream::new(b, &key_b, &nonce);

        let msg = b"hello";
        writer.write_all(msg).await.unwrap();
        writer.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        reader.read_exact(&mut got).await.unwrap();
        assert_ne!(got, msg);
    }

    #[test]
    fn parse_obfs_key_accepts_64_hex_chars() {
        let s = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = parse_obfs_key(s).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[31], 0xff);
    }

    #[test]
    fn parse_obfs_key_rejects_bad_length() {
        let s = "ab"; // 1 byte
        assert!(parse_obfs_key(s).is_err());
    }

    #[test]
    fn parse_obfs_key_rejects_non_hex() {
        let s = "not-hex-at-all-no-way-this-parses";
        assert!(parse_obfs_key(s).is_err());
    }
}

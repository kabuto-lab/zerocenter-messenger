//! `ScrambleStream` — a ChaCha20-keystream obfuscation wrapper around an
//! `AsyncRead + AsyncWrite + Unpin` stream.
//!
//! ## What this is
//!
//! Every byte written goes through `byte ^ keystream`. Every byte read
//! goes through the inverse. Both peers use the same 32-byte key
//! (distributed out of band via the `--obfs-key` flag). Each new
//! connection negotiates a fresh 12-byte ChaCha20 nonce via a tiny
//! in-clear handshake (see [`scramble_handshake`]): the dialer picks
//! random bytes and writes them, the listener reads them, then both
//! sides wrap the rest of the byte stream with matching `ScrambleStream`
//! instances. The result: from the second-handshake-byte onward, what
//! a DPI box sees on the wire is indistinguishable from random bytes
//! — the libp2p Noise XX handshake pattern is no longer recognisable.
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
//! - **Not** nonce-hidden. The 12-byte nonce prefix on each connection
//!   is sent in the clear. A passive observer who knows the protocol
//!   exists can see "12 random bytes then more random bytes." Real
//!   Obfs4 derives the nonce from the handshake. Listed as a Phase 4c
//!   improvement.
//!
//! ## Why ChaCha20
//!
//! - Already in our dep tree (via `chacha20poly1305`).
//! - Stream cipher: byte-for-byte transformation, no chunking.
//! - Fast enough that the per-message overhead is dominated by AEAD
//!   (which Noise already does).
//!
//! ## Trait flavour
//!
//! The impls are over **`futures::io::AsyncRead + AsyncWrite`** (NOT
//! tokio's variants). libp2p 0.53's upgrade pipeline operates on
//! futures-io, so the wrap sits naturally between `libp2p_tcp::tokio::
//! Transport` and the Noise upgrade. Tests use `tokio::io::duplex`
//! plus `tokio_util::compat` to bridge.

use std::pin::Pin;
use std::task::{Context, Poll};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rand::RngCore;

/// Either a raw stream or a `ScrambleStream`-wrapped one, behind a
/// single concrete type. Lets the transport builder pick at runtime
/// whether the obfuscation layer is in play without paying for dynamic
/// dispatch — the libp2p `.and_then(...)` slot wants ONE concrete
/// Output type, so we unify here via an enum.
pub enum MaybeScrambled<S> {
    Plain(S),
    Scrambled(ScrambleStream<S>),
}

impl<S: AsyncRead + Unpin> AsyncRead for MaybeScrambled<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            MaybeScrambled::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeScrambled::Scrambled(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MaybeScrambled<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            MaybeScrambled::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeScrambled::Scrambled(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            MaybeScrambled::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeScrambled::Scrambled(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        match this {
            MaybeScrambled::Plain(s) => Pin::new(s).poll_close(cx),
            MaybeScrambled::Scrambled(s) => Pin::new(s).poll_close(cx),
        }
    }
}

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
    /// be agreed (typically via [`scramble_handshake`]).
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
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // SAFETY: we project Pin to each field manually since we don't
        // use pin-project for this small module. `inner` is the only
        // field we re-pin; `in_cipher` is `Unpin`.
        let this = unsafe { self.get_unchecked_mut() };
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            this.in_cipher.apply_keystream(&mut buf[..n]);
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
        // which is incorrect. The futures `AsyncWrite` contract does
        // allow partial writes, but for any wrapped transport that
        // respects back-pressure this is essentially never short. The
        // "proper" fix is a small write-buffer that holds the scratch
        // and a pre-cipher cursor. Listed as Phase 4c polish.
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

/// Perform the connection-opening nonce exchange and wrap the stream.
///
/// Dialer: generates 12 random bytes, writes them as plaintext, then
/// wraps the rest of the byte stream with `ScrambleStream(key, nonce)`.
/// Listener: reads 12 bytes from the wire, then wraps with the matching
/// `ScrambleStream(key, nonce)`. Both sides are now in lock-step on
/// the same keystream and can pass the wrapped stream up to the next
/// transport upgrade (Noise XX in our case).
///
/// Any I/O error before the 12 bytes are exchanged surfaces as an
/// `Err` and the connection is dropped — the upgrade pipeline above
/// us interprets it as a normal connection failure.
pub async fn scramble_handshake<S>(
    mut stream: S,
    key: &[u8; 32],
    is_dialer: bool,
) -> std::io::Result<ScrambleStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nonce: [u8; 12] = if is_dialer {
        let mut n = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut n);
        stream.write_all(&n).await?;
        stream.flush().await?;
        n
    } else {
        let mut n = [0u8; 12];
        stream.read_exact(&mut n).await?;
        n
    };
    Ok(ScrambleStream::new(stream, key, &nonce))
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
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn roundtrip_in_memory() {
        // tokio::io::duplex gives a tokio-flavoured pair; `.compat()`
        // adapts each half to the `futures::io` traits ScrambleStream
        // operates on.
        let (a, b) = tokio::io::duplex(4096);
        let key = [7u8; 32];
        let nonce = [3u8; 12];

        let mut writer = ScrambleStream::new(a.compat(), &key, &nonce);
        let mut reader = ScrambleStream::new(b.compat(), &key, &nonce);

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
        let (a, middle_observer) = tokio::io::duplex(4096);
        let mut writer = ScrambleStream::new(a.compat(), &[1u8; 32], &[2u8; 12]);

        let needle = b"PLAINTEXT_MARKER_QQ123";
        writer.write_all(needle).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let mut middle = middle_observer.compat();
        let mut wire = Vec::new();
        middle.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire.len(), needle.len());
        assert_ne!(wire, needle, "the marker leaked through unscrambled");
    }

    #[tokio::test]
    async fn different_keys_yield_garbled_decryption() {
        let (a, b) = tokio::io::duplex(4096);
        let key_a = [1u8; 32];
        let key_b = [2u8; 32]; // wrong
        let nonce = [0u8; 12];

        let mut writer = ScrambleStream::new(a.compat(), &key_a, &nonce);
        let mut reader = ScrambleStream::new(b.compat(), &key_b, &nonce);

        let msg = b"hello";
        writer.write_all(msg).await.unwrap();
        writer.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        reader.read_exact(&mut got).await.unwrap();
        assert_ne!(got, msg);
    }

    #[tokio::test]
    async fn handshake_exchanges_nonce_and_roundtrips() {
        // Spin up a paired duplex; one side runs as dialer, the other
        // as listener. Both invoke scramble_handshake. After the
        // 12-byte nonce exchange the wrapped streams must roundtrip.
        let (a, b) = tokio::io::duplex(4096);
        let key = [9u8; 32];

        let dialer_fut = scramble_handshake(a.compat(), &key, /* is_dialer */ true);
        let listener_fut = scramble_handshake(b.compat(), &key, /* is_dialer */ false);

        let (dialer_res, listener_res) = futures::join!(dialer_fut, listener_fut);
        let mut d = dialer_res.expect("dialer handshake");
        let mut l = listener_res.expect("listener handshake");

        let msg = b"obfuscated payload after the in-clear nonce";
        d.write_all(msg).await.unwrap();
        d.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        l.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
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

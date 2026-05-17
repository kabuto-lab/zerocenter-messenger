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
    /// Scrambled bytes the keystream has already been advanced past
    /// but the inner writer hasn't fully accepted yet. Lives across
    /// `poll_write` calls: short inner writes parked the tail here
    /// rather than re-scrambling next time (ChaCha20 can't be rewound).
    /// Drained FIRST on every `poll_write` / `poll_flush` / `poll_close`
    /// before accepting new caller bytes.
    pending: Vec<u8>,
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
            pending: Vec::new(),
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

        // Drain any scrambled bytes left from a previous short inner
        // write before accepting new caller bytes. The keystream has
        // already been advanced past `pending` and we can't intermix
        // freshly-scrambled bytes ahead of it.
        match drain_pending(&mut this.inner, &mut this.pending, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        // Pending is now empty. Scramble the caller's buf and try to
        // hand it to the inner writer in one shot. Any tail the inner
        // didn't accept is parked in `pending` for the next drain.
        let mut scratch = buf.to_vec();
        this.out_cipher.apply_keystream(&mut scratch);

        match Pin::new(&mut this.inner).poll_write(cx, &scratch) {
            Poll::Ready(Ok(n)) => {
                if n < scratch.len() {
                    this.pending.extend_from_slice(&scratch[n..]);
                }
                // We've committed to all of `buf` either way — flushed
                // bytes are in the inner pipeline, the rest sits in
                // `pending` until the next poll drains it. The caller
                // owns no further responsibility for these bytes.
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => {
                // Cipher has been advanced past these bytes already and
                // they never made it onto the wire. Connection's write
                // half is permanently desynced — surface the error so
                // the upper layer drops the connection.
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                // Inner not ready yet. Park the scrambled bytes; the
                // caller will see Ok(buf.len()) once they retry after
                // their waker fires, and the next call will drain.
                this.pending.extend_from_slice(&scratch);
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        // Push everything we've already scrambled out before asking the
        // inner to flush — otherwise the caller-visible flush would lie.
        match drain_pending(&mut this.inner, &mut this.pending, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = unsafe { self.get_unchecked_mut() };
        match drain_pending(&mut this.inner, &mut this.pending, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

/// Repeatedly try to hand `pending` bytes to `inner` until either the
/// buffer empties (`Ready(Ok(()))`), the inner stalls (`Pending`), or
/// errors out. Loops because a single `poll_write` may accept only a
/// prefix and immediately be ready to accept more — useful when the
/// inner is a small in-memory pipe.
///
/// `Ok(0)` from the inner means "I will never accept these bytes" — we
/// translate to `WriteZero` since otherwise we'd spin forever.
fn drain_pending<S: AsyncWrite + Unpin>(
    inner: &mut S,
    pending: &mut Vec<u8>,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<()>> {
    while !pending.is_empty() {
        match Pin::new(&mut *inner).poll_write(cx, pending) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            Poll::Ready(Ok(n)) => {
                pending.drain(..n);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
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
    async fn short_inner_writes_dont_desync_keystream() {
        // 16-byte inner duplex forces many short writes for a 1000-byte
        // message: every poll_write that hits the cap returns Ok(16) and
        // the rest of the scrambled tail goes into `pending`. Without
        // the drain-first / pending-buffer fix the keystream would
        // advance past bytes that never went on the wire, and the
        // reader's descrambling would diverge after the first 16 bytes.
        let (a, b) = tokio::io::duplex(16);
        let key = [42u8; 32];
        let nonce = [9u8; 12];

        let mut writer = ScrambleStream::new(a.compat(), &key, &nonce);
        let mut reader = ScrambleStream::new(b.compat(), &key, &nonce);

        // 1000 bytes with a recognizable pattern so an off-by-one
        // keystream offset would produce a glaringly wrong read.
        let msg: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        let write_fut = async {
            writer.write_all(&msg).await.unwrap();
            writer.flush().await.unwrap();
            writer.close().await.unwrap();
        };
        let read_fut = async {
            let mut got = vec![0u8; 1000];
            reader.read_exact(&mut got).await.unwrap();
            got
        };
        let (_, got) = futures::join!(write_fut, read_fut);
        assert_eq!(got, msg, "1000-byte message must survive many short writes");
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

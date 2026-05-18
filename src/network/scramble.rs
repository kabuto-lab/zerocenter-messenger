//! `ScrambleStream` — a ChaCha20-keystream obfuscation wrapper around an
//! `AsyncRead + AsyncWrite + Unpin` stream, with 256-byte-quantum frame
//! padding (Phase 4c task 2) to hide payload sizes from statistical DPI.
//!
//! ## What this is
//!
//! Every byte written goes through `byte ^ keystream`. Every byte read
//! goes through the inverse. Both peers use the same 32-byte key
//! (distributed out of band via the `--obfs-key` flag). Each new
//! connection negotiates a fresh 12-byte ChaCha20 nonce via a tiny
//! in-clear handshake (see [`scramble_handshake`]).
//!
//! ### Framing (Phase 4c task 2)
//!
//! Above the byte-XOR layer sits a simple frame protocol:
//!
//! ```text
//!   [u16-be: actual_len] [actual_len bytes payload] [pad to next 256-multiple]
//! ```
//!
//! The entire frame (header + payload + pad) is XOR'd with the keystream
//! together, so an observer can't tell the header from the payload from
//! the pad. The receiver descrambles the 2-byte header, learns the
//! payload length, descrambles `payload + pad` bytes, delivers only the
//! payload to the upper layer.
//!
//! Effect on the wire: every frame is a multiple of 256 bytes. A 48-byte
//! Noise handshake message and a 200-byte DM both look like 256 bytes; a
//! 300-byte DM looks like 512. This collapses the per-message size
//! fingerprint that statistical DPI uses to identify libp2p.
//!
//! ## What this is NOT
//!
//! - **Not** real Obfs4. The 12-byte nonce prefix is still sent in the
//!   clear; real Obfs4 derives it from an NTOR-style handshake so there
//!   is no plaintext prefix. There is also no inter-arrival-time
//!   randomization yet (Phase 4c continuation).
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
//! ## Trait flavour
//!
//! The impls are over **`futures::io::AsyncRead + AsyncWrite`** (NOT
//! tokio's variants). libp2p 0.53's upgrade pipeline operates on
//! futures-io, so the wrap sits naturally between `libp2p_tcp::tokio::
//! Transport` and the Noise upgrade. Tests use `tokio::io::duplex`
//! plus `tokio_util::compat` to bridge.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rand::{Rng, RngCore};

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

/// Frame quantum: every on-wire frame's total length (header + payload +
/// pad) is rounded up to a multiple of this. 256 is the documented
/// default — small enough that short DMs don't waste much bandwidth,
/// large enough to hide typical Noise handshake (48 B) and yamux
/// header (~10 B) sizes inside a common bucket.
pub const FRAME_QUANTUM: usize = 256;

/// Maximum payload bytes per frame, dictated by the u16 length header.
/// `poll_write` caps `buf` to this and returns `Ok(MAX_PAYLOAD)`; the
/// caller (typically `AsyncWriteExt::write_all`) re-calls for the rest.
pub const MAX_PAYLOAD_PER_FRAME: usize = u16::MAX as usize;

/// What the reader expects on the wire next.
enum ReadState {
    /// Still accumulating the 2-byte length header. `partial[..filled]`
    /// holds the descrambled bytes received so far.
    NeedHeader { partial: [u8; 2], filled: usize },
    /// Header parsed. `payload_remaining` payload bytes are still to be
    /// read and delivered upward; after them, `pad_remaining` pad bytes
    /// are still to be read and discarded. Both must be descrambled to
    /// keep the keystream in lockstep with the sender.
    InBody { payload_remaining: u16, pad_remaining: u16 },
}

impl Default for ReadState {
    fn default() -> Self {
        Self::NeedHeader { partial: [0; 2], filled: 0 }
    }
}

/// Round `frame_total` up to the nearest [`FRAME_QUANTUM`]-multiple.
fn padded_frame_size(frame_total: usize) -> usize {
    frame_total.div_ceil(FRAME_QUANTUM) * FRAME_QUANTUM
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
    /// Framing state machine for the read side. Survives across
    /// `poll_read` calls so a frame straddling many polls reassembles
    /// correctly.
    read_state: ReadState,
    /// Phase 4c.2′ — per-frame inter-arrival-time jitter cap, ms.
    /// `None` (or `Some(0)`) means no jitter. When set, every `poll_write`
    /// that's about to emit a NEW frame first waits a `uniform(0..=max)`
    /// ms delay so the wire-level timing pattern of libp2p / Noise /
    /// yamux frames is randomised within that window.
    jitter_max_ms: Option<u32>,
    /// An in-progress jitter sleep, if any. `tokio::time::Sleep` is
    /// `!Unpin`, so we box-pin it; the box itself is `Unpin`.
    pending_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> ScrambleStream<S> {
    /// Wrap `inner`. `key` is shared between both peers; `nonce` must
    /// be agreed (typically via [`scramble_handshake`]). No jitter.
    pub fn new(inner: S, key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self::with_jitter(inner, key, nonce, None)
    }

    /// Like [`ScrambleStream::new`] but with a per-frame jitter cap.
    /// `jitter_max_ms = Some(n)` makes every new frame wait `uniform(0..=n)`
    /// ms before emission. `None` or `Some(0)` is the no-jitter path.
    pub fn with_jitter(
        inner: S,
        key: &[u8; 32],
        nonce: &[u8; 12],
        jitter_max_ms: Option<u32>,
    ) -> Self {
        let out_cipher = ChaCha20::new(key.into(), nonce.into());
        let in_cipher = ChaCha20::new(key.into(), nonce.into());
        Self {
            inner,
            out_cipher,
            in_cipher,
            pending: Vec::new(),
            read_state: ReadState::default(),
            jitter_max_ms,
            pending_sleep: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ScrambleStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out_buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if out_buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // SAFETY: manual Pin projection. `inner` is the only !Unpin
        // field; everything else (cipher state, pending Vec, read state
        // enum with Copy fields) is `Unpin`.
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.read_state {
                ReadState::NeedHeader { ref mut partial, ref mut filled } => {
                    // Fill the 2-byte header. We may need multiple inner
                    // polls if the inner returns short reads.
                    let need = 2 - *filled;
                    let mut tmp = [0u8; 2];
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp[..need]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            // Clean EOF only at a frame boundary; partial
                            // header is a truncated stream.
                            return if *filled == 0 {
                                Poll::Ready(Ok(0))
                            } else {
                                Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()))
                            };
                        }
                        Poll::Ready(Ok(n)) => {
                            this.in_cipher.apply_keystream(&mut tmp[..n]);
                            partial[*filled..*filled + n].copy_from_slice(&tmp[..n]);
                            *filled += n;
                            if *filled == 2 {
                                let payload_len = u16::from_be_bytes(*partial);
                                let frame_total = 2 + payload_len as usize;
                                let padded = padded_frame_size(frame_total);
                                let pad_amount = (padded - frame_total) as u16;
                                this.read_state = ReadState::InBody {
                                    payload_remaining: payload_len,
                                    pad_remaining: pad_amount,
                                };
                            }
                            // Loop: either keep filling the header (if
                            // partial) or move into the body.
                        }
                    }
                }
                ReadState::InBody { ref mut payload_remaining, ref mut pad_remaining } => {
                    if *payload_remaining > 0 {
                        // Read payload bytes straight into the caller's
                        // buffer, descramble in place, return.
                        let want = std::cmp::min(out_buf.len(), *payload_remaining as usize);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut out_buf[..want]) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    std::io::ErrorKind::UnexpectedEof.into(),
                                ));
                            }
                            Poll::Ready(Ok(n)) => {
                                this.in_cipher.apply_keystream(&mut out_buf[..n]);
                                *payload_remaining -= n as u16;
                                return Poll::Ready(Ok(n));
                            }
                        }
                    } else if *pad_remaining > 0 {
                        // Pad bytes still need to be drained off the
                        // wire — descramble (to advance the keystream
                        // in lockstep with the sender) then discard.
                        let chunk = std::cmp::min(*pad_remaining as usize, 512);
                        let mut tmp = vec![0u8; chunk];
                        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    std::io::ErrorKind::UnexpectedEof.into(),
                                ));
                            }
                            Poll::Ready(Ok(n)) => {
                                this.in_cipher.apply_keystream(&mut tmp[..n]);
                                *pad_remaining -= n as u16;
                                // Loop: maybe more pad, maybe done.
                            }
                        }
                    } else {
                        // Both zero: frame fully consumed. Next frame
                        // starts with a fresh header.
                        this.read_state = ReadState::default();
                        // Loop: drop into the NeedHeader arm.
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ScrambleStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
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

        // Phase 4c.2′ — gate the next frame's emission behind a uniform
        // random jitter sleep. Three phases:
        //
        //   1. If a sleep is in progress, poll it. Ready → drop the
        //      future and fall through; Pending → return Pending so the
        //      executor wakes us when the timer fires.
        //   2. If no sleep is in progress and jitter is configured, roll
        //      a fresh `uniform(0..=max)` delay. Zero or unset → skip.
        //   3. After both phases, we're cleared to scramble + write.
        //
        // The jitter applies only to NEW frames, not to draining pending
        // (which happens before this step and represents bytes already
        // scrambled in a previous call). flush/close also skip jitter —
        // they shouldn't delay bytes that are already on the wire path.
        if let Some(sleep) = this.pending_sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    this.pending_sleep = None;
                }
            }
        } else if let Some(max) = this.jitter_max_ms {
            if max > 0 {
                let dur_ms = rand::thread_rng().gen_range(0..=max);
                if dur_ms > 0 {
                    let mut sleep =
                        Box::pin(tokio::time::sleep(Duration::from_millis(dur_ms as u64)));
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => {
                            this.pending_sleep = Some(sleep);
                            return Poll::Pending;
                        }
                        Poll::Ready(()) => {
                            // Timer fired in-line (Sleep is sometimes
                            // immediately Ready for sub-tick durations);
                            // fall through to frame emission.
                        }
                    }
                }
            }
        }

        // Build one frame containing up to MAX_PAYLOAD_PER_FRAME bytes
        // of `buf`. Frame layout:
        //   [u16-be: payload_len] [payload_len bytes] [pad to FRAME_QUANTUM-multiple]
        // The pad bytes start as zero; ChaCha20 XOR turns them into
        // pseudo-random bytes on the wire. Pad bytes don't leak
        // information because the keystream is already secret.
        let payload_len = std::cmp::min(buf.len(), MAX_PAYLOAD_PER_FRAME);
        let frame_total_unpadded = 2 + payload_len;
        let padded = padded_frame_size(frame_total_unpadded);

        let mut frame = Vec::with_capacity(padded);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        frame.extend_from_slice(&buf[..payload_len]);
        frame.resize(padded, 0);

        // Scramble the whole frame in one go so the keystream advances
        // exactly `padded` bytes for this frame.
        this.out_cipher.apply_keystream(&mut frame);

        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n < frame.len() {
                    this.pending.extend_from_slice(&frame[n..]);
                }
                // Caller-visible: we accepted `payload_len` of their
                // bytes. The pad + length-header overhead is invisible
                // to them.
                Poll::Ready(Ok(payload_len))
            }
            Poll::Ready(Err(e)) => {
                // Cipher already advanced; connection's write half is
                // permanently desynced. Surface the error.
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                // Park the scrambled frame; the next drain will ship it.
                this.pending.extend_from_slice(&frame);
                Poll::Ready(Ok(payload_len))
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
/// `jitter_max_ms` is forwarded to the resulting [`ScrambleStream`];
/// `None` (or `Some(0)`) disables per-frame jitter.
///
/// Any I/O error before the 12 bytes are exchanged surfaces as an
/// `Err` and the connection is dropped — the upgrade pipeline above
/// us interprets it as a normal connection failure.
pub async fn scramble_handshake<S>(
    mut stream: S,
    key: &[u8; 32],
    is_dialer: bool,
    jitter_max_ms: Option<u32>,
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
    Ok(ScrambleStream::with_jitter(stream, key, &nonce, jitter_max_ms))
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
        // Confirm that a passive observer in the middle sees random-
        // looking framed bytes, not our plaintext. With Phase 4c
        // framing, the writer emits one 256-byte frame for a 22-byte
        // needle (2-byte header + 22 payload + 232 pad), and the whole
        // thing is XOR'd with the ChaCha20 keystream.
        let (a, middle_observer) = tokio::io::duplex(4096);
        let mut writer = ScrambleStream::new(a.compat(), &[1u8; 32], &[2u8; 12]);

        let needle = b"PLAINTEXT_MARKER_QQ123";
        writer.write_all(needle).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        let mut middle = middle_observer.compat();
        let mut wire = Vec::new();
        middle.read_to_end(&mut wire).await.unwrap();

        assert!(!wire.is_empty(), "writer's frame must hit the wire");
        assert_eq!(
            wire.len() % FRAME_QUANTUM,
            0,
            "wire length must be a {FRAME_QUANTUM}-multiple after framing, got {}",
            wire.len()
        );
        assert!(
            !wire.windows(needle.len()).any(|w| w == needle),
            "scrambled wire must not contain the plaintext marker"
        );
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
        drop(writer); // signal EOF so the reader doesn't block forever

        // With the wrong key the descrambled length header is
        // essentially random. The reader then tries to consume
        // payload+pad bytes that don't exist on the truncated wire,
        // which surfaces as UnexpectedEof — or if the random length
        // happens to fit, the descrambled payload is garbage that
        // doesn't match `msg`. Both outcomes are acceptable; what
        // must NOT happen is a clean decode equal to the plaintext.
        let mut got = vec![0u8; msg.len()];
        match reader.read_exact(&mut got).await {
            Err(_) => {}
            Ok(()) => assert_ne!(
                got, msg,
                "wrong-key decode must differ from plaintext"
            ),
        }
    }

    #[tokio::test]
    async fn frame_padding_rounds_up_to_quantum() {
        // Three payloads in adjacent quantum buckets — verify the wire
        // hides the difference: same total byte count for every payload
        // that fits in one quantum.
        for payload_len in [1usize, 50, 200, 253] {
            let (a, observer) = tokio::io::duplex(4096);
            let mut writer = ScrambleStream::new(a.compat(), &[3u8; 32], &[4u8; 12]);
            let payload = vec![b'x'; payload_len];
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();
            drop(writer);
            let mut obs = observer.compat();
            let mut wire = Vec::new();
            obs.read_to_end(&mut wire).await.unwrap();
            assert_eq!(
                wire.len(),
                FRAME_QUANTUM,
                "payload_len={payload_len} must produce one {FRAME_QUANTUM}-byte frame"
            );
        }

        // 300-byte payload spills into the next quantum: 2 + 300 = 302
        // rounds up to 512.
        let (a, observer) = tokio::io::duplex(4096);
        let mut writer = ScrambleStream::new(a.compat(), &[3u8; 32], &[4u8; 12]);
        writer.write_all(&vec![b'y'; 300]).await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);
        let mut obs = observer.compat();
        let mut wire = Vec::new();
        obs.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire.len(), 2 * FRAME_QUANTUM, "300-byte payload → 2 quanta");
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
            // `close()` signals EOF to the reader after the frame's pad
            // bytes have been drained — without it the reader's
            // `read_to_end` would hang waiting for more frames.
            writer.close().await.unwrap();
        };
        let read_fut = async {
            // `read_to_end` (not `read_exact(1000)`) so pad bytes are
            // consumed in the natural read flow and the reader terminates
            // cleanly on the writer's EOF. read_exact would return after
            // 1000 payload bytes and leave the writer's flush parked on
            // 22 unconsumed pad bytes → deadlock.
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.unwrap();
            got
        };
        let (_, got) = futures::join!(write_fut, read_fut);
        assert_eq!(got, msg, "1000-byte message must survive many short writes");
    }

    #[tokio::test]
    async fn jitter_roundtrips_three_frames() {
        // Small jitter cap (3 ms) keeps test wall time bounded; the test
        // run is still negligible (≤ ~9 ms total even worst-case).
        // Confirms (a) the sleep future is correctly polled into Ready
        // and (b) the byte stream still roundtrips bit-for-bit with
        // jitter wired in.
        let (a, b) = tokio::io::duplex(4096);
        let key = [11u8; 32];
        let nonce = [22u8; 12];

        let mut writer =
            ScrambleStream::with_jitter(a.compat(), &key, &nonce, Some(3));
        let mut reader = ScrambleStream::with_jitter(b.compat(), &key, &nonce, None);

        let write_fut = async {
            // Three separate frames so the jitter path is exercised
            // three times, not just once.
            writer.write_all(b"frame-one-").await.unwrap();
            writer.write_all(b"frame-two-").await.unwrap();
            writer.write_all(b"frame-three").await.unwrap();
            writer.flush().await.unwrap();
            writer.close().await.unwrap();
        };
        let read_fut = async {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.unwrap();
            got
        };
        let (_, got) = futures::join!(write_fut, read_fut);
        assert_eq!(got, b"frame-one-frame-two-frame-three");
    }

    #[tokio::test]
    async fn jitter_zero_is_a_noop() {
        // `Some(0)` should be indistinguishable from `None` — no sleep
        // created, no scheduler interaction beyond the existing path.
        let (a, b) = tokio::io::duplex(4096);
        let key = [13u8; 32];
        let nonce = [21u8; 12];

        let mut writer =
            ScrambleStream::with_jitter(a.compat(), &key, &nonce, Some(0));
        let mut reader = ScrambleStream::new(b.compat(), &key, &nonce);

        let msg = b"hello with zero-jitter";
        writer.write_all(msg).await.unwrap();
        writer.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        reader.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn handshake_exchanges_nonce_and_roundtrips() {
        // Spin up a paired duplex; one side runs as dialer, the other
        // as listener. Both invoke scramble_handshake. After the
        // 12-byte nonce exchange the wrapped streams must roundtrip.
        let (a, b) = tokio::io::duplex(4096);
        let key = [9u8; 32];

        let dialer_fut =
            scramble_handshake(a.compat(), &key, /* is_dialer */ true, /* jitter */ None);
        let listener_fut =
            scramble_handshake(b.compat(), &key, /* is_dialer */ false, /* jitter */ None);

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

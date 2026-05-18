use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Version byte that prefixes every AEAD-encrypted blob stored at rest
/// (ratchet session state, message content, etc). Bump if the AEAD
/// construction changes (algorithm, AAD layout, nonce size).
const AT_REST_VERSION: u8 = 1;
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// Encrypted message stored locally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: i64,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub timestamp: i64,
    pub ttl: i64,
}

/// A single contact row: (peer_id, public_key, alias).
pub type ContactRow = (Vec<u8>, Vec<u8>, Option<String>);

/// Local message storage using SQLite.
///
/// Holds the data-encryption key (DEK) used to AEAD-encrypt sensitive
/// blobs at rest — currently just `ratchet_sessions.state_blob`, more
/// in future Phase 3.5 commits. The DEK lives in the OS keyring (see
/// [`crate::crypto::keyring::load_or_create_dek`]); this struct just
/// keeps a copy in memory for the duration of the process.
pub struct MessageStore {
    conn: Connection,
    dek: [u8; 32],
}

impl MessageStore {
    /// Open or create database. `dek` is the 32-byte symmetric key used
    /// to AEAD-encrypt at-rest blobs — obtain it via
    /// [`crate::crypto::keyring::load_or_create_dek`].
    pub fn open<P: AsRef<Path>>(data_dir: P, dek: [u8; 32]) -> Result<Self> {
        let db_path = data_dir.as_ref().join("messages.db");
        
        info!("Opening message store: {:?}", db_path);
        
        let conn = Connection::open(&db_path)?;
        
        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender BLOB NOT NULL,
                recipient BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                ttl INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id BLOB UNIQUE NOT NULL,
                public_key BLOB NOT NULL,
                alias TEXT,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                topic TEXT,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Cache of remote peers' signed X25519 prekeys. Populated by the
        // /zerocenter/prekey/1.0.0 response handler. Each row's signature
        // has already been verified against the peer's Ed25519 key before
        // insertion — callers can trust the bytes here.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS prekeys_seen (
                peer_id    BLOB PRIMARY KEY,
                x25519_pub BLOB NOT NULL,
                signature  BLOB NOT NULL,
                fetched_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Persistent Double Ratchet sessions, one per remote peer. The
        // state blob is JSON (see RatchetState::to_json / from_json).
        // The state blob is JSON encrypted at rest with the per-profile
        // DEK (see `encrypt_at_rest`).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ratchet_sessions (
                peer_id    BLOB PRIMARY KEY,
                state_blob BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Our one-time prekeys (OTPKs). Each row is a single X25519
        // keypair signed by our Ed25519 identity. The public half is
        // published on demand via the prekey protocol; the responder
        // consumes it on the next X3DH handshake, providing forward-
        // secret *asynchronous* first-message delivery (initiator can
        // send even when we are offline at handshake time).
        //
        // The private bytes are AEAD-encrypted at rest with the DEK.
        // `consumed_at` is NULL while the OTPK is still available; set
        // to the consumption timestamp after a successful first decrypt.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS my_otpks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                x25519_priv   BLOB NOT NULL,
                x25519_pub    BLOB NOT NULL,
                signature     BLOB NOT NULL,
                created_at    INTEGER NOT NULL,
                consumed_at   INTEGER
            )",
            [],
        )?;

        // Outbox: messages we wanted to send but the recipient wasn't
        // connected at the time. Drained when ConnectionEstablished
        // fires for that peer. Plaintext is AEAD-encrypted at rest so
        // a disk-read attacker can't see queued messages.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS outbox (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id       BLOB NOT NULL,
                ciphertext    BLOB NOT NULL,
                created_at    INTEGER NOT NULL,
                ttl           INTEGER NOT NULL,
                is_wire_bytes INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_outbox_peer ON outbox(peer_id)",
            [],
        )?;

        // Phase 5 mailbox encrypt-once: pre-existing databases that
        // predate the `is_wire_bytes` column get it via a one-shot
        // migration. SQLite's `ALTER TABLE ADD COLUMN` is idempotent
        // when the column is absent and errors otherwise — we ignore
        // the "duplicate column" error to keep startup clean. New
        // databases pick up the column at CREATE time above.
        if let Err(e) = conn.execute(
            "ALTER TABLE outbox ADD COLUMN is_wire_bytes INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            // rusqlite returns a SqliteFailure with extended code
            // SQLITE_ERROR for "duplicate column name"; the message
            // contains "duplicate column". Any other ALTER failure
            // surfaces.
            let msg = format!("{}", e);
            if !msg.contains("duplicate column") {
                return Err(e.into());
            }
        }

        // DHT-mailbox drops we have published on behalf of the local
        // user. Used to drive republish-before-Kad-TTL-expires and to
        // know when to stop republishing (recipient ACK or 7-day cap).
        //
        // `wire_ciphertext` is the serialized EncryptedPayload — the
        // exact bytes we put into the DHT record. It is **already**
        // confidential by construction (Double Ratchet output). We
        // additionally encrypt-at-rest with the DEK so a local-disk
        // attacker can't tie our published drops to recipients.
        //
        // `slot_id` is the Kad key derivation input — `floor(unix_ts /
        // SLOT_SECONDS)`. Recorded so we can recompute the Kad key for
        // republish.
        //
        // `acknowledged_at` is set when the recipient confirms receipt
        // (Phase 3 of the mailbox plan; see plans/phase4-mailbox.md).
        // Once set, we stop republishing this row.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS mailbox_drops (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_pid     BLOB NOT NULL,
                slot_id           INTEGER NOT NULL,
                wire_ciphertext   BLOB NOT NULL,
                created_at        INTEGER NOT NULL,
                last_published_at INTEGER NOT NULL,
                expires_at        INTEGER NOT NULL,
                acknowledged_at   INTEGER
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_drops_recipient ON mailbox_drops(recipient_pid)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_drops_repub
             ON mailbox_drops(last_published_at)
             WHERE acknowledged_at IS NULL",
            [],
        )?;

        // Recipient-side state: last DHT slot we polled. Used to avoid
        // re-querying empty slots on every startup. Single-row table
        // (id=0 always).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS mailbox_poll_state (
                id              INTEGER PRIMARY KEY,
                last_slot_polled INTEGER NOT NULL
            )",
            [],
        )?;

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)",
            [],
        )?;

        Ok(Self { conn, dek })
    }

    /// Encrypt a blob for at-rest storage. Used for both ratchet session
    /// state and message content. Output layout:
    ///   [version: u8] [nonce: 12 bytes] [ciphertext + 16-byte tag]
    fn encrypt_at_rest(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.dek[..]));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce[..]),
                Payload { msg: plaintext, aad: &[] },
            )
            .expect("ChaCha20-Poly1305 encryption is infallible for valid keys");

        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(AT_REST_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Inverse of [`Self::encrypt_at_rest`]. Returns Err for unknown
    /// version, malformed length, or AEAD verification failure (which
    /// usually means the DEK changed).
    fn decrypt_at_rest(&self, blob: &[u8]) -> Result<Vec<u8>> {
        let Some((&version, rest)) = blob.split_first() else {
            return Err(anyhow!("empty at-rest blob"));
        };
        if version != AT_REST_VERSION {
            return Err(anyhow!(
                "unknown at-rest blob version {} (expected {})",
                version,
                AT_REST_VERSION
            ));
        }
        if rest.len() < NONCE_LEN + 16 {
            return Err(anyhow!("at-rest blob too short ({} bytes)", rest.len()));
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.dek[..]));
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload { msg: ciphertext, aad: &[] },
            )
            .map_err(|_| anyhow!("AEAD failed — DEK rotated or blob tampered"))
    }

    /// Persist a message. The `content` argument is the plaintext on
    /// this device's local view of the conversation; this function
    /// AEAD-encrypts it under the per-profile DEK before writing.
    ///
    /// Sender / recipient PeerId bytes stay in the clear so we can still
    /// query "messages from peer X" without expensive scan-and-decrypt.
    /// Those are who-talks-to-whom metadata, an acceptable trade-off for
    /// query efficiency; full metadata privacy is a Phase 4 concern.
    pub fn store_message(
        &self,
        sender: &[u8],
        recipient: &[u8],
        content: &[u8],
        ttl_secs: i64,
    ) -> Result<i64> {
        let timestamp = chrono_time();
        let encrypted = self.encrypt_at_rest(content);

        self.conn.execute(
            "INSERT INTO messages (sender, recipient, ciphertext, timestamp, ttl)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sender, recipient, encrypted, timestamp, ttl_secs],
        )?;
        // `execute` returns affected-rows count, not the new primary key.
        // For an `INTEGER PRIMARY KEY AUTOINCREMENT` column SQLite gives
        // us the rowid via `last_insert_rowid`.
        Ok(self.conn.last_insert_rowid())
    }

    /// Get messages for a recipient. The `ciphertext` field in the
    /// returned [`StoredMessage`]s contains decrypted plaintext.
    /// Rows whose blob fails to decrypt (DEK rotation, corruption) are
    /// **skipped silently** — we don't return errors here because the
    /// alternative is a single bad row blocking all history.
    pub fn get_messages(&self, recipient: &[u8]) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, recipient, ciphertext, timestamp, ttl
             FROM messages
             WHERE recipient = ?1
             ORDER BY timestamp ASC"
        )?;

        let messages = stmt
            .query_map(params![recipient], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    sender: row.get(1)?,
                    recipient: row.get(2)?,
                    ciphertext: row.get(3)?,
                    timestamp: row.get(4)?,
                    ttl: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|m| self.decrypt_message_row(m))
            .collect();

        Ok(messages)
    }

    /// Delete expired messages
    pub fn cleanup_expired(&self) -> Result<usize> {
        let now = chrono_time();
        
        let deleted = self.conn.execute(
            "DELETE FROM messages WHERE timestamp + ttl < ?1",
            params![now],
        )?;

        info!("Cleaned up {} expired messages", deleted);

        Ok(deleted)
    }

    /// Add a contact
    pub fn add_contact(
        &self,
        peer_id: &[u8],
        public_key: &[u8],
        alias: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (peer_id, public_key, alias, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_id, public_key, alias, chrono_time()],
        )?;

        Ok(())
    }

    /// Get all contacts
    pub fn get_contacts(&self) -> Result<Vec<ContactRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, public_key, alias FROM contacts ORDER BY alias"
        )?;

        let contacts = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(contacts)
    }

    /// Get recent messages (for history). Returns plaintext content;
    /// rows that fail to decrypt are skipped (logged at warn).
    pub fn get_recent_messages(&self, limit: usize) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, recipient, ciphertext, timestamp, ttl
             FROM messages
             ORDER BY timestamp DESC
             LIMIT ?1"
        )?;

        let messages = stmt
            .query_map(params![limit as i64], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    sender: row.get(1)?,
                    recipient: row.get(2)?,
                    ciphertext: row.get(3)?,
                    timestamp: row.get(4)?,
                    ttl: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|m| self.decrypt_message_row(m))
            .collect();

        Ok(messages)
    }

    /// Cache a verified prekey for a peer. Overwrites any previous entry —
    /// peers rotate prekeys, and the most recently verified one wins.
    ///
    /// Caller is responsible for verifying the Ed25519 signature against
    /// the peer's identity key BEFORE calling this. The store does not
    /// re-verify; the column exists for forensic / re-export purposes.
    pub fn save_prekey(
        &self,
        peer_id: &[u8],
        x25519_pub: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO prekeys_seen
                 (peer_id, x25519_pub, signature, fetched_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_id, &x25519_pub[..], &signature[..], chrono_time()],
        )?;
        Ok(())
    }

    /// Persist (or update) the ratchet session for `peer_id`.
    /// `state_plaintext` is the serialized session JSON; this function
    /// AEAD-encrypts it with the per-profile DEK before writing.
    /// Callers should invoke this after every successful encrypt or
    /// decrypt so a crash doesn't wedge the chain.
    pub fn save_session(&self, peer_id: &[u8], state_plaintext: &[u8]) -> Result<()> {
        let blob = self.encrypt_at_rest(state_plaintext);
        self.conn.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
                 (peer_id, state_blob, updated_at)
             VALUES (?1, ?2, ?3)",
            params![peer_id, blob, chrono_time()],
        )?;
        Ok(())
    }

    /// Load and decrypt the ratchet session JSON for `peer_id`, if any.
    /// Returns `Ok(None)` for an unknown peer; `Err` if a row exists but
    /// cannot be decrypted (DEK rotated, file tampered, format changed).
    pub fn load_session(&self, peer_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state_blob FROM ratchet_sessions WHERE peer_id = ?1")?;
        let mut rows = stmt.query(params![peer_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let blob: Vec<u8> = row.get(0)?;
        let plaintext = self.decrypt_at_rest(&blob)?;
        Ok(Some(plaintext))
    }

    /// Insert a fresh one-time prekey owned by us. The private bytes
    /// are AEAD-encrypted at rest under the DEK; the public bytes and
    /// signature are stored plain (they are inherently public).
    pub fn add_my_otpk(
        &self,
        priv_bytes: &[u8; 32],
        pub_bytes: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<i64> {
        let enc_priv = self.encrypt_at_rest(priv_bytes);
        self.conn.execute(
            "INSERT INTO my_otpks (x25519_priv, x25519_pub, signature, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![enc_priv, &pub_bytes[..], &signature[..], chrono_time()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Count OTPKs that have not yet been published-and-consumed.
    pub fn unused_otpk_count(&self) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM my_otpks WHERE consumed_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Atomically pop the oldest unused OTPK and mark it consumed.
    /// Returns `(id, public_bytes, signature)`. The private bytes stay
    /// in the row for later look-up by `load_otpk_private(id)`.
    ///
    /// Marking consumed at pop time (rather than after the responder
    /// confirms) is the conservative choice: a single OTPK is never
    /// reused across two different initiator handshakes, even under
    /// concurrent prekey-fetch races. The cost is wasted OTPKs when an
    /// initiator fetches but never sends — pool size compensates.
    pub fn pop_unused_otpk(&self) -> Result<Option<(i64, [u8; 32], [u8; 64])>> {
        let now = chrono_time();
        // Single round-trip: pick the oldest unused row, return its
        // public+signature, mark it consumed. UPDATE ... RETURNING is
        // a sqlite 3.35+ feature; bundled rusqlite ships current sqlite.
        let mut stmt = self.conn.prepare(
            "UPDATE my_otpks
                SET consumed_at = ?1
              WHERE id = (
                    SELECT id FROM my_otpks
                     WHERE consumed_at IS NULL
                     ORDER BY id ASC
                     LIMIT 1
              )
              RETURNING id, x25519_pub, signature",
        )?;
        let row = stmt.query_row(params![now], |row| {
            let id: i64 = row.get(0)?;
            let pub_vec: Vec<u8> = row.get(1)?;
            let sig_vec: Vec<u8> = row.get(2)?;
            Ok((id, pub_vec, sig_vec))
        });

        match row {
            Ok((id, pub_vec, sig_vec)) => {
                let Ok(pub_arr): Result<[u8; 32], _> = pub_vec.try_into() else {
                    return Err(anyhow!("OTPK row {} has malformed pubkey", id));
                };
                let Ok(sig_arr): Result<[u8; 64], _> = sig_vec.try_into() else {
                    return Err(anyhow!("OTPK row {} has malformed signature", id));
                };
                Ok(Some((id, pub_arr, sig_arr)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load and decrypt the private bytes for the OTPK with the given id.
    /// Returns `None` if the id is unknown OR if the row already has
    /// `consumed_at` set — the audit's F3 finding. Gating on
    /// `consumed_at IS NULL` defends against a replay of a first-
    /// message where the OTPK row is still present (not yet GC'd by
    /// `delete_otpk`) but has been used. Without the gate, the replay
    /// would re-derive the same SK and a fresh `RatchetState::new_responder`
    /// would overwrite any in-memory chain progress on this peer.
    pub fn load_otpk_private(&self, id: i64) -> Result<Option<[u8; 32]>> {
        let row = self.conn.query_row(
            "SELECT x25519_priv FROM my_otpks WHERE id = ?1 AND consumed_at IS NULL",
            params![id],
            |row| row.get::<_, Vec<u8>>(0),
        );
        let enc_priv = match row {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let plain = self.decrypt_at_rest(&enc_priv)?;
        let arr: [u8; 32] = plain
            .try_into()
            .map_err(|_| anyhow!("OTPK private has unexpected length"))?;
        Ok(Some(arr))
    }

    /// Permanently delete a consumed OTPK row (after first-decrypt-success).
    /// Optional: keeps the table small. Not strictly required — the row
    /// already has `consumed_at` set so it won't be popped again.
    pub fn delete_otpk(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM my_otpks WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Queue a plaintext message for later delivery to `peer_id`. The
    /// content is AEAD-encrypted before persisting. Returns the row id.
    /// Used on the "no session yet" offline path where we can't ratchet-
    /// encrypt up front; `drain_outbox_for` will re-feed the plaintext
    /// through `try_send_or_queue` and encrypt then.
    pub fn outbox_add(&self, peer_id: &[u8], plaintext: &[u8], ttl_secs: i64) -> Result<i64> {
        let enc = self.encrypt_at_rest(plaintext);
        self.conn.execute(
            "INSERT INTO outbox (peer_id, ciphertext, created_at, ttl, is_wire_bytes)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![peer_id, enc, chrono_time(), ttl_secs],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Phase 5 mailbox encrypt-once: queue an ALREADY-encrypted
    /// `ProtocolMessage` (wire bytes that would have gone over the
    /// live `request-response` channel) for later delivery to
    /// `peer_id`. The wire bytes are AEAD-encrypted again at rest under
    /// the local DEK. `drain_outbox_for` sends these bytes directly
    /// via `request_response::send_request` without re-encrypting,
    /// guaranteeing that the recipient sees identical ciphertext for
    /// the direct-delivery and mailbox-fetch paths.
    pub fn outbox_add_wire(
        &self,
        peer_id: &[u8],
        wire_bytes: &[u8],
        ttl_secs: i64,
    ) -> Result<i64> {
        let enc = self.encrypt_at_rest(wire_bytes);
        self.conn.execute(
            "INSERT INTO outbox (peer_id, ciphertext, created_at, ttl, is_wire_bytes)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![peer_id, enc, chrono_time(), ttl_secs],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Return all unsent outbox entries for `peer_id`, oldest first.
    /// Each entry is `(row_id, content, is_wire_bytes)`:
    /// - `is_wire_bytes = false` → `content` is plaintext; the caller
    ///   should re-feed it through the normal encrypt path.
    /// - `is_wire_bytes = true` → `content` is the encrypted
    ///   `ProtocolMessage` wire bytes; the caller should send them
    ///   directly without re-encrypting.
    /// Caller must `outbox_delete` after successful delivery in either
    /// case. Rows whose at-rest blob fails to decrypt are skipped
    /// (logged at warn).
    pub fn outbox_get_for(&self, peer_id: &[u8]) -> Result<Vec<(i64, Vec<u8>, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ciphertext, is_wire_bytes
             FROM outbox WHERE peer_id = ?1 ORDER BY id ASC",
        )?;
        let rows: Vec<(i64, Vec<u8>, bool)> = stmt
            .query_map(params![peer_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)? != 0,
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, enc, is_wire)| match self.decrypt_at_rest(&enc) {
                Ok(content) => Some((id, content, is_wire)),
                Err(e) => {
                    tracing::warn!("Skipping outbox row id={}: {}", id, e);
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Delete a single outbox row after successful delivery.
    pub fn outbox_delete(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Drop outbox entries whose `created_at + ttl < now`. Called from
    /// the same hourly tick that prunes expired stored messages.
    pub fn outbox_cleanup_expired(&self) -> Result<usize> {
        let now = chrono_time();
        let deleted = self.conn.execute(
            "DELETE FROM outbox WHERE created_at + ttl < ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    // ============================================================
    // DHT mailbox — scaffolding (Phase 2 of the mailbox plan wires
    // these into the network layer). See plans/phase4-mailbox.md.
    // ============================================================

    /// Record that we have published a mailbox drop for `recipient` at
    /// `slot_id`. `wire_ciphertext` is the serialized EncryptedPayload
    /// — i.e. the bytes that went into the DHT record. We additionally
    /// AEAD-encrypt at rest under the DEK.
    pub fn mailbox_drop_record(
        &self,
        recipient: &[u8],
        slot_id: i64,
        wire_ciphertext: &[u8],
        expires_at: i64,
    ) -> Result<i64> {
        let enc = self.encrypt_at_rest(wire_ciphertext);
        let now = chrono_time();
        self.conn.execute(
            "INSERT INTO mailbox_drops
                 (recipient_pid, slot_id, wire_ciphertext,
                  created_at, last_published_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
            params![recipient, slot_id, enc, now, expires_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Update the `last_published_at` timestamp for a row after a
    /// successful republish to the DHT. Called by the republish tick.
    pub fn mailbox_drop_touch(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE mailbox_drops SET last_published_at = ?1 WHERE id = ?2",
            params![chrono_time(), id],
        )?;
        Ok(())
    }

    /// Mark a drop as acknowledged (recipient confirmed receipt).
    /// Republish loop will skip ACK'd rows.
    pub fn mailbox_drop_ack(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE mailbox_drops SET acknowledged_at = ?1 WHERE id = ?2",
            params![chrono_time(), id],
        )?;
        Ok(())
    }

    /// Return drops that need republishing — unacked AND last published
    /// more than `republish_after_secs` ago AND not yet expired.
    /// Each entry is `(id, recipient_pid, slot_id, wire_ciphertext)`.
    pub fn mailbox_drops_due_for_republish(
        &self,
        republish_after_secs: i64,
    ) -> Result<Vec<(i64, Vec<u8>, i64, Vec<u8>)>> {
        let now = chrono_time();
        let threshold = now - republish_after_secs;
        let mut stmt = self.conn.prepare(
            "SELECT id, recipient_pid, slot_id, wire_ciphertext
             FROM mailbox_drops
             WHERE acknowledged_at IS NULL
               AND last_published_at < ?1
               AND expires_at > ?2
             ORDER BY last_published_at ASC",
        )?;
        let rows: Vec<(i64, Vec<u8>, i64, Vec<u8>)> = stmt
            .query_map(params![threshold, now], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, recipient, slot, enc)| match self.decrypt_at_rest(&enc) {
                Ok(plain) => Some((id, recipient, slot, plain)),
                Err(e) => {
                    tracing::warn!("Skipping mailbox_drops row id={}: {}", id, e);
                    None
                }
            })
            .collect();
        Ok(rows)
    }

    /// Prune drops past their expires_at OR acknowledged more than
    /// 24h ago. Called from the hourly cleanup tick.
    pub fn mailbox_drops_cleanup(&self) -> Result<usize> {
        let now = chrono_time();
        let n = self.conn.execute(
            "DELETE FROM mailbox_drops
             WHERE expires_at < ?1
                OR (acknowledged_at IS NOT NULL AND acknowledged_at < ?2)",
            params![now, now - 86400],
        )?;
        Ok(n)
    }

    /// Recipient-side: get the last DHT slot we've polled (or 0 if
    /// none recorded yet). Used to bound the slot-range to query.
    pub fn mailbox_last_polled_slot(&self) -> Result<i64> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_slot_polled FROM mailbox_poll_state WHERE id = 0",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(v.unwrap_or(0))
    }

    /// Recipient-side: record that we have completed polling up to
    /// `slot_id`. Future polls only need to start from `slot_id + 1`.
    pub fn mailbox_set_last_polled_slot(&self, slot_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO mailbox_poll_state (id, last_slot_polled)
             VALUES (0, ?1)",
            params![slot_id],
        )?;
        Ok(())
    }

    /// Load the cached prekey for a peer if present. Returns
    /// `(x25519_pub, signature)`.
    pub fn load_prekey(&self, peer_id: &[u8]) -> Result<Option<([u8; 32], [u8; 64])>> {
        let mut stmt = self.conn.prepare(
            "SELECT x25519_pub, signature FROM prekeys_seen WHERE peer_id = ?1",
        )?;

        let mut rows = stmt.query(params![peer_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let pub_vec: Vec<u8> = row.get(0)?;
        let sig_vec: Vec<u8> = row.get(1)?;

        // Defensive: corrupt rows with wrong widths just look like "no
        // cache" to the caller, which will refetch and re-verify.
        let Ok(pub_arr): Result<[u8; 32], _> = pub_vec.try_into() else {
            return Ok(None);
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_vec.try_into() else {
            return Ok(None);
        };

        Ok(Some((pub_arr, sig_arr)))
    }

    /// Get messages between two peers. Returns plaintext content.
    pub fn get_conversation(&self, peer1: &[u8], peer2: &[u8], limit: usize) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, recipient, ciphertext, timestamp, ttl
             FROM messages
             WHERE (sender = ?1 AND recipient = ?2) OR (sender = ?2 AND recipient = ?1)
             ORDER BY timestamp ASC
             LIMIT ?3"
        )?;

        let messages = stmt
            .query_map(params![peer1, peer2, limit as i64], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    sender: row.get(1)?,
                    recipient: row.get(2)?,
                    ciphertext: row.get(3)?,
                    timestamp: row.get(4)?,
                    ttl: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|m| self.decrypt_message_row(m))
            .collect();

        Ok(messages)
    }

    /// Decrypt the `ciphertext` field of a freshly-read row in place.
    /// Returns `None` if the row can't be decrypted — caller skips it.
    fn decrypt_message_row(&self, mut m: StoredMessage) -> Option<StoredMessage> {
        match self.decrypt_at_rest(&m.ciphertext) {
            Ok(plain) => {
                m.ciphertext = plain;
                Some(m)
            }
            Err(e) => {
                tracing::warn!("Dropping message row id={}: {}", m.id, e);
                None
            }
        }
    }
}

fn chrono_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_dek() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn prekey_roundtrip() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();

        let peer = [9u8; 38]; // PeerId byte length varies; the column is BLOB.
        let pubkey = [7u8; 32];
        let sig = [3u8; 64];

        assert!(store.load_prekey(&peer).unwrap().is_none());
        store.save_prekey(&peer, &pubkey, &sig).unwrap();

        let (got_pub, got_sig) = store.load_prekey(&peer).unwrap().expect("present");
        assert_eq!(got_pub, pubkey);
        assert_eq!(got_sig, sig);

        // Rotation: save a new prekey for the same peer, latest wins.
        let pubkey2 = [4u8; 32];
        let sig2 = [5u8; 64];
        store.save_prekey(&peer, &pubkey2, &sig2).unwrap();
        let (got_pub2, got_sig2) = store.load_prekey(&peer).unwrap().expect("present");
        assert_eq!(got_pub2, pubkey2);
        assert_eq!(got_sig2, sig2);
    }

    #[test]
    fn prekey_unknown_peer_returns_none() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        assert!(store.load_prekey(&[1, 2, 3]).unwrap().is_none());
    }

    #[test]
    fn load_otpk_private_skips_consumed_rows() {
        // F3 regression: prior to the fix, `load_otpk_private(id)`
        // returned the private bytes as long as the row existed,
        // regardless of `consumed_at`. A replay of a first-message
        // could then re-bootstrap a responder session even after the
        // OTPK was consumed, wiping any subsequent chain progress.
        // Now the SQL guards `consumed_at IS NULL` so a consumed row
        // looks identical to "row was already GC'd" — caller drops
        // the message.
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();

        let priv_bytes = [7u8; 32];
        let pub_bytes = [8u8; 32];
        let sig = [9u8; 64];
        let id = store.add_my_otpk(&priv_bytes, &pub_bytes, &sig).unwrap();

        // Pre-consume: loadable.
        assert_eq!(
            store.load_otpk_private(id).unwrap().as_ref(),
            Some(&priv_bytes)
        );

        // Consume via pop. The row stays in the table (consumed_at set);
        // `delete_otpk` would remove it physically — F3 covers the
        // window in between.
        let (popped_id, _, _) = store.pop_unused_otpk().unwrap().unwrap();
        assert_eq!(popped_id, id);

        // Post-consume: load returns None even though the row still
        // exists — confirming the consumed_at gate.
        assert!(store.load_otpk_private(id).unwrap().is_none());
    }

    #[test]
    fn session_roundtrip() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [1u8; 38];
        assert!(store.load_session(&peer).unwrap().is_none());
        store.save_session(&peer, b"{\"some\":\"blob\"}").unwrap();
        assert_eq!(
            store.load_session(&peer).unwrap().as_deref(),
            Some(b"{\"some\":\"blob\"}".as_ref())
        );
        // Update overwrites.
        store.save_session(&peer, b"{\"newer\":1}").unwrap();
        assert_eq!(
            store.load_session(&peer).unwrap().as_deref(),
            Some(b"{\"newer\":1}".as_ref())
        );
    }

    #[test]
    fn session_blob_is_actually_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [2u8; 38];
        let secret_text = b"top-secret-needle-marker-xyzzy";
        store.save_session(&peer, secret_text).unwrap();

        // Read the raw row bypassing decrypt — must NOT contain the marker.
        let mut stmt = store
            .conn
            .prepare("SELECT state_blob FROM ratchet_sessions WHERE peer_id = ?1")
            .unwrap();
        let raw: Vec<u8> = stmt.query_row(params![&peer[..]], |row| row.get(0)).unwrap();
        assert!(
            !contains_subslice(&raw, secret_text),
            "ratchet_sessions.state_blob still contains plaintext — encryption-at-rest broken"
        );
        // And the version byte should be present.
        assert_eq!(raw[0], AT_REST_VERSION);
    }

    #[test]
    fn wrong_dek_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let store_a = MessageStore::open(dir.path(), [1u8; 32]).unwrap();
        store_a.save_session(&[3u8; 38], b"payload").unwrap();
        drop(store_a);

        // Reopen with a different DEK — load_session must error.
        let store_b = MessageStore::open(dir.path(), [2u8; 32]).unwrap();
        let res = store_b.load_session(&[3u8; 38]);
        assert!(res.is_err(), "decrypt should fail with wrong DEK, got {:?}", res);
    }

    fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn message_content_is_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let sender = [1u8; 38];
        let recipient = [2u8; 38];
        let marker = b"unique-plaintext-marker-blorbo";
        store.store_message(&sender, &recipient, marker, 60).unwrap();

        // Raw row must not contain the marker.
        let mut stmt = store
            .conn
            .prepare("SELECT ciphertext FROM messages WHERE recipient = ?1")
            .unwrap();
        let raw: Vec<u8> = stmt
            .query_row(params![&recipient[..]], |row| row.get(0))
            .unwrap();
        assert!(
            !contains_subslice(&raw, marker),
            "messages.ciphertext still contains plaintext — encryption-at-rest broken"
        );
        assert_eq!(raw[0], AT_REST_VERSION);

        // Round-trip via public API gives plaintext back.
        let history = store.get_recent_messages(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].ciphertext, marker);
    }

    #[test]
    fn outbox_queue_drain_delete() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [7u8; 38];

        assert!(store.outbox_get_for(&peer).unwrap().is_empty());
        let id1 = store.outbox_add(&peer, b"hello bob", 60).unwrap();
        let id2 = store.outbox_add(&peer, b"and a follow-up", 60).unwrap();

        let queued = store.outbox_get_for(&peer).unwrap();
        assert_eq!(queued.len(), 2);
        // The plaintext path returns is_wire_bytes = false.
        assert_eq!(queued[0], (id1, b"hello bob".to_vec(), false));
        assert_eq!(queued[1], (id2, b"and a follow-up".to_vec(), false));

        // After delivery, caller deletes.
        store.outbox_delete(id1).unwrap();
        let after = store.outbox_get_for(&peer).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, id2);
    }

    #[test]
    fn outbox_add_wire_round_trips_with_kind_flag() {
        // Phase 5: outbox_add_wire stores already-encrypted bytes and
        // returns them via outbox_get_for tagged is_wire_bytes = true,
        // so the drain path knows not to re-encrypt.
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [11u8; 38];

        let plain_id = store.outbox_add(&peer, b"plaintext one", 60).unwrap();
        let wire_id = store
            .outbox_add_wire(&peer, b"opaque-protocol-message-bytes", 60)
            .unwrap();

        let queued = store.outbox_get_for(&peer).unwrap();
        assert_eq!(queued.len(), 2);
        // Insertion order preserved.
        let (got_plain_id, got_plain, got_plain_wire) = &queued[0];
        let (got_wire_id, got_wire, got_wire_wire) = &queued[1];
        assert_eq!(*got_plain_id, plain_id);
        assert_eq!(got_plain.as_slice(), b"plaintext one");
        assert!(!got_plain_wire, "plaintext rows must report is_wire_bytes=false");
        assert_eq!(*got_wire_id, wire_id);
        assert_eq!(got_wire.as_slice(), b"opaque-protocol-message-bytes");
        assert!(got_wire_wire, "wire rows must report is_wire_bytes=true");
    }

    #[test]
    fn outbox_is_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [8u8; 38];
        let marker = b"outbox-secret-marker-fnord";
        store.outbox_add(&peer, marker, 60).unwrap();

        let mut stmt = store
            .conn
            .prepare("SELECT ciphertext FROM outbox WHERE peer_id = ?1")
            .unwrap();
        let raw: Vec<u8> = stmt
            .query_row(params![&peer[..]], |row| row.get(0))
            .unwrap();
        assert!(!contains_subslice(&raw, marker), "outbox ciphertext leaks plaintext");
        assert_eq!(raw[0], AT_REST_VERSION);
    }

    #[test]
    fn outbox_cleanup_expired_drops_old_rows() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [9u8; 38];

        // Add a row with a very old created_at to simulate expiry.
        let _id = store.outbox_add(&peer, b"old", 1).unwrap();
        // Backdate the row directly so it's already expired.
        store
            .conn
            .execute(
                "UPDATE outbox SET created_at = 0 WHERE peer_id = ?1",
                params![&peer[..]],
            )
            .unwrap();

        let deleted = store.outbox_cleanup_expired().unwrap();
        assert_eq!(deleted, 1);
        assert!(store.outbox_get_for(&peer).unwrap().is_empty());
    }

    #[test]
    fn mailbox_drops_basic_lifecycle() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let recip = [0xAAu8; 38];
        let now = chrono_time();

        let id = store
            .mailbox_drop_record(&recip, 12345, b"ciphertext-bytes", now + 86400)
            .unwrap();

        // Initially the row is its own most-recent publish — not due for
        // republish if threshold is 0 seconds (last_published_at == now).
        let due = store.mailbox_drops_due_for_republish(0).unwrap();
        assert!(due.iter().all(|(rid, ..)| *rid != id));

        // After a long-enough threshold it shows up.
        let due = store.mailbox_drops_due_for_republish(-10).unwrap();
        assert!(due.iter().any(|(rid, ..)| *rid == id));
        let (_, got_recip, got_slot, got_ct) =
            due.iter().find(|(rid, ..)| *rid == id).unwrap();
        assert_eq!(got_recip, &recip[..]);
        assert_eq!(*got_slot, 12345);
        assert_eq!(got_ct, b"ciphertext-bytes");

        // Mark republished — last_published_at advances.
        store.mailbox_drop_touch(id).unwrap();
        let due = store.mailbox_drops_due_for_republish(0).unwrap();
        assert!(due.iter().all(|(rid, ..)| *rid != id));

        // ACK removes from due-list.
        store.mailbox_drop_ack(id).unwrap();
        let due = store.mailbox_drops_due_for_republish(-10).unwrap();
        assert!(due.iter().all(|(rid, ..)| *rid != id));
    }

    #[test]
    fn mailbox_drop_ciphertext_is_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let needle = b"mailbox-secret-pls-no-leak";
        store
            .mailbox_drop_record(&[0xBBu8; 38], 1, needle, chrono_time() + 3600)
            .unwrap();
        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT wire_ciphertext FROM mailbox_drops LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!contains_subslice(&raw, needle));
        assert_eq!(raw[0], AT_REST_VERSION);
    }

    #[test]
    fn mailbox_poll_state_roundtrip() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        assert_eq!(store.mailbox_last_polled_slot().unwrap(), 0);
        store.mailbox_set_last_polled_slot(42).unwrap();
        assert_eq!(store.mailbox_last_polled_slot().unwrap(), 42);
        // Idempotent update.
        store.mailbox_set_last_polled_slot(100).unwrap();
        assert_eq!(store.mailbox_last_polled_slot().unwrap(), 100);
    }

    #[test]
    fn mailbox_drops_cleanup_drops_expired_and_old_acks() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let recip = [0xCCu8; 38];

        // Expired
        let id_exp = store
            .mailbox_drop_record(&recip, 1, b"e", chrono_time() - 1)
            .unwrap();
        // Live + ACKed long ago
        let id_old_ack = store
            .mailbox_drop_record(&recip, 2, b"o", chrono_time() + 86400)
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE mailbox_drops SET acknowledged_at = 0 WHERE id = ?1",
                params![id_old_ack],
            )
            .unwrap();
        // Live, not acked
        let id_live = store
            .mailbox_drop_record(&recip, 3, b"l", chrono_time() + 86400)
            .unwrap();

        let removed = store.mailbox_drops_cleanup().unwrap();
        assert_eq!(removed, 2);

        let due = store.mailbox_drops_due_for_republish(-1).unwrap();
        let ids: Vec<i64> = due.iter().map(|(id, ..)| *id).collect();
        assert!(!ids.contains(&id_exp));
        assert!(!ids.contains(&id_old_ack));
        assert!(ids.contains(&id_live));
    }

    #[test]
    fn message_with_wrong_dek_is_skipped_not_errored() {
        // A row encrypted with DEK_A becomes unreadable to DEK_B; the
        // get_recent_messages call should still succeed and just skip it,
        // not bubble an error.
        let dir = tempdir().unwrap();
        {
            let store_a = MessageStore::open(dir.path(), [9u8; 32]).unwrap();
            store_a
                .store_message(&[1u8; 38], &[2u8; 38], b"hello", 60)
                .unwrap();
        }
        let store_b = MessageStore::open(dir.path(), [3u8; 32]).unwrap();
        let history = store_b.get_recent_messages(10).unwrap();
        assert!(history.is_empty(), "row encrypted with wrong DEK should be filtered");
    }
}

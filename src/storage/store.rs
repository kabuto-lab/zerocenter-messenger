use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac};
use rand::RngCore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use tracing::info;

/// Version byte that prefixes every AEAD-encrypted blob stored at rest
/// (ratchet session state, message content, etc). Bump if the AEAD
/// construction changes (algorithm, AAD layout, nonce size).
const AT_REST_VERSION: u8 = 1;
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// Domain separator for the `outbox.peer_id` HMAC tag (audit finding
/// F12). A dedicated constant keeps this DEK-keyed MAC from ever
/// colliding with another at-rest MAC the codebase might add later.
const OUTBOX_PEER_DOMAIN: &[u8] = b"ME55-outbox-peer-v1";

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
        // /ME55/prekey/1.0.0 response handler. Each row's signature
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
        //
        // An OTPK moves through three states, tracked by two nullable
        // timestamp columns:
        //   - both NULL       → fresh, available to hand out
        //   - served_at set   → handed to an initiator in a prekey
        //                       response; must not be served again, but
        //                       the private key is STILL needed to
        //                       complete the responder X3DH when that
        //                       initiator's first message lands
        //   - consumed_at set → that first message has been decrypted;
        //                       the key is spent and a replay of the
        //                       first message must be rejected
        // Collapsing "served" and "consumed" into one column was the bug
        // behind dropped first DMs: `pop_unused_otpk` marked the row at
        // serve time, so `load_otpk_private` (gated on the spent state)
        // refused the key for the very first legitimate use.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS my_otpks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                x25519_priv   BLOB NOT NULL,
                x25519_pub    BLOB NOT NULL,
                signature     BLOB NOT NULL,
                created_at    INTEGER NOT NULL,
                served_at     INTEGER,
                consumed_at   INTEGER
            )",
            [],
        )?;

        // Pre-fix databases predate the `served_at` column and used
        // `consumed_at` as the serve-time marker. Add the column (the
        // "duplicate column" error is ignored exactly like the
        // outbox.is_wire_bytes migration below), then backfill: a row
        // the old code marked `consumed_at` was really only *served* —
        // the collapsed-state bug meant no 3-DH first message ever
        // actually completed — so treat it as served. `consumed_at`
        // stays set, which correctly keeps `load_otpk_private` gating
        // out that dead handshake. New databases get `served_at` at
        // CREATE time and the backfill matches nothing.
        if let Err(e) = conn.execute(
            "ALTER TABLE my_otpks ADD COLUMN served_at INTEGER",
            [],
        ) {
            let msg = format!("{}", e);
            if !msg.contains("duplicate column") {
                return Err(e.into());
            }
        }
        conn.execute(
            "UPDATE my_otpks SET served_at = consumed_at
              WHERE consumed_at IS NOT NULL AND served_at IS NULL",
            [],
        )?;

        // Outbox: messages we wanted to send but the recipient wasn't
        // connected at the time. Drained when ConnectionEstablished
        // fires for that peer. Plaintext is AEAD-encrypted at rest so
        // a disk-read attacker can't see queued messages; `peer_id`
        // holds an HMAC tag (not the raw PeerId) so the same attacker
        // also can't see *who* has mail queued — see `outbox_peer_tag`.
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

        // F12 (audit) — outbox.peer_id at-rest hardening. Pre-F12
        // databases stored the recipient PeerId in the clear in
        // `outbox.peer_id`, leaking who-has-mail-queued to a disk-read
        // attacker even though the message body was encrypted. The
        // column now holds an HMAC tag (see `outbox_peer_tag`); re-tag
        // any rows left over from a pre-F12 build exactly once. Gated
        // on `PRAGMA user_version` so a normal startup — and a fresh
        // database, which has no rows anyway — skips the table scan.
        let schema_version: i64 =
            conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if schema_version < 1 {
            let legacy_rows: Vec<(i64, Vec<u8>)> = {
                let mut stmt = conn.prepare("SELECT id, peer_id FROM outbox")?;
                let collected = stmt
                    .query_map([], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                collected
            };
            for (id, raw_peer) in legacy_rows {
                conn.execute(
                    "UPDATE outbox SET peer_id = ?1 WHERE id = ?2",
                    params![outbox_peer_tag(&dek, &raw_peer), id],
                )?;
            }
            conn.execute("PRAGMA user_version = 1", [])?;
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

        // Phase 5 group chats. Five tables: `groups` and
        // `group_members` are public metadata (member PeerIds in clear
        // — same trade-off as `messages.sender/recipient`, query-
        // efficiency over metadata privacy). `my_sender_keys` and
        // `their_sender_keys` carry Megolm chain state and are AEAD-
        // wrapped at rest under the DEK exactly like
        // `ratchet_sessions.state_blob`. `group_messages` carries the
        // decrypted plaintext for the user's local conversation view,
        // also AEAD-wrapped.
        //
        // The schema is deliberately separate from the DM `messages`
        // table — group-message rows have a group_id and no recipient
        // PeerId in the DM sense (the recipient is the group itself,
        // and every member has their own local copy).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS groups (
                group_id    BLOB PRIMARY KEY,
                name        TEXT NOT NULL,
                founder_pid BLOB NOT NULL,
                epoch       INTEGER NOT NULL,
                created_at  INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_members (
                group_id  BLOB NOT NULL,
                peer_id   BLOB NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, peer_id)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_group_members_gid ON group_members(group_id)",
            [],
        )?;

        // My own per-group sender chain. One row per group I belong to.
        // `state_blob` is the AEAD-wrapped JSON of `crypto::megolm::
        // SenderChain` (chain_key + index + ed25519 signing key).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS my_sender_keys (
                group_id   BLOB PRIMARY KEY,
                state_blob BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;

        // Per-(group, member) sender chain that *they* are sending
        // from. One row per other member of each of my groups.
        // `state_blob` is the AEAD-wrapped JSON of
        // `crypto::megolm::ReceiverChain` (chain_key + next-index +
        // their ed25519 verify key + bounded skipped-keys cache, all
        // in one blob — mirrors the DR ratchet pattern of carrying its
        // own skipped queue inside the session blob).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS their_sender_keys (
                group_id   BLOB NOT NULL,
                peer_id    BLOB NOT NULL,
                state_blob BLOB NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, peer_id)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_their_sender_keys_gid
             ON their_sender_keys(group_id)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS group_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id   BLOB NOT NULL,
                sender     BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                timestamp  INTEGER NOT NULL,
                ttl        INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_group_messages_gid_ts
             ON group_messages(group_id, timestamp)",
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

    /// Count OTPKs still available to hand out — never served to any
    /// initiator. Drives `P2PNode::replenish_otpk_pool`.
    pub fn unused_otpk_count(&self) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM my_otpks WHERE served_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Atomically pop the oldest never-served OTPK and mark it served.
    /// Returns `(id, public_bytes, signature)`. The private bytes stay
    /// in the row — `load_otpk_private(id)` retrieves them when the
    /// initiator's first message lands, and `mark_otpk_consumed(id)`
    /// retires the row only then.
    ///
    /// Marking served at pop time (rather than after the responder
    /// confirms) is the conservative choice: a single OTPK is never
    /// served to two different initiator handshakes, even under
    /// concurrent prekey-fetch races. The cost is wasted OTPKs when an
    /// initiator fetches but never sends — pool size compensates.
    pub fn pop_unused_otpk(&self) -> Result<Option<(i64, [u8; 32], [u8; 64])>> {
        let now = chrono_time();
        // Single round-trip: pick the oldest never-served row, return
        // its public+signature, mark it served. UPDATE ... RETURNING is
        // a sqlite 3.35+ feature; bundled rusqlite ships current sqlite.
        let mut stmt = self.conn.prepare(
            "UPDATE my_otpks
                SET served_at = ?1
              WHERE id = (
                    SELECT id FROM my_otpks
                     WHERE served_at IS NULL
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
    /// Returns `None` if the id is unknown OR if the row is already spent
    /// (`consumed_at` set) — the audit's F3 finding.
    ///
    /// The gate is `consumed_at IS NULL`, NOT `served_at IS NULL`: a
    /// served-but-not-yet-spent OTPK MUST still load, because completing
    /// the responder X3DH for the initiator's first message is exactly
    /// what `served_at` was set in anticipation of. Gating on the spent
    /// state defends against a replay of that first message — the replay
    /// would otherwise re-derive the same SK and a fresh
    /// `RatchetState::new_responder` would overwrite in-memory chain
    /// progress on this peer.
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

    /// Mark an OTPK spent after a successful responder first-decrypt.
    /// This is the replay gate: once `consumed_at` is set,
    /// `load_otpk_private` refuses the key, so a replayed first message
    /// can no longer re-bootstrap a responder session. Distinct from
    /// `delete_otpk` (physical GC) — keeping the consumed marker means a
    /// replay stays rejected even if the row outlives a failed delete.
    pub fn mark_otpk_consumed(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE my_otpks SET consumed_at = ?1 WHERE id = ?2",
            params![chrono_time(), id],
        )?;
        Ok(())
    }

    /// Permanently delete an OTPK row — pure GC after `mark_otpk_consumed`.
    /// Optional: keeps the table small. Not strictly required — the
    /// `consumed_at` marker already blocks re-load and `served_at` blocks
    /// re-pop, so a row that survives a failed delete is still safe.
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
            params![outbox_peer_tag(&self.dek, peer_id), enc, chrono_time(), ttl_secs],
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
            params![outbox_peer_tag(&self.dek, peer_id), enc, chrono_time(), ttl_secs],
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
            .query_map(params![outbox_peer_tag(&self.dek, peer_id)], |row| {
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

    // ───────────────────────── Phase 5 group chats ─────────────────────────

    /// Insert or replace a `groups` row. `epoch=0` on initial create;
    /// callers bump it themselves on accepted MembershipUpdates.
    pub fn group_upsert(
        &self,
        group_id: &crate::protocol::GroupId,
        name: &str,
        founder_pid: &[u8],
        epoch: u64,
    ) -> Result<()> {
        let now = chrono_time();
        self.conn.execute(
            "INSERT INTO groups (group_id, name, founder_pid, epoch, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id) DO UPDATE SET
                 name = excluded.name,
                 founder_pid = excluded.founder_pid,
                 epoch = excluded.epoch",
            params![&group_id[..], name, founder_pid, epoch as i64, now],
        )?;
        Ok(())
    }

    /// Load a single group by id. Returns `None` if not present.
    pub fn group_get(
        &self,
        group_id: &crate::protocol::GroupId,
    ) -> Result<Option<crate::protocol::GroupRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, founder_pid, epoch, created_at
             FROM groups WHERE group_id = ?1",
        )?;
        let row = stmt
            .query_row(params![&group_id[..]], group_row_from_db)
            .ok();
        Ok(row.and_then(|r| r.ok()))
    }

    /// List all groups, oldest first.
    pub fn group_list(&self) -> Result<Vec<crate::protocol::GroupRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, founder_pid, epoch, created_at
             FROM groups ORDER BY created_at ASC",
        )?;
        let rows = stmt
            .query_map([], group_row_from_db)?
            .filter_map(|r| r.ok().and_then(|x| x.ok()))
            .collect();
        Ok(rows)
    }

    /// Bump a group's epoch. Called on accepted MembershipUpdates.
    pub fn group_bump_epoch(
        &self,
        group_id: &crate::protocol::GroupId,
        new_epoch: u64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE groups SET epoch = ?1 WHERE group_id = ?2",
            params![new_epoch as i64, &group_id[..]],
        )?;
        Ok(())
    }

    /// Add a member to a group. Idempotent — re-adding leaves the
    /// original `joined_at` untouched (ON CONFLICT DO NOTHING).
    pub fn group_member_add(
        &self,
        group_id: &crate::protocol::GroupId,
        peer_id: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO group_members (group_id, peer_id, joined_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, peer_id) DO NOTHING",
            params![&group_id[..], peer_id, chrono_time()],
        )?;
        Ok(())
    }

    /// Remove a member from a group. No-op if not present.
    pub fn group_member_remove(
        &self,
        group_id: &crate::protocol::GroupId,
        peer_id: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND peer_id = ?2",
            params![&group_id[..], peer_id],
        )?;
        Ok(())
    }

    /// List a group's members as PeerId byte strings.
    pub fn group_members(
        &self,
        group_id: &crate::protocol::GroupId,
    ) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_id FROM group_members WHERE group_id = ?1 ORDER BY joined_at ASC")?;
        let rows = stmt
            .query_map(params![&group_id[..]], |r| r.get::<_, Vec<u8>>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Drop the entire group: removes the `groups` row, all members,
    /// my sender chain, and all their-sender-chains. Used on `leave`
    /// (self-leave) and after receiving a remove-me MembershipUpdate.
    /// Group-message history rows are kept for local audit.
    pub fn group_forget(&self, group_id: &crate::protocol::GroupId) -> Result<()> {
        self.conn.execute(
            "DELETE FROM their_sender_keys WHERE group_id = ?1",
            params![&group_id[..]],
        )?;
        self.conn.execute(
            "DELETE FROM my_sender_keys WHERE group_id = ?1",
            params![&group_id[..]],
        )?;
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1",
            params![&group_id[..]],
        )?;
        self.conn.execute(
            "DELETE FROM groups WHERE group_id = ?1",
            params![&group_id[..]],
        )?;
        Ok(())
    }

    /// Save my sender-chain state for a group. `state_plaintext` is
    /// the JSON of `crypto::megolm::SenderChain`; AEAD-wrapped under
    /// the DEK before write.
    pub fn my_sender_key_save(
        &self,
        group_id: &crate::protocol::GroupId,
        state_plaintext: &[u8],
    ) -> Result<()> {
        let blob = self.encrypt_at_rest(state_plaintext);
        self.conn.execute(
            "INSERT OR REPLACE INTO my_sender_keys (group_id, state_blob, updated_at)
             VALUES (?1, ?2, ?3)",
            params![&group_id[..], blob, chrono_time()],
        )?;
        Ok(())
    }

    /// Load my sender-chain state. Returns `None` if no row exists.
    /// AEAD failure is silent-skip (returns `None`) so a single
    /// corrupt row doesn't block all group work.
    pub fn my_sender_key_load(
        &self,
        group_id: &crate::protocol::GroupId,
    ) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state_blob FROM my_sender_keys WHERE group_id = ?1")?;
        let blob: Option<Vec<u8>> = stmt
            .query_row(params![&group_id[..]], |r| r.get(0))
            .ok();
        match blob {
            Some(b) => match self.decrypt_at_rest(&b) {
                Ok(pt) => Ok(Some(pt)),
                Err(e) => {
                    tracing::warn!("Skipping my_sender_keys row: {}", e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Save a peer's sender-chain receiver state for a group.
    pub fn their_sender_key_save(
        &self,
        group_id: &crate::protocol::GroupId,
        peer_id: &[u8],
        state_plaintext: &[u8],
    ) -> Result<()> {
        let blob = self.encrypt_at_rest(state_plaintext);
        self.conn.execute(
            "INSERT OR REPLACE INTO their_sender_keys
             (group_id, peer_id, state_blob, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![&group_id[..], peer_id, blob, chrono_time()],
        )?;
        Ok(())
    }

    /// Load a peer's sender-chain receiver state.
    pub fn their_sender_key_load(
        &self,
        group_id: &crate::protocol::GroupId,
        peer_id: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT state_blob FROM their_sender_keys
             WHERE group_id = ?1 AND peer_id = ?2",
        )?;
        let blob: Option<Vec<u8>> = stmt
            .query_row(params![&group_id[..], peer_id], |r| r.get(0))
            .ok();
        match blob {
            Some(b) => match self.decrypt_at_rest(&b) {
                Ok(pt) => Ok(Some(pt)),
                Err(e) => {
                    tracing::warn!("Skipping their_sender_keys row: {}", e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Drop a peer's sender-chain state. Used when the peer is
    /// removed from a group or rotates their key (the old chain is
    /// discarded so future messages must use the new one).
    pub fn their_sender_key_delete(
        &self,
        group_id: &crate::protocol::GroupId,
        peer_id: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM their_sender_keys WHERE group_id = ?1 AND peer_id = ?2",
            params![&group_id[..], peer_id],
        )?;
        Ok(())
    }

    /// Persist a decrypted group message. Returns the row id.
    pub fn group_message_store(
        &self,
        group_id: &crate::protocol::GroupId,
        sender: &[u8],
        plaintext: &[u8],
        ttl_secs: i64,
    ) -> Result<i64> {
        let encrypted = self.encrypt_at_rest(plaintext);
        self.conn.execute(
            "INSERT INTO group_messages (group_id, sender, ciphertext, timestamp, ttl)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&group_id[..], sender, encrypted, chrono_time(), ttl_secs],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Load all messages in a group, oldest first. Rows whose at-rest
    /// blob fails to decrypt are silently skipped (same policy as
    /// `get_messages`).
    pub fn group_messages_get(
        &self,
        group_id: &crate::protocol::GroupId,
    ) -> Result<Vec<crate::protocol::GroupStoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, sender, ciphertext, timestamp, ttl
             FROM group_messages
             WHERE group_id = ?1
             ORDER BY timestamp ASC",
        )?;
        let rows: Vec<_> = stmt
            .query_map(params![&group_id[..]], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, gid_bytes, sender, blob, timestamp, ttl)| {
                let plaintext = match self.decrypt_at_rest(&blob) {
                    Ok(pt) => pt,
                    Err(e) => {
                        tracing::warn!("Skipping group_messages id={}: {}", id, e);
                        return None;
                    }
                };
                let mut group_id = [0u8; 32];
                if gid_bytes.len() != 32 {
                    return None;
                }
                group_id.copy_from_slice(&gid_bytes);
                Some(crate::protocol::GroupStoredMessage {
                    id,
                    group_id,
                    sender,
                    plaintext,
                    timestamp,
                    ttl,
                })
            })
            .collect();
        Ok(rows)
    }
}

/// Inflate a `groups` row from SQL. Outer `Result` is sqlite's; inner
/// `Result` flags a bad-shape `group_id` blob length so the caller can
/// drop the row instead of panicking.
fn group_row_from_db(
    r: &rusqlite::Row,
) -> rusqlite::Result<Result<crate::protocol::GroupRow, ()>> {
    let gid_bytes: Vec<u8> = r.get(0)?;
    let name: String = r.get(1)?;
    let founder_pid: Vec<u8> = r.get(2)?;
    let epoch: i64 = r.get(3)?;
    let created_at: i64 = r.get(4)?;
    if gid_bytes.len() != 32 {
        return Ok(Err(()));
    }
    let mut group_id = [0u8; 32];
    group_id.copy_from_slice(&gid_bytes);
    Ok(Ok(crate::protocol::GroupRow {
        group_id,
        name,
        founder_pid,
        epoch: epoch as u64,
        created_at,
    }))
}

fn chrono_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Deterministically tag a recipient `PeerId` for storage in the
/// `outbox.peer_id` column (audit finding F12).
///
/// Pre-F12 the column held the raw `PeerId` bytes, so a disk-read
/// attacker without the OS-keyring DEK could enumerate exactly who had
/// undelivered mail queued — the message body was encrypted, the
/// recipient was not. The stored value is now
/// `HMAC-SHA256(DEK, OUTBOX_PEER_DOMAIN || peer_id)`:
///
/// - keyed by the DEK, so the mapping is opaque without the keyring;
/// - deterministic (unlike `encrypt_at_rest`, which uses a random
///   nonce), so the equality lookup in `outbox_get_for` and the
///   `idx_outbox_peer` index keep working unchanged;
/// - one-way, which is sufficient: `drain_outbox_for` is only ever
///   called with a `PeerId` already in hand, so the column never
///   needs to be reversed.
///
/// An attacker who already holds the DEK can confirm a *guessed*
/// PeerId by recomputing the tag — but that same attacker can already
/// decrypt every queued body, so this draws the line at the DEK
/// boundary, matching the rest of the at-rest model.
fn outbox_peer_tag(dek: &[u8; 32], peer_id: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(dek)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(OUTBOX_PEER_DOMAIN);
    mac.update(peer_id);
    mac.finalize().into_bytes().to_vec()
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
    fn otpk_lifecycle_serve_then_consume() {
        // The OTPK three-state lifecycle, end to end:
        //   fresh        → load_otpk_private returns the key
        //   served (pop) → STILL returns the key (the responder needs
        //                  it to complete X3DH for the initiator's
        //                  first DM)
        //   consumed     → returns None — the F3 replay gate
        // Regression guard: an earlier version collapsed "served" and
        // "consumed" into one column, so pop() alone made
        // load_otpk_private return None and EVERY 3-DH first message
        // was dropped with "OTPK id=N not found in our store".
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();

        let priv_bytes = [7u8; 32];
        let pub_bytes = [8u8; 32];
        let sig = [9u8; 64];
        let id = store.add_my_otpk(&priv_bytes, &pub_bytes, &sig).unwrap();

        // Fresh: loadable, and counted as available.
        assert_eq!(store.unused_otpk_count().unwrap(), 1);
        assert_eq!(
            store.load_otpk_private(id).unwrap().as_ref(),
            Some(&priv_bytes)
        );

        // Serve via pop: the row leaves the available pool, but the
        // private key MUST still load — this is the bug fix.
        let (popped_id, _, _) = store.pop_unused_otpk().unwrap().unwrap();
        assert_eq!(popped_id, id);
        assert_eq!(store.unused_otpk_count().unwrap(), 0);
        assert_eq!(
            store.load_otpk_private(id).unwrap().as_ref(),
            Some(&priv_bytes),
            "served-but-not-spent OTPK must still load"
        );

        // A second pop must not hand out the same OTPK again.
        assert!(store.pop_unused_otpk().unwrap().is_none());

        // Consume after a successful first-decrypt: the F3 replay gate
        // now kicks in and the key is no longer retrievable.
        store.mark_otpk_consumed(id).unwrap();
        assert!(
            store.load_otpk_private(id).unwrap().is_none(),
            "consumed OTPK must not load (F3 replay gate)"
        );

        // delete_otpk is pure GC; load stays None afterwards.
        store.delete_otpk(id).unwrap();
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

        // peer_id is HMAC-tagged at rest (F12), so a by-peer filter on
        // the raw peer would no longer match; the single row is enough.
        let mut stmt = store
            .conn
            .prepare("SELECT ciphertext FROM outbox")
            .unwrap();
        let raw: Vec<u8> = stmt.query_row([], |row| row.get(0)).unwrap();
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
        // Backdate the row directly so it's already expired. (peer_id
        // is HMAC-tagged at rest now, so backdate the lone row outright
        // rather than filtering by the raw peer.)
        store
            .conn
            .execute("UPDATE outbox SET created_at = 0", [])
            .unwrap();

        let deleted = store.outbox_cleanup_expired().unwrap();
        assert_eq!(deleted, 1);
        assert!(store.outbox_get_for(&peer).unwrap().is_empty());
    }

    #[test]
    fn outbox_peer_id_is_hmac_tagged_at_rest() {
        // F12: the recipient PeerId must not sit in the clear in the
        // outbox.peer_id column. After an add, the stored value is the
        // 32-byte HMAC tag — not the raw peer — and lookup still works.
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let peer = [13u8; 38];

        store.outbox_add(&peer, b"queued for later", 60).unwrap();

        let stored: Vec<u8> = store
            .conn
            .query_row("SELECT peer_id FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_ne!(stored, peer.to_vec(), "raw PeerId must not be on disk");
        assert_eq!(stored.len(), 32, "stored peer_id is an HMAC-SHA256 tag");
        assert_eq!(stored, outbox_peer_tag(&test_dek(), &peer));

        // Lookup by the original peer still resolves the row.
        let queued = store.outbox_get_for(&peer).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].1, b"queued for later");

        // A different DEK produces a different tag — the mapping is
        // opaque without the keyring key.
        assert_ne!(
            outbox_peer_tag(&[7u8; 32], &peer),
            outbox_peer_tag(&test_dek(), &peer),
        );
    }

    #[test]
    fn outbox_peer_id_migration_retags_legacy_rows() {
        // A pre-F12 database has raw PeerId bytes in outbox.peer_id and
        // user_version = 0. Re-opening the store must re-tag those rows
        // so drain still finds them — without the migration, mail
        // queued before the upgrade would be silently orphaned.
        let dir = tempdir().unwrap();
        let peer = [21u8; 38];

        {
            let store = MessageStore::open(dir.path(), test_dek()).unwrap();
            // Simulate a pre-F12 row: raw peer_id in the column, and
            // rewind the schema marker so the next open re-migrates.
            let body = store.encrypt_at_rest(b"legacy queued message");
            store
                .conn
                .execute(
                    "INSERT INTO outbox
                       (peer_id, ciphertext, created_at, ttl, is_wire_bytes)
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    params![&peer[..], body, chrono_time(), 3600],
                )
                .unwrap();
            store.conn.execute("PRAGMA user_version = 0", []).unwrap();
        }

        // Re-open: the F12 migration runs and re-tags the legacy row.
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();

        let stored: Vec<u8> = store
            .conn
            .query_row("SELECT peer_id FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, outbox_peer_tag(&test_dek(), &peer));

        // The legacy row is now reachable through the normal API.
        let queued = store.outbox_get_for(&peer).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].1, b"legacy queued message");

        // The migration is one-shot: user_version is bumped, so a
        // second open must not double-tag the (now 32-byte) value.
        drop(store);
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let again: Vec<u8> = store
            .conn
            .query_row("SELECT peer_id FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(again, outbox_peer_tag(&test_dek(), &peer));
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

    // ─────────────────── Phase 5 group-chat storage tests ───────────────────

    fn gid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn group_upsert_and_get_roundtrip() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();

        let g = gid(0xA1);
        assert!(store.group_get(&g).unwrap().is_none());

        store.group_upsert(&g, "team-alpha", &[1u8; 38], 0).unwrap();
        let row = store.group_get(&g).unwrap().expect("present");
        assert_eq!(row.group_id, g);
        assert_eq!(row.name, "team-alpha");
        assert_eq!(row.founder_pid, vec![1u8; 38]);
        assert_eq!(row.epoch, 0);

        // Upsert with new epoch + name; row is updated in place.
        store.group_upsert(&g, "team-alpha-v2", &[1u8; 38], 3).unwrap();
        let row2 = store.group_get(&g).unwrap().expect("present");
        assert_eq!(row2.name, "team-alpha-v2");
        assert_eq!(row2.epoch, 3);
        assert_eq!(row2.created_at, row.created_at, "created_at preserved on upsert");
    }

    #[test]
    fn group_list_returns_all_groups_oldest_first() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        store.group_upsert(&gid(1), "first", &[1u8; 38], 0).unwrap();
        store.group_upsert(&gid(2), "second", &[2u8; 38], 0).unwrap();
        let list = store.group_list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "first");
        assert_eq!(list[1].name, "second");
    }

    #[test]
    fn group_bump_epoch_persists() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(7);
        store.group_upsert(&g, "g", &[1u8; 38], 0).unwrap();
        store.group_bump_epoch(&g, 12).unwrap();
        assert_eq!(store.group_get(&g).unwrap().unwrap().epoch, 12);
    }

    #[test]
    fn group_member_add_remove_idempotent() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(1);
        store.group_upsert(&g, "g", &[0u8; 38], 0).unwrap();

        let alice = [0xAAu8; 38];
        let bob = [0xBBu8; 38];

        store.group_member_add(&g, &alice).unwrap();
        store.group_member_add(&g, &bob).unwrap();
        // Re-adding alice is a no-op (ON CONFLICT DO NOTHING).
        store.group_member_add(&g, &alice).unwrap();

        let members = store.group_members(&g).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&alice.to_vec()));
        assert!(members.contains(&bob.to_vec()));

        store.group_member_remove(&g, &alice).unwrap();
        // Remove of an absent member is a no-op (idempotent).
        store.group_member_remove(&g, &alice).unwrap();
        let members = store.group_members(&g).unwrap();
        assert_eq!(members, vec![bob.to_vec()]);
    }

    #[test]
    fn my_sender_key_roundtrip_and_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(0xCC);
        let plaintext = b"opaque-chain-state-blob".to_vec();

        assert!(store.my_sender_key_load(&g).unwrap().is_none());
        store.my_sender_key_save(&g, &plaintext).unwrap();
        let loaded = store.my_sender_key_load(&g).unwrap().expect("present");
        assert_eq!(loaded, plaintext);

        // Direct table read returns the AEAD-wrapped bytes, NOT the
        // plaintext — protects against a "we accidentally stored it
        // plaintext" regression.
        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT state_blob FROM my_sender_keys WHERE group_id = ?1",
                params![&g[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(raw, plaintext, "state_blob must be ciphertext on disk");
        assert!(raw.len() > plaintext.len(), "AEAD adds nonce + tag overhead");
    }

    #[test]
    fn their_sender_key_roundtrip_per_peer() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(0xDD);
        let alice = [0xAAu8; 38];
        let bob = [0xBBu8; 38];

        store.their_sender_key_save(&g, &alice, b"alice-chain").unwrap();
        store.their_sender_key_save(&g, &bob, b"bob-chain").unwrap();
        assert_eq!(
            store.their_sender_key_load(&g, &alice).unwrap().as_deref(),
            Some(&b"alice-chain"[..])
        );
        assert_eq!(
            store.their_sender_key_load(&g, &bob).unwrap().as_deref(),
            Some(&b"bob-chain"[..])
        );

        store.their_sender_key_delete(&g, &alice).unwrap();
        assert!(store.their_sender_key_load(&g, &alice).unwrap().is_none());
        // Bob's chain is untouched.
        assert_eq!(
            store.their_sender_key_load(&g, &bob).unwrap().as_deref(),
            Some(&b"bob-chain"[..])
        );
    }

    #[test]
    fn group_message_store_and_get_oldest_first() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(0xEE);
        let alice = [0xAAu8; 38];
        let bob = [0xBBu8; 38];

        store.group_message_store(&g, &alice, b"hello", 60).unwrap();
        store.group_message_store(&g, &bob, b"hi", 60).unwrap();

        let history = store.group_messages_get(&g).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].plaintext, b"hello");
        assert_eq!(history[1].plaintext, b"hi");
        assert_eq!(history[0].sender, alice.to_vec());
        assert_eq!(history[1].sender, bob.to_vec());
    }

    #[test]
    fn group_message_is_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(0xEF);
        let alice = [0xAAu8; 38];
        let plaintext = b"sensitive group chat content";
        store.group_message_store(&g, &alice, plaintext, 60).unwrap();

        let raw: Vec<u8> = store
            .conn
            .query_row(
                "SELECT ciphertext FROM group_messages WHERE group_id = ?1",
                params![&g[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(raw, plaintext.to_vec());
        // Plaintext substring must not appear in the at-rest blob.
        assert!(
            raw.windows(plaintext.len()).all(|w| w != plaintext),
            "plaintext leaked into on-disk row"
        );
    }

    #[test]
    fn group_forget_removes_metadata_keeps_history() {
        let dir = tempdir().unwrap();
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        let g = gid(0xF0);
        let me = [0xAAu8; 38];

        store.group_upsert(&g, "g", &me, 0).unwrap();
        store.group_member_add(&g, &me).unwrap();
        store.my_sender_key_save(&g, b"my-chain").unwrap();
        store.their_sender_key_save(&g, &[0xBBu8; 38], b"their-chain").unwrap();
        store.group_message_store(&g, &me, b"historical msg", 60).unwrap();

        store.group_forget(&g).unwrap();

        assert!(store.group_get(&g).unwrap().is_none());
        assert!(store.group_members(&g).unwrap().is_empty());
        assert!(store.my_sender_key_load(&g).unwrap().is_none());
        assert!(store
            .their_sender_key_load(&g, &[0xBBu8; 38])
            .unwrap()
            .is_none());
        // Local message history is intentionally retained for audit.
        let history = store.group_messages_get(&g).unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn group_open_is_idempotent() {
        // Re-opening an existing db must not error on CREATE TABLE — all
        // schema statements use IF NOT EXISTS.
        let dir = tempdir().unwrap();
        let g = gid(0xAB);
        {
            let store = MessageStore::open(dir.path(), test_dek()).unwrap();
            store.group_upsert(&g, "persist", &[1u8; 38], 0).unwrap();
        }
        let store = MessageStore::open(dir.path(), test_dek()).unwrap();
        assert!(store.group_get(&g).unwrap().is_some());
    }
}

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

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

/// Local message storage using SQLite
pub struct MessageStore {
    conn: Connection,
}

impl MessageStore {
    /// Open or create database
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
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

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Store an encrypted message
    pub fn store_message(
        &self,
        sender: &[u8],
        recipient: &[u8],
        ciphertext: &[u8],
        ttl_secs: i64,
    ) -> Result<i64> {
        let timestamp = chrono_time();
        
        let id = self.conn.execute(
            "INSERT INTO messages (sender, recipient, ciphertext, timestamp, ttl)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sender, recipient, ciphertext, timestamp, ttl_secs],
        )? as i64;

        Ok(id)
    }

    /// Get messages for a recipient
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
            .collect::<Result<Vec<_>, _>>()?;

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

    /// Get recent messages (for history)
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
            .collect::<Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Get messages between two peers
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
            .collect::<Result<Vec<_>, _>>()?;

        Ok(messages)
    }
}

fn chrono_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

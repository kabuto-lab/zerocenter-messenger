use serde::{Deserialize, Serialize};

/// Protocol message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Recipient identifier (hash of public key)
    pub to: Vec<u8>,
    
    /// Sender identifier
    pub from: Vec<u8>,
    
    /// Encrypted payload
    pub payload: Vec<u8>,
    
    /// Unix timestamp
    pub timestamp: i64,
    
    /// Time to live in seconds
    pub ttl: i64,
    
    /// Message type
    pub msg_type: MessageType,
}

/// Type of message
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Direct message
    Direct = 0,
    
    /// Group message
    Group = 1,
    
    /// File transfer
    File = 2,
    
    /// Voice message
    Voice = 3,
    
    /// System/control message
    Control = 4,
}

impl ProtocolMessage {
    /// Create a new direct message
    pub fn new_direct(to: Vec<u8>, from: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            to,
            from,
            payload,
            timestamp: current_timestamp(),
            ttl: 7 * 24 * 60 * 60, // 7 days
            msg_type: MessageType::Direct,
        }
    }

    /// Check if message is expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.timestamp + self.ttl
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

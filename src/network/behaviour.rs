use libp2p::{
    gossipsub, identify, kad, mdns,
    swarm::NetworkBehaviour,
    StreamProtocol, request_response,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use serde::{Serialize, Deserialize};

use crate::core::Identity;

/// Request-Response protocol for direct messaging
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectMessageRequest(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectMessageResponse(pub bool);

/// Request the responder's signed X25519 prekey. The request carries no
/// data — the responder already knows which prekey is "theirs".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyRequest;

/// Signed prekey bundle returned by the responder. The Ed25519 signature
/// is over `prekey_signing_bytes(x25519_public)` (see core::identity) and
/// must be verified against the responder's PeerId-embedded Ed25519 pubkey
/// before the prekey is trusted.
///
/// Optionally also carries a **one-time prekey** (OTPK) bundle. When
/// present, the initiator uses the 3-DH variant of X3DH (additional
/// DH between initiator's ephemeral and this OTPK) for stronger forward
/// secrecy on the very first message. Each OTPK is consumed by the
/// responder after a single successful handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyResponse {
    pub x25519_public: [u8; 32],
    #[serde(with = "crate::serde_helpers::serde_arr64")]
    pub signature: [u8; 64],

    /// Optional OTPK bundle. Old responders (pre-3.5) omit this; old
    /// initiators ignore it (default-None on deserialize).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otpk: Option<OneTimePrekey>,
}

/// One-time prekey bundle. `id` is the responder's local row id — the
/// initiator echoes it back in the first message header so the responder
/// can look up the matching private bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub id: i64,
    pub x25519_public: [u8; 32],
    #[serde(with = "crate::serde_helpers::serde_arr64")]
    pub signature: [u8; 64],
}

/// Combined network behaviour for the P2P node
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Kademlia DHT for peer discovery and content routing
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,

    /// Gossipsub for pubsub messaging
    pub gossipsub: gossipsub::Behaviour,

    /// mDNS for local network discovery
    pub mdns: mdns::tokio::Behaviour,

    /// Identify protocol for peer information exchange
    pub identify_behaviour: identify::Behaviour,

    /// Request-Response for direct messaging
    pub request_response: request_response::cbor::Behaviour<DirectMessageRequest, DirectMessageResponse>,

    /// Request-Response for fetching peer prekeys. Kept on a separate
    /// protocol from DMs so a peer that only wants to look up keys doesn't
    /// have to advertise full DM support, and so the two flows can evolve
    /// their wire formats independently.
    pub prekey: request_response::cbor::Behaviour<PrekeyRequest, PrekeyResponse>,
}

impl Behaviour {
    /// Create a new network behaviour
    pub fn new(identity: &Identity) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = identity.peer_id();
        let keypair = identity.keypair().clone();

        // Kademlia configuration
        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_protocol_names(vec![StreamProtocol::new("/zerocenter/kad/1.0.0")]);

        let kademlia = kad::Behaviour::with_config(
            peer_id,
            kad::store::MemoryStore::new(peer_id),
            kademlia_config,
        );

        // Gossipsub configuration
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|msg| {
                // Custom message ID based on content
                let mut hasher = DefaultHasher::new();
                msg.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            })
            .build()
            .expect("Valid Gossipsub config");

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair),
            gossipsub_config,
        )
        .expect("Valid Gossipsub parameters");

        // Subscribe to global topic
        let global_topic = gossipsub::IdentTopic::new("/zerocenter/global");
        gossipsub.subscribe(&global_topic)?;

        // mDNS configuration
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            peer_id,
        )?;

        // Identify configuration
        let public_key = identity.keypair().public();
        let identify_behaviour = identify::Behaviour::new(
            identify::Config::new(
                "/zerocenter/1.0.0".to_string(),
                public_key
            )
            .with_agent_version(format!("zerocenter/{}", env!("CARGO_PKG_VERSION")))
        );

        // Request-Response configuration for direct messaging
        let request_response_config = request_response::Config::default();
        // Phase 3 wire format (EncryptedPayload inside ProtocolMessage.payload)
        // — bumped from 1.0.0 so peers still on the old plaintext format
        // fail the libp2p protocol negotiation cleanly instead of silently
        // sending plaintext into a node expecting ciphertext.
        let request_response = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/zerocenter/direct-message/2.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response_config.clone(),
        );

        // Separate request-response instance for the prekey-fetch protocol.
        let prekey = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/zerocenter/prekey/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response_config,
        );

        Ok(Self {
            kademlia,
            gossipsub,
            mdns,
            identify_behaviour,
            request_response,
            prekey,
        })
    }
}

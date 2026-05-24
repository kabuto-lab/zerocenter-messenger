use libp2p::{
    dcutr, gossipsub, identify, kad, mdns, relay,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
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
///
/// Phase 2 PQ-X3DH adds an optional `pq_prekey` field carrying the
/// responder's signed ML-KEM-768 encapsulation key. When both peers
/// have populated it, the initial X3DH is **hybrid**: classical X25519
/// DH outputs are combined with the ML-KEM shared secret via HKDF,
/// secure as long as either primitive is unbroken. Old responders
/// without this field downgrade cleanly to pure classical X25519.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyResponse {
    pub x25519_public: [u8; 32],
    #[serde(with = "crate::serde_helpers::serde_arr64")]
    pub signature: [u8; 64],

    /// Optional OTPK bundle. Old responders (pre-3.5) omit this; old
    /// initiators ignore it (default-None on deserialize).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otpk: Option<OneTimePrekey>,

    /// Optional Phase 2 PQ prekey. When present, the initiator
    /// encapsulates against this ML-KEM-768 public key and feeds the
    /// resulting shared secret into the X3DH HKDF for hybrid security.
    /// Pre-Phase-2 peers omit this; the initiator falls back to pure
    /// X25519 X3DH (existing wire path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_prekey: Option<MlKemPrekey>,
}

/// Phase 2 PQ prekey bundle. `ek` is the raw 1184-byte ML-KEM-768
/// encapsulation key; `signature` is an Ed25519 signature over
/// `ml_kem_prekey_signing_bytes(ek)` made by the responder's
/// long-term identity key. The initiator MUST verify the signature
/// against the responder's PeerId-embedded Ed25519 pubkey before
/// encapsulating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemPrekey {
    /// Raw 1184-byte ML-KEM-768 encapsulation key.
    pub ek: Vec<u8>,
    /// Ed25519 signature over `ML_KEM_PREKEY_SIG_DOMAIN || ek`.
    #[serde(with = "crate::serde_helpers::serde_arr64")]
    pub signature: [u8; 64],
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

    /// Circuit-relay v2 client. Lets this peer dial others through a
    /// relay node when both ends are behind NAT. Constructed externally
    /// via `relay::client::new(peer_id)` and passed into
    /// [`Behaviour::new`] because the relay-client transport and
    /// behaviour are conceptually one component.
    pub relay_client: relay::client::Behaviour,

    /// Circuit-relay v2 server. Toggled on per `--relay-server`. NAT'd
    /// nodes leave it off (they couldn't actually serve traffic);
    /// public-IP nodes turn it on so they can act as relays for others.
    pub relay_server: Toggle<relay::Behaviour>,

    /// Direct Connection Upgrade through Relay — hole-punching on top
    /// of an existing relay connection. After the initial circuit
    /// connect succeeds, both peers attempt to coordinate a direct
    /// TCP connection so the relay can drop out of the path.
    pub dcutr: dcutr::Behaviour,
}

impl Behaviour {
    /// Create a new network behaviour.
    ///
    /// `relay_client` comes from `libp2p::relay::client::new(peer_id)`
    /// — its companion relay-client transport must be spliced into the
    /// swarm's transport stack via `OrTransport` (or libp2p's
    /// `SwarmBuilder::with_relay_client`). `enable_relay_server`
    /// flips on the relay-server behaviour (only set this on nodes
    /// with a publicly reachable address).
    pub fn new(
        identity: &Identity,
        relay_client: relay::client::Behaviour,
        enable_relay_server: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = identity.peer_id();
        let keypair = identity.keypair().clone();

        // Kademlia configuration
        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_protocol_names(vec![StreamProtocol::new("/ME55/kad/1.0.0")]);

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
        let global_topic = gossipsub::IdentTopic::new("/ME55/global");
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
                "/ME55/1.0.0".to_string(),
                public_key
            )
            .with_agent_version(format!("ME55/{}", env!("CARGO_PKG_VERSION")))
        );

        // Request-Response configuration for direct messaging
        let request_response_config = request_response::Config::default();
        // Phase 3 wire format (EncryptedPayload inside ProtocolMessage.payload)
        // — bumped from 1.0.0 so peers still on the old plaintext format
        // fail the libp2p protocol negotiation cleanly instead of silently
        // sending plaintext into a node expecting ciphertext.
        let request_response = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/ME55/direct-message/2.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response_config.clone(),
        );

        // Separate request-response instance for the prekey-fetch protocol.
        let prekey = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/ME55/prekey/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response_config,
        );

        // Relay server is a per-node opt-in. The Toggle wrapper lets us
        // keep the same Behaviour struct shape for both relay-server and
        // pure-client deployments.
        let relay_server: Toggle<relay::Behaviour> = if enable_relay_server {
            Some(relay::Behaviour::new(peer_id, relay::Config::default())).into()
        } else {
            None.into()
        };

        // DCUtR — symmetric, both client and server roles share the same
        // behaviour type. Cheap to always include.
        let dcutr = dcutr::Behaviour::new(peer_id);

        Ok(Self {
            kademlia,
            gossipsub,
            mdns,
            identify_behaviour,
            request_response,
            prekey,
            relay_client,
            relay_server,
            dcutr,
        })
    }
}

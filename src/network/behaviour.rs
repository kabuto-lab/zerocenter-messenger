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
        let request_response = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/zerocenter/direct-message/1.0.0"),
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
        })
    }
}

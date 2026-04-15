use anyhow::Result;
use libp2p::{
    noise,
    swarm::Swarm,
    tcp, yamux, PeerId, SwarmBuilder, Multiaddr,
    request_response,
};
use libp2p::futures::StreamExt;
use std::time::Duration;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::core::{Config, Identity};
use crate::network::{Behaviour, DirectMessageRequest};
use crate::protocol::ProtocolMessage;
use crate::storage::MessageStore;

/// P2P Node - the core networking engine
pub struct P2PNode {
    config: Config,
    identity: Identity,
    swarm: Option<Swarm<Behaviour>>,
    message_store: Option<MessageStore>,
    /// Connected peers cache: PeerId -> Multiaddr
    connected_peers: HashMap<PeerId, Multiaddr>,
}

/// Command for P2P node operations
pub enum NodeCommand {
    Connect(Multiaddr),
    Send(PeerId, String),
    ListPeers,
    ListContacts,
    History(usize),
}

impl P2PNode {
    /// Create a new P2P node
    pub async fn new(config: Config, identity: Identity) -> Result<Self> {
        let message_store = MessageStore::open(&config.data_dir)?;

        Ok(Self {
            config,
            identity,
            swarm: None,
            message_store: Some(message_store),
            connected_peers: HashMap::new(),
        })
    }

    /// Start the P2P node (begin listening)
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting P2P node...");

        // Create the network behaviour
        let behaviour = Behaviour::new(&self.identity)
            .map_err(|e| anyhow::anyhow!("Failed to create behaviour: {}", e))?;

        // Build the swarm
        let keypair = self.identity.keypair().clone();

        // NOTE: .with_quic() is disabled while the "quic" libp2p feature is off
        // (see Cargo.toml). TCP+Noise+Yamux is enough for LAN testing. Restore
        // both when the local toolchain can build `ring` again.
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().port_reuse(true).nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Listen on all interfaces with random port
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", self.config.listen_port)
            .parse()
            .expect("Valid listen address");

        swarm.listen_on(listen_addr.clone())?;

        info!("Listening on: {:?}", listen_addr);

        self.swarm = Some(swarm);

        Ok(())
    }

    /// Connect to a specific peer by Multiaddr
    pub fn connect_to_peer(&mut self, address: Multiaddr) -> Result<()> {
        let swarm = self.swarm.as_mut().ok_or_else(|| anyhow::anyhow!("Swarm not initialized"))?;
        
        info!("Dialing peer: {}", address);
        swarm.dial(address)?;
        
        Ok(())
    }

    /// Send a direct message to a peer.
    ///
    /// Requires the recipient to be directly connected (via mDNS/Kad discovery and
    /// an established connection). If the peer is not connected this returns an
    /// error — we deliberately do NOT fall back to gossipsub for DMs, since that
    /// would broadcast private content to every subscriber of the global topic.
    pub fn send_message(&mut self, recipient: PeerId, content: &str) -> Result<()> {
        let swarm = self.swarm.as_mut().ok_or_else(|| anyhow::anyhow!("Swarm not initialized"))?;

        if !self.connected_peers.contains_key(&recipient) {
            anyhow::bail!(
                "Peer {} is not connected. Use `connect <multiaddr>` first \
                 (offline delivery will be added in a future phase).",
                recipient
            );
        }

        // Create protocol message (plaintext for now, E2EE in Phase 3).
        let msg = ProtocolMessage::new_direct(
            recipient.to_bytes(),
            self.identity.peer_id().to_bytes(),
            content.as_bytes().to_vec(),
        );

        // Serialize message
        let msg_bytes = msg.to_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;

        // Send via request-response (direct peer-to-peer)
        swarm.behaviour_mut().request_response.send_request(
            &recipient,
            DirectMessageRequest(msg_bytes),
        );
        info!("Sent direct message to {}", recipient);

        // Store message locally
        if let Some(ref store) = self.message_store {
            store.store_message(
                &self.identity.peer_id().to_bytes(),
                &recipient.to_bytes(),
                content.as_bytes(),
                msg.ttl,
            )?;
        }

        Ok(())
    }

    /// Get list of connected peers
    pub fn get_connected_peers(&self) -> Vec<(PeerId, Multiaddr)> {
        self.connected_peers
            .iter()
            .map(|(pid, addr)| (*pid, addr.clone()))
            .collect()
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Run the event loop with command channel
    pub async fn run_with_commands(
        mut self,
        mut cmd_rx: mpsc::Receiver<NodeCommand>,
    ) -> Result<()> {
        use libp2p::swarm::SwarmEvent;

        let mut swarm = self.swarm.take().expect("Swarm not initialized");

        info!("P2P node running. Peer ID: {}", self.peer_id());

        loop {
            tokio::select! {
                // Handle CLI commands
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(NodeCommand::Connect(addr)) => {
                            info!("Dialing peer: {}", addr);
                            if let Err(e) = swarm.dial(addr) {
                                error!("Failed to dial: {}", e);
                            }
                        }
                        Some(NodeCommand::Send(peer_id, message)) => {
                            info!("Sending message to {}: {}", peer_id, message);
                            if let Err(e) = self.send_message_via_swarm(&mut swarm, peer_id, &message) {
                                error!("Failed to send message: {}", e);
                            } else {
                                println!("📤 Message sent to {}", peer_id);
                            }
                        }
                        Some(NodeCommand::ListPeers) => {
                            if self.connected_peers.is_empty() {
                                println!("No connected peers");
                            } else {
                                println!("\nConnected Peers:");
                                println!("─────────────────────────────────────");
                                for (pid, addr) in &self.connected_peers {
                                    println!("  {} ", pid);
                                    println!("    at {}", addr);
                                }
                                println!("─────────────────────────────────────");
                                println!("Total: {} peer(s)", self.connected_peers.len());
                            }
                        }
                        Some(NodeCommand::ListContacts) => {
                            println!("\nContacts:");
                            println!("─────────────────────────────────────");
                            if self.connected_peers.is_empty() {
                                println!("  (no contacts yet - connect to peers first)");
                            } else {
                                for (pid, _) in &self.connected_peers {
                                    println!("  {}", pid);
                                }
                            }
                            println!("─────────────────────────────────────");
                        }
                        Some(NodeCommand::History(limit)) => {
                            if let Some(ref store) = self.message_store {
                                match store.get_recent_messages(limit) {
                                    Ok(messages) => {
                                        if messages.is_empty() {
                                            println!("\n📭 No messages in history");
                                        } else {
                                            println!("\n📜 Message History (last {}):", messages.len());
                                            println!("─────────────────────────────────────");
                                            for msg in messages {
                                                let sender_str = String::from_utf8_lossy(&msg.sender);
                                                let content = String::from_utf8_lossy(&msg.ciphertext);
                                                println!("  [{}] {}: {}", 
                                                    chrono_format(msg.timestamp),
                                                    truncate_peer(&sender_str, 16),
                                                    content);
                                            }
                                            println!("─────────────────────────────────────");
                                        }
                                    }
                                    Err(e) => {
                                        println!("Error loading history: {}", e);
                                    }
                                }
                            } else {
                                println!("Message store not available");
                            }
                        }
                        None => break, // Channel closed
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on: {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            info!("Connected to: {} via {:?}", peer_id, endpoint);
                            let addr = endpoint.get_remote_address();
                            self.connected_peers.insert(peer_id, addr.clone());
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            warn!("Connection closed to: {} (cause: {:?})", peer_id, cause);
                            self.connected_peers.remove(&peer_id);
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("Incoming connection error: {}", error);
                        }
                        SwarmEvent::Behaviour(event) => {
                            self.handle_behaviour_event(event).await?;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    /// Send message via swarm (helper for run_with_commands).
    ///
    /// Requires a direct connection to the recipient. See [`Self::send_message`]
    /// for the rationale — the gossipsub fallback was removed because it leaked
    /// plaintext DMs to every subscriber of the global topic.
    fn send_message_via_swarm(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        recipient: PeerId,
        content: &str,
    ) -> Result<()> {
        if !self.connected_peers.contains_key(&recipient) {
            anyhow::bail!(
                "Peer {} is not connected. Use `connect <multiaddr>` first \
                 (offline delivery will be added in a future phase).",
                recipient
            );
        }

        // Create protocol message (plaintext for now, E2EE in Phase 3).
        let msg = ProtocolMessage::new_direct(
            recipient.to_bytes(),
            self.identity.peer_id().to_bytes(),
            content.as_bytes().to_vec(),
        );

        // Serialize message
        let msg_bytes = msg.to_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;

        // Send via request-response (direct peer-to-peer)
        swarm.behaviour_mut().request_response.send_request(
            &recipient,
            DirectMessageRequest(msg_bytes),
        );
        info!("Sent direct message to {}", recipient);

        // Store message locally
        if let Some(ref store) = self.message_store {
            store.store_message(
                &self.identity.peer_id().to_bytes(),
                &recipient.to_bytes(),
                content.as_bytes(),
                msg.ttl,
            )?;
        }

        Ok(())
    }

    /// Handle behaviour events
    async fn handle_behaviour_event(
        &mut self,
        event: crate::network::BehaviourEvent,
    ) -> Result<()> {
        match event {
            crate::network::BehaviourEvent::Kademlia(kad_event) => {
                info!("Kademlia event: {:?}", kad_event);
            }
            crate::network::BehaviourEvent::Gossipsub(gs_event) => {
                // Gossipsub is kept in the behaviour for future public-channel
                // use, but we intentionally do NOT treat incoming pubsub traffic
                // as direct messages. DMs arrive over the request-response
                // protocol only; mixing channels would reintroduce the plaintext
                // broadcast leak that was removed in Phase 3.
                match gs_event {
                    libp2p::gossipsub::Event::Message { propagation_source, .. } => {
                        info!(
                            "Ignoring gossipsub message from {} (DMs use request-response)",
                            propagation_source
                        );
                    }
                    libp2p::gossipsub::Event::Subscribed { peer_id, topic } => {
                        info!("Peer {} subscribed to {:?}", peer_id, topic);
                    }
                    libp2p::gossipsub::Event::Unsubscribed { peer_id, topic } => {
                        info!("Peer {} unsubscribed from {:?}", peer_id, topic);
                    }
                    _ => {}
                }
            }
            crate::network::BehaviourEvent::Mdns(mdns_event) => {
                match mdns_event {
                    libp2p::mdns::Event::Discovered(list) => {
                        for (peer_id, addr) in list {
                            info!("mDNS discovered peer {} at {}", peer_id, addr);
                            self.connected_peers.insert(peer_id, addr);
                        }
                    }
                    libp2p::mdns::Event::Expired(list) => {
                        for (peer_id, _) in list {
                            info!("mDNS peer {} expired", peer_id);
                            self.connected_peers.remove(&peer_id);
                        }
                    }
                }
            }
            crate::network::BehaviourEvent::IdentifyBehaviour(id_event) => {
                match id_event {
                    libp2p::identify::Event::Received { peer_id, info } => {
                        info!("Identify from {}: {:?}", peer_id, info);
                    }
                    libp2p::identify::Event::Sent { peer_id } => {
                        info!("Sent identify info to {}", peer_id);
                    }
                    libp2p::identify::Event::Pushed { peer_id, .. } => {
                        info!("Pushed identify info to {}", peer_id);
                    }
                    libp2p::identify::Event::Error { peer_id, error } => {
                        warn!("Identify error with {}: {:?}", peer_id, error);
                    }
                }
            }
            crate::network::BehaviourEvent::RequestResponse(req_event) => {
                match req_event {
                    request_response::Event::Message { peer, message, .. } => {
                        // In libp2p 0.53 `Message` is an enum with Request/Response
                        // variants — destructure it explicitly.
                        match message {
                            request_response::Message::Request { request, .. } => {
                                match ProtocolMessage::from_bytes(&request.0) {
                                    Ok(proto_msg) => {
                                        let my_peer_id = self.identity.peer_id();
                                        let sender = PeerId::from_bytes(&proto_msg.from)
                                            .unwrap_or(my_peer_id);

                                        info!(
                                            "Direct message from {} (via {}): {}",
                                            sender,
                                            peer,
                                            String::from_utf8_lossy(&proto_msg.payload)
                                        );

                                        // Store the message
                                        if let Some(ref store) = self.message_store {
                                            store.store_message(
                                                &proto_msg.from,
                                                &proto_msg.to,
                                                &proto_msg.payload,
                                                proto_msg.ttl,
                                            )?;
                                        }

                                        // Print received message
                                        println!(
                                            "\n📨 Direct message from {}: {}",
                                            sender,
                                            String::from_utf8_lossy(&proto_msg.payload)
                                        );
                                        println!("> ");
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse direct message: {}", e);
                                    }
                                }
                            }
                            request_response::Message::Response { .. } => {
                                // We don't send responses yet; ignore.
                            }
                        }
                    }
                    request_response::Event::ResponseSent { peer, .. } => {
                        info!("Response sent to {}", peer);
                    }
                    request_response::Event::InboundFailure { peer, error, .. } => {
                        warn!("Inbound request failure from {}: {:?}", peer, error);
                    }
                    request_response::Event::OutboundFailure { peer, error, .. } => {
                        warn!("Outbound request failure to {}: {:?}", peer, error);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Format timestamp as HH:MM:SS
fn chrono_format(timestamp: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(timestamp as u64))
        .unwrap_or(UNIX_EPOCH);
    
    let datetime = duration.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = datetime.as_secs();
    
    // Get hours, minutes, seconds
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Truncate peer ID for display
fn truncate_peer(peer: &str, max_len: usize) -> String {
    if peer.len() > max_len {
        format!("{}...", &peer[..max_len.saturating_sub(3)])
    } else {
        peer.to_string()
    }
}

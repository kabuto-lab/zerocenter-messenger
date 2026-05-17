use anyhow::Result;
use libp2p::{
    noise,
    swarm::Swarm,
    tcp, yamux, PeerId, SwarmBuilder, Multiaddr,
    request_response,
};
use libp2p::futures::StreamExt;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::core::{Config, Identity};
use crate::core::identity::prekey_signing_bytes;
use crate::crypto::{ratchet::RatchetState, x3dh};
use crate::network::{
    Behaviour, DirectMessageRequest, OneTimePrekey, PrekeyRequest, PrekeyResponse,
};
use crate::protocol::{EncryptedPayload, ProtocolMessage};
use crate::storage::MessageStore;
use ed25519_dalek::{Signature as Ed25519Sig, Signer, VerifyingKey};
use x25519_dalek::PublicKey as X25519Pub;

/// P2P Node - the core networking engine
pub struct P2PNode {
    config: Config,
    identity: Identity,
    swarm: Option<Swarm<Behaviour>>,
    message_store: Option<MessageStore>,
    /// Connected peers cache: PeerId -> Multiaddr
    connected_peers: HashMap<PeerId, Multiaddr>,
    /// In-memory ratchet sessions, one per remote peer. Loaded lazily
    /// from `MessageStore::load_session` on first use; saved back on
    /// every successful encrypt or decrypt.
    sessions: HashMap<PeerId, RatchetState>,
    /// Outbound prekey-fetch requests we already sent, to avoid storming
    /// the network when the user fires `send` repeatedly before the
    /// response arrives.
    inflight_prekey_fetches: HashSet<PeerId>,
    /// Plaintext messages waiting on a prekey fetch / X3DH bootstrap.
    /// Drained when the corresponding `PrekeyResponse` arrives.
    pending_sends: HashMap<PeerId, Vec<String>>,
    /// Inbound encrypted payloads whose sender we don't yet have an
    /// X3DH-able prekey for (responder bootstrap requires the initiator's
    /// long-term X25519 prekey to verify the X3DH derivation).
    pending_recvs: HashMap<PeerId, Vec<EncryptedPayload>>,
    /// In-memory cache of one-time prekey bundles received from peers.
    /// Each OTPK is consumed (removed) on the next outbound session
    /// bootstrap to that peer. A miss falls back to the 2-DH variant.
    cached_otpks: HashMap<PeerId, OneTimePrekey>,
    /// Our own listen addresses, tracked from `NewListenAddr` events
    /// so the `addr` CLI command can print shareable multiaddrs.
    listen_addrs: Vec<Multiaddr>,
}

/// Inputs that travel only on the first message of a fresh session:
/// the X3DH ephemeral pubkey, plus (optionally) the OTPK id consumed.
struct FirstMessageHello {
    x3dh_eph: X25519Pub,
    /// `None` when 2-DH X3DH was used (peer published no OTPK); `Some`
    /// when 3-DH was used.
    otpk_id: Option<i64>,
}

/// Command for P2P node operations.
///
/// CLI-shaped variants (Connect, Send, ListPeers, ListContacts,
/// History, ListAddrs) print results to stdout — the legacy pattern
/// from before the GUI existed. GUI-shaped variants (Query*) carry a
/// `tokio::sync::oneshot::Sender` so the node can return structured
/// data to the Tauri command handler.
pub enum NodeCommand {
    Connect(Multiaddr),
    Send(PeerId, String),
    ListPeers,
    ListContacts,
    History(usize),
    /// Request the named peer's signed X25519 prekey. Response is stored in
    /// the local prekey cache once verified; no direct reply to the caller
    /// (the ratchet layer, once wired up in commit 4, will poll the cache).
    FetchPrekey(PeerId),
    /// Ask the node to print its own multiaddrs (with `/p2p/<PeerId>`
    /// suffix appended). Used by the `addr` CLI command.
    ListAddrs,

    // ---- GUI-shaped, structured reply ----
    /// Return the local PeerId as a base58 string.
    QueryPeerId(tokio::sync::oneshot::Sender<String>),
    /// Return all stored contacts.
    QueryContacts(tokio::sync::oneshot::Sender<Vec<ContactDto>>),
    /// Return conversation history with a specific peer (newest last).
    QueryMessages(PeerId, tokio::sync::oneshot::Sender<Vec<MessageDto>>),
    /// Manually add a contact with an optional alias. Reply is
    /// `Ok(())` on success or `Err(string)` on failure.
    AddContact {
        peer_id: PeerId,
        alias: Option<String>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}

/// DTO returned to the GUI by `QueryContacts`. PeerId becomes a base58
/// string so the webview can render it without further conversion.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactDto {
    pub peer_id: String,
    pub alias: Option<String>,
}

/// DTO returned to the GUI by `QueryMessages`. `is_own` lets the
/// webview pick the "sent" bubble style vs the "received" one.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageDto {
    pub sender: String,
    pub content: String,
    pub timestamp: i64,
    pub is_own: bool,
}

impl P2PNode {
    /// Create a new P2P node.
    ///
    /// `dek` is the 32-byte data-encryption key used to AEAD-encrypt
    /// at-rest blobs (currently ratchet session state). Obtain it from
    /// [`crate::crypto::keyring::load_or_create_dek`] using the same
    /// profile name as `config.profile`.
    pub async fn new(config: Config, identity: Identity, dek: [u8; 32]) -> Result<Self> {
        let message_store = MessageStore::open(&config.data_dir, dek)?;

        Ok(Self {
            config,
            identity,
            swarm: None,
            message_store: Some(message_store),
            connected_peers: HashMap::new(),
            sessions: HashMap::new(),
            inflight_prekey_fetches: HashSet::new(),
            pending_sends: HashMap::new(),
            pending_recvs: HashMap::new(),
            cached_otpks: HashMap::new(),
            listen_addrs: Vec::new(),
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

        // Seed Kademlia from any user-supplied bootstrap nodes. Each
        // entry must be a full multiaddr including the `/p2p/<PeerId>`
        // suffix — the PeerId is what Kademlia needs to slot the
        // address into its routing table. Bad addresses are warned
        // about and skipped so one typo can't block startup.
        for addr_str in &self.config.bootstrap_nodes {
            match Self::parse_bootstrap_addr(addr_str) {
                Ok((peer, addr)) => {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer, addr.clone());
                    if let Err(e) = swarm.dial(addr.clone()) {
                        warn!("Bootstrap dial failed for {}: {}", addr_str, e);
                    } else {
                        info!("Seeded Kademlia with bootstrap peer {} at {}", peer, addr);
                    }
                }
                Err(e) => warn!("Skipping bad bootstrap addr {:?}: {}", addr_str, e),
            }
        }

        self.swarm = Some(swarm);

        // Ensure we have a healthy pool of one-time prekeys ready to
        // hand out on prekey-fetch requests. Failure is logged but
        // non-fatal — peers will just fall back to the 2-DH X3DH variant.
        if let Err(e) = self.replenish_otpk_pool() {
            warn!("OTPK pool init failed: {}", e);
        }

        Ok(())
    }

    /// Split a `/.../p2p/<PeerId>` multiaddr into its PeerId and the
    /// transport-only prefix. Returns Err if the trailing `/p2p/...`
    /// component is missing — without it Kademlia can't index the
    /// address.
    fn parse_bootstrap_addr(s: &str) -> Result<(PeerId, Multiaddr)> {
        use libp2p::multiaddr::Protocol;
        let full: Multiaddr = s
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid multiaddr: {}", e))?;
        let peer = full
            .iter()
            .find_map(|p| match p {
                Protocol::P2p(pid) => Some(pid),
                _ => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("multiaddr is missing a /p2p/<PeerId> suffix")
            })?;
        Ok((peer, full))
    }

    /// Connect to a specific peer by Multiaddr
    pub fn connect_to_peer(&mut self, address: Multiaddr) -> Result<()> {
        let swarm = self.swarm.as_mut().ok_or_else(|| anyhow::anyhow!("Swarm not initialized"))?;

        info!("Dialing peer: {}", address);
        swarm.dial(address)?;

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

        // Periodic TTL sweep. One hour is a safe default — messages have a
        // 7-day TTL so we don't need sub-minute precision, and an hourly
        // cadence keeps the DB bounded without spamming I/O.
        let mut cleanup_tick = tokio::time::interval(Duration::from_secs(3600));
        // Skip the immediate first tick — there's nothing worth sweeping at
        // startup and it would race with the rest of the init log lines.
        cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        cleanup_tick.tick().await;

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
                            info!("Send requested to {}: {}", peer_id, message);
                            self.try_send_or_queue(&mut swarm, peer_id, message);
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
                            if let Some(ref store) = self.message_store {
                                match store.get_contacts() {
                                    Ok(contacts) if contacts.is_empty() => {
                                        println!("\nContacts:");
                                        println!("─────────────────────────────────────");
                                        println!("  (no contacts yet — they'll be added when you receive a DM)");
                                        println!("─────────────────────────────────────");
                                    }
                                    Ok(contacts) => {
                                        println!("\nContacts:");
                                        println!("─────────────────────────────────────");
                                        for (peer_id_bytes, _pk, alias) in contacts {
                                            match PeerId::from_bytes(&peer_id_bytes) {
                                                Ok(pid) => match alias {
                                                    Some(a) => println!("  {} ({})", pid, a),
                                                    None => println!("  {}", pid),
                                                },
                                                Err(_) => println!("  <unparseable peer id>"),
                                            }
                                        }
                                        println!("─────────────────────────────────────");
                                    }
                                    Err(e) => println!("Error loading contacts: {}", e),
                                }
                            } else {
                                println!("Contact store not available");
                            }
                        }
                        Some(NodeCommand::FetchPrekey(peer_id)) => {
                            info!("Fetching prekey from {}", peer_id);
                            swarm
                                .behaviour_mut()
                                .prekey
                                .send_request(&peer_id, PrekeyRequest);
                        }
                        Some(NodeCommand::QueryPeerId(reply)) => {
                            let _ = reply.send(self.identity.peer_id().to_string());
                        }
                        Some(NodeCommand::QueryContacts(reply)) => {
                            let dtos = match self.message_store.as_ref() {
                                Some(s) => s
                                    .get_contacts()
                                    .ok()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter_map(|(pid_bytes, _pk, alias)| {
                                        PeerId::from_bytes(&pid_bytes).ok().map(|pid| ContactDto {
                                            peer_id: pid.to_string(),
                                            alias,
                                        })
                                    })
                                    .collect(),
                                None => Vec::new(),
                            };
                            let _ = reply.send(dtos);
                        }
                        Some(NodeCommand::QueryMessages(peer_id, reply)) => {
                            let me_bytes = self.identity.peer_id().to_bytes();
                            let them_bytes = peer_id.to_bytes();
                            let dtos = match self.message_store.as_ref() {
                                Some(s) => s
                                    .get_conversation(&me_bytes, &them_bytes, 500)
                                    .ok()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|m| {
                                        let is_own = m.sender == me_bytes;
                                        let sender = PeerId::from_bytes(&m.sender)
                                            .map(|p| p.to_string())
                                            .unwrap_or_else(|_| "?".to_string());
                                        MessageDto {
                                            sender,
                                            content: String::from_utf8_lossy(&m.ciphertext)
                                                .into_owned(),
                                            timestamp: m.timestamp,
                                            is_own,
                                        }
                                    })
                                    .collect(),
                                None => Vec::new(),
                            };
                            let _ = reply.send(dtos);
                        }
                        Some(NodeCommand::AddContact { peer_id, alias, reply }) => {
                            let result = if let Some(ref store) = self.message_store {
                                store
                                    .add_contact(
                                        &peer_id.to_bytes(),
                                        &peer_id.to_bytes(),
                                        alias.as_deref(),
                                    )
                                    .map_err(|e| e.to_string())
                            } else {
                                Err("no message store".to_string())
                            };
                            let _ = reply.send(result);
                        }
                        Some(NodeCommand::ListAddrs) => {
                            let me = self.identity.peer_id();
                            if self.listen_addrs.is_empty() {
                                println!("\nNo listen addresses bound yet.");
                            } else {
                                println!("\nYour shareable multiaddrs:");
                                println!("─────────────────────────────────────");
                                for addr in &self.listen_addrs {
                                    // Append /p2p/<our peer id> so the result is
                                    // a complete dial-able address.
                                    println!("  {}/p2p/{}", addr, me);
                                }
                                println!("─────────────────────────────────────");
                                println!("Send any of these to a peer; they `connect` to it.");
                            }
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

                // Periodic TTL sweep on the local message store
                // and the offline outbox.
                _ = cleanup_tick.tick() => {
                    if let Some(ref store) = self.message_store {
                        match store.cleanup_expired() {
                            Ok(0) => {}
                            Ok(n) => info!("TTL sweep: deleted {} expired messages", n),
                            Err(e) => warn!("TTL sweep failed: {}", e),
                        }
                        match store.outbox_cleanup_expired() {
                            Ok(0) => {}
                            Ok(n) => info!("Outbox sweep: deleted {} stale entries", n),
                            Err(e) => warn!("Outbox sweep failed: {}", e),
                        }
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on: {}", address);
                            if !self.listen_addrs.contains(&address) {
                                self.listen_addrs.push(address);
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            info!("Connected to: {} via {:?}", peer_id, endpoint);
                            let addr = endpoint.get_remote_address();
                            self.connected_peers.insert(peer_id, addr.clone());
                            // Send anything queued for this peer while they
                            // were offline.
                            self.drain_outbox_for(&mut swarm, peer_id);
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
                            self.handle_behaviour_event(&mut swarm, event)?;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a swarm-level behaviour event.
    ///
    /// `swarm` is passed explicitly because `self.swarm` is taken by the
    /// event-loop in `run_with_commands` and is therefore `None` for the
    /// duration of the loop.
    fn handle_behaviour_event(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        event: crate::network::BehaviourEvent,
    ) -> Result<()> {
        match event {
            crate::network::BehaviourEvent::Kademlia(kad_event) => {
                info!("Kademlia event: {:?}", kad_event);
            }
            crate::network::BehaviourEvent::Gossipsub(gs_event) => {
                // Gossipsub is kept in the behaviour for future public-channel
                // use, but we intentionally do NOT treat incoming pubsub traffic
                // as direct messages — see commit-history note about plaintext
                // broadcast leak.
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
            crate::network::BehaviourEvent::Mdns(mdns_event) => match mdns_event {
                libp2p::mdns::Event::Discovered(list) => {
                    for (peer_id, addr) in list {
                        info!("mDNS discovered peer {} at {}", peer_id, addr);
                        self.connected_peers.insert(peer_id, addr);
                        // Drain any queued messages for this peer now
                        // that we know how to reach them. libp2p's
                        // request-response behaviour will auto-dial as
                        // needed when send_request is called.
                        self.drain_outbox_for(swarm, peer_id);
                    }
                }
                libp2p::mdns::Event::Expired(list) => {
                    for (peer_id, _) in list {
                        info!("mDNS peer {} expired", peer_id);
                        self.connected_peers.remove(&peer_id);
                    }
                }
            },
            crate::network::BehaviourEvent::IdentifyBehaviour(id_event) => match id_event {
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
            },
            crate::network::BehaviourEvent::RequestResponse(req_event) => match req_event {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Request { request, .. } => {
                        self.process_incoming_dm(swarm, peer, &request.0);
                    }
                    request_response::Message::Response { .. } => {
                        // DMs are one-shot — we never send a response.
                    }
                },
                request_response::Event::ResponseSent { peer, .. } => {
                    info!("DM response sent to {}", peer);
                }
                request_response::Event::InboundFailure { peer, error, .. } => {
                    warn!("DM inbound failure from {}: {:?}", peer, error);
                }
                request_response::Event::OutboundFailure { peer, error, .. } => {
                    warn!("DM outbound failure to {}: {:?}", peer, error);
                }
            },
            crate::network::BehaviourEvent::Prekey(req_event) => {
                self.handle_prekey_event(swarm, req_event);
            }
        }
        Ok(())
    }

    /// Prekey request-response protocol.
    ///
    /// Inbound `Request`: reply with our own signed prekey.
    /// Inbound `Response`: verify, cache, then drain any pending sends /
    /// recvs that were waiting on this prekey.
    fn handle_prekey_event(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        event: request_response::Event<PrekeyRequest, PrekeyResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request: _, channel, .. } => {
                    // Try to attach an OTPK bundle. If we have one in the
                    // pool, it's popped (and marked consumed) atomically;
                    // pre-3.5 peers without OTPK support just see None.
                    let otpk_bundle = self.pop_one_otpk_bundle();
                    let resp = PrekeyResponse {
                        x25519_public: *self.identity.x25519_public().as_bytes(),
                        signature: self.identity.x25519_signature().to_bytes(),
                        otpk: otpk_bundle,
                    };
                    if swarm
                        .behaviour_mut()
                        .prekey
                        .send_response(channel, resp)
                        .is_err()
                    {
                        warn!("Failed to send prekey response to {}", peer);
                    }
                }
                request_response::Message::Response { response, .. } => {
                    match self.verify_and_store_prekey(peer, &response) {
                        Ok(prekey_pub) => {
                            info!("Cached verified prekey from {}", peer);
                            // Verify and cache OTPK if attached.
                            if let Some(ref otpk) = response.otpk {
                                if self.verify_otpk(peer, otpk).is_ok() {
                                    info!("Cached verified OTPK id={} from {}", otpk.id, peer);
                                    self.cached_otpks.insert(peer, otpk.clone());
                                } else {
                                    warn!("Dropping unverifiable OTPK from {}", peer);
                                }
                            }
                            self.inflight_prekey_fetches.remove(&peer);
                            self.process_pending(swarm, peer, prekey_pub);
                        }
                        Err(e) => {
                            warn!("Dropping prekey response from {}: {}", peer, e);
                            self.inflight_prekey_fetches.remove(&peer);
                        }
                    }
                }
            },
            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!("Prekey outbound failure to {}: {:?}", peer, error);
                self.inflight_prekey_fetches.remove(&peer);
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("Prekey inbound failure from {}: {:?}", peer, error);
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Verify the Ed25519 signature on a prekey response and persist it.
    /// Returns the verified X25519 public key for immediate use by the
    /// caller (avoids a round-trip through the store).
    fn verify_and_store_prekey(
        &self,
        sender: PeerId,
        resp: &PrekeyResponse,
    ) -> Result<X25519Pub> {
        let multihash = sender.as_ref();
        if multihash.code() != 0 {
            anyhow::bail!("peer id does not embed an inline public key");
        }
        let libp2p_pk = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest())
            .map_err(|e| anyhow::anyhow!("decode peer pubkey: {}", e))?;
        let ed_bytes = libp2p_pk
            .try_into_ed25519()
            .map_err(|_| anyhow::anyhow!("peer is not Ed25519"))?
            .to_bytes();
        let verifying = VerifyingKey::from_bytes(&ed_bytes)
            .map_err(|e| anyhow::anyhow!("ed25519 key decode: {}", e))?;

        let sig = Ed25519Sig::from_bytes(&resp.signature);
        verifying
            .verify_strict(&prekey_signing_bytes(&resp.x25519_public), &sig)
            .map_err(|_| anyhow::anyhow!("prekey signature did not verify"))?;

        if let Some(ref store) = self.message_store {
            store.save_prekey(&sender.to_bytes(), &resp.x25519_public, &resp.signature)?;
        }
        Ok(X25519Pub::from(resp.x25519_public))
    }

    // ============================================================
    // Ratchet integration: send path
    // ============================================================

    /// User-initiated send. Three cases:
    /// 1. Session already exists  → encrypt and send straight away.
    /// 2. No session, but we have the peer's prekey cached/loaded
    ///    → run X3DH-lite as initiator, create session, send (with the
    ///    X3DH ephemeral attached in the first message header).
    /// 3. No session and no prekey → queue the plaintext, fire a
    ///    prekey fetch, drain on response.
    fn try_send_or_queue(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        plaintext: String,
    ) {
        // If the peer isn't currently connected, persist the message to
        // the outbox and stop. The ConnectionEstablished handler will
        // drain the outbox the next time the peer becomes reachable —
        // including across our own restarts (the outbox is on disk).
        // We accept that this doesn't help the "both never online at
        // once" case; that needs a relay layer, which is its own feature.
        if !self.connected_peers.contains_key(&peer) {
            if let Some(ref store) = self.message_store {
                match store.outbox_add(&peer.to_bytes(), plaintext.as_bytes(), 7 * 24 * 3600) {
                    Ok(_) => {
                        info!("Peer {} not connected — queued in outbox", peer);
                        println!("📭 Peer not connected — message queued (will send when peer appears)");
                    }
                    Err(e) => {
                        error!("Failed to add to outbox for {}: {}", peer, e);
                    }
                }
            } else {
                error!("No message store available; message to {} is lost", peer);
            }
            return;
        }

        if self.restore_session_if_persisted(&peer) {
            self.encrypt_and_send_existing(swarm, peer, &plaintext, None);
            return;
        }

        if let Some(prekey_pub) = self.cached_prekey(&peer) {
            self.bootstrap_initiator_and_send(swarm, peer, &plaintext, prekey_pub);
            return;
        }

        // Need to fetch the prekey first. Queue this message.
        self.pending_sends.entry(peer).or_default().push(plaintext);
        if self.inflight_prekey_fetches.insert(peer) {
            info!("Fetching prekey from {} before send", peer);
            swarm
                .behaviour_mut()
                .prekey
                .send_request(&peer, PrekeyRequest);
        }
    }

    /// Drain the on-disk outbox for `peer`. Called when a peer becomes
    /// reachable (ConnectionEstablished or mDNS discovery). Each queued
    /// plaintext is fed back into `try_send_or_queue` — which now sees
    /// the peer as connected, so it proceeds through the normal
    /// encrypt-and-send path (including prekey fetch if needed).
    /// The outbox row is deleted only after the message is handed off.
    fn drain_outbox_for(&mut self, swarm: &mut Swarm<Behaviour>, peer: PeerId) {
        let entries = match self.message_store.as_ref() {
            Some(store) => match store.outbox_get_for(&peer.to_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to read outbox for {}: {}", peer, e);
                    return;
                }
            },
            None => return,
        };

        if entries.is_empty() {
            return;
        }
        info!("Draining {} outbox entries for {}", entries.len(), peer);

        for (row_id, plaintext_bytes) in entries {
            let plaintext = String::from_utf8_lossy(&plaintext_bytes).into_owned();
            self.try_send_or_queue(swarm, peer, plaintext);
            if let Some(ref store) = self.message_store {
                if let Err(e) = store.outbox_delete(row_id) {
                    warn!("Failed to delete outbox row {}: {}", row_id, e);
                }
            }
        }
    }

    /// Run the initiator side of X3DH and create a new session.
    /// Uses the 3-DH (OTPK) variant if a one-time prekey is cached for
    /// `peer`, otherwise falls back to the 2-DH variant. The first
    /// message carries `x3dh_eph` and, when applicable, `otpk_id`.
    fn bootstrap_initiator_and_send(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        plaintext: &str,
        their_prekey_pub: X25519Pub,
    ) {
        let hello = match self.cached_otpks.remove(&peer) {
            Some(otpk_bundle) => {
                let otpk_pub = X25519Pub::from(otpk_bundle.x25519_public);
                let (eph_pub, sk) = x3dh::initiator_derive_with_otpk(
                    self.identity.x25519_secret(),
                    &their_prekey_pub,
                    &otpk_pub,
                );
                let session = RatchetState::new_initiator(sk, their_prekey_pub);
                self.sessions.insert(peer, session);
                FirstMessageHello {
                    x3dh_eph: eph_pub,
                    otpk_id: Some(otpk_bundle.id),
                }
            }
            None => {
                let (eph_pub, sk) = x3dh::initiator_derive(
                    self.identity.x25519_secret(),
                    &their_prekey_pub,
                );
                let session = RatchetState::new_initiator(sk, their_prekey_pub);
                self.sessions.insert(peer, session);
                FirstMessageHello {
                    x3dh_eph: eph_pub,
                    otpk_id: None,
                }
            }
        };
        self.encrypt_and_send_existing(swarm, peer, plaintext, Some(hello));
    }

    /// Encrypt `plaintext` with the existing ratchet session for `peer`
    /// and dispatch it via the DM request-response protocol. Persists
    /// the local plaintext copy + the updated session blob.
    ///
    /// `hello` carries the X3DH ephemeral pubkey and (optionally) the
    /// OTPK id, both of which appear ONLY in the first message of a
    /// fresh session and are `None` after that.
    fn encrypt_and_send_existing(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        plaintext: &str,
        hello: Option<FirstMessageHello>,
    ) {
        let ad = Self::ratchet_ad(&self.identity.peer_id(), &peer);

        let ratchet_msg = {
            let session = match self.sessions.get_mut(&peer) {
                Some(s) => s,
                None => {
                    error!("encrypt_and_send_existing: no session for {}", peer);
                    return;
                }
            };
            match session.encrypt(plaintext.as_bytes(), &ad) {
                Ok(m) => m,
                Err(e) => {
                    error!("Ratchet encrypt failed for {}: {}", peer, e);
                    return;
                }
            }
        };

        let payload = EncryptedPayload {
            dh: ratchet_msg.header.dh,
            pn: ratchet_msg.header.pn,
            n: ratchet_msg.header.n,
            ct: ratchet_msg.ciphertext,
            x3dh_eph: hello.as_ref().map(|h| *h.x3dh_eph.as_bytes()),
            otpk_id: hello.as_ref().and_then(|h| h.otpk_id),
        };

        let payload_bytes = match payload.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize EncryptedPayload: {}", e);
                return;
            }
        };

        let proto_msg = match ProtocolMessage::new_direct_signed(
            peer.to_bytes(),
            self.identity.peer_id().to_bytes(),
            payload_bytes,
            self.identity.keypair(),
        ) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to sign DM: {}", e);
                return;
            }
        };

        let wire_bytes = match proto_msg.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize ProtocolMessage: {}", e);
                return;
            }
        };

        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, DirectMessageRequest(wire_bytes));

        // Persist the local plaintext copy (so history shows it) and the
        // updated session state (so a restart doesn't break the chain).
        if let Some(ref store) = self.message_store {
            if let Err(e) = store.store_message(
                &self.identity.peer_id().to_bytes(),
                &peer.to_bytes(),
                plaintext.as_bytes(),
                proto_msg.ttl,
            ) {
                warn!("Failed to store local plaintext copy: {}", e);
            }
        }
        self.persist_session(&peer);

        println!("📤 Encrypted message sent to {}", peer);
    }

    // ============================================================
    // Ratchet integration: receive path
    // ============================================================

    fn process_incoming_dm(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        transport_peer: PeerId,
        request_bytes: &[u8],
    ) {
        // Step 1: parse the outer envelope.
        let proto_msg = match ProtocolMessage::from_bytes(request_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DM from {}: {}", transport_peer, e);
                return;
            }
        };

        // Step 2: verify the application-layer Ed25519 signature.
        let verified_sender = match proto_msg.verify() {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Dropping DM from transport peer {}: signature verification failed ({})",
                    transport_peer, e
                );
                return;
            }
        };

        // Step 3: transport peer must equal the signed sender.
        if verified_sender != transport_peer {
            warn!(
                "Dropping DM: transport peer {} != signed sender {}",
                transport_peer, verified_sender
            );
            return;
        }

        // Step 4: parse the encrypted payload.
        let payload = match EncryptedPayload::from_bytes(&proto_msg.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!("Malformed EncryptedPayload from {}: {}", verified_sender, e);
                return;
            }
        };

        // Step 5: route to the right decrypt path.
        if self.restore_session_if_persisted(&verified_sender) {
            self.decrypt_and_store(verified_sender, &payload);
            return;
        }

        // No session yet — need responder bootstrap. We need both the
        // initiator's X3DH ephemeral (in the payload) AND the initiator's
        // long-term X25519 prekey (cached or fetched).
        let Some(eph_bytes) = payload.x3dh_eph else {
            warn!(
                "Dropping DM from {}: no session and no x3dh_eph in payload",
                verified_sender
            );
            return;
        };

        if let Some(initiator_x25519) = self.cached_prekey(&verified_sender) {
            self.bootstrap_responder_and_decrypt(
                verified_sender,
                eph_bytes,
                initiator_x25519,
                &payload,
            );
        } else {
            // Queue and fetch.
            self.pending_recvs
                .entry(verified_sender)
                .or_default()
                .push(payload);
            if self.inflight_prekey_fetches.insert(verified_sender) {
                info!(
                    "Fetching prekey from {} to complete responder X3DH",
                    verified_sender
                );
                swarm
                    .behaviour_mut()
                    .prekey
                    .send_request(&verified_sender, PrekeyRequest);
            }
        }
    }

    fn bootstrap_responder_and_decrypt(
        &mut self,
        peer: PeerId,
        eph_bytes: [u8; 32],
        initiator_x25519: X25519Pub,
        payload: &EncryptedPayload,
    ) {
        let eph_pub = X25519Pub::from(eph_bytes);

        // 3-DH path if the initiator says they consumed an OTPK. We
        // refuse to fall back to 2-DH in that case because the initiator
        // definitely derived SK with 3-DH; a 2-DH derivation would yield
        // a different SK and AEAD would fail anyway — better to drop
        // explicitly with a clear log line.
        let sk = if let Some(otpk_id) = payload.otpk_id {
            let otpk_priv_bytes = match self
                .message_store
                .as_ref()
                .and_then(|s| s.load_otpk_private(otpk_id).ok().flatten())
            {
                Some(b) => b,
                None => {
                    warn!(
                        "Dropping first DM from {}: OTPK id={} not found in our store",
                        peer, otpk_id
                    );
                    return;
                }
            };
            let otpk_secret = x25519_dalek::StaticSecret::from(otpk_priv_bytes);
            x3dh::responder_derive_with_otpk(
                self.identity.x25519_secret(),
                &otpk_secret,
                &eph_pub,
                &initiator_x25519,
            )
        } else {
            x3dh::responder_derive(
                self.identity.x25519_secret(),
                &eph_pub,
                &initiator_x25519,
            )
        };

        // Clone our signed prekey secret for the ratchet's keepsake
        // (the original stays inside Identity).
        let my_spk_clone =
            x25519_dalek::StaticSecret::from(self.identity.x25519_secret().to_bytes());
        let session = RatchetState::new_responder(sk, my_spk_clone);
        self.sessions.insert(peer, session);

        // Decrypt happens via the session we just installed. If it
        // succeeds we delete the consumed OTPK row so it can't be reused
        // even by ourselves; if it fails the OTPK is wasted but already
        // marked consumed by `pop_unused_otpk` — net effect: one OTPK
        // burned per bad-first-message attempt, which is also a mild
        // DoS resistance property.
        let decrypted_ok = self.decrypt_first_message(peer, payload);
        if decrypted_ok {
            if let (Some(id), Some(store)) =
                (payload.otpk_id, self.message_store.as_ref())
            {
                if let Err(e) = store.delete_otpk(id) {
                    warn!("Failed to delete consumed OTPK id={}: {}", id, e);
                }
            }
        }
    }

    /// Variant of `decrypt_and_store` that returns a bool — used by the
    /// responder bootstrap path which needs to know whether the first
    /// message decrypted (to decide whether to clean up the OTPK row).
    fn decrypt_first_message(&mut self, peer: PeerId, payload: &EncryptedPayload) -> bool {
        let ad = Self::ratchet_ad(&peer, &self.identity.peer_id());
        let ratchet_msg = crate::crypto::ratchet::RatchetMessage {
            header: crate::crypto::ratchet::Header {
                dh: payload.dh,
                pn: payload.pn,
                n: payload.n,
            },
            ciphertext: payload.ct.clone(),
        };
        let plaintext = match self
            .sessions
            .get_mut(&peer)
            .and_then(|s| s.decrypt(&ratchet_msg, &ad).ok())
        {
            Some(pt) => pt,
            None => {
                warn!("First-message decrypt failed from {}", peer);
                return false;
            }
        };

        if let Some(ref store) = self.message_store {
            let _ = store.add_contact(&peer.to_bytes(), &peer.to_bytes(), None);
            let _ = store.store_message(
                &peer.to_bytes(),
                &self.identity.peer_id().to_bytes(),
                &plaintext,
                7 * 24 * 3600,
            );
        }
        self.persist_session(&peer);

        let text = String::from_utf8_lossy(&plaintext);
        info!("Decrypted first DM from {}: {}", peer, text);
        println!("\n🔓 {}: {}", peer, text);
        println!("> ");
        true
    }

    fn decrypt_and_store(&mut self, peer: PeerId, payload: &EncryptedPayload) {
        let ad = Self::ratchet_ad(&peer, &self.identity.peer_id());

        let ratchet_msg = crate::crypto::ratchet::RatchetMessage {
            header: crate::crypto::ratchet::Header {
                dh: payload.dh,
                pn: payload.pn,
                n: payload.n,
            },
            ciphertext: payload.ct.clone(),
        };

        let plaintext = {
            let session = match self.sessions.get_mut(&peer) {
                Some(s) => s,
                None => {
                    error!("decrypt_and_store: no session for {}", peer);
                    return;
                }
            };
            match session.decrypt(&ratchet_msg, &ad) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("Ratchet decrypt failed from {}: {}", peer, e);
                    return;
                }
            }
        };

        // Auto-persist contact + plaintext copy + updated session.
        if let Some(ref store) = self.message_store {
            if let Err(e) = store.add_contact(&peer.to_bytes(), &peer.to_bytes(), None) {
                warn!("Failed to persist contact: {}", e);
            }
            if let Err(e) = store.store_message(
                &peer.to_bytes(),
                &self.identity.peer_id().to_bytes(),
                &plaintext,
                7 * 24 * 3600,
            ) {
                warn!("Failed to store plaintext copy: {}", e);
            }
        }
        self.persist_session(&peer);

        let text = String::from_utf8_lossy(&plaintext);
        info!("Decrypted DM from {}: {}", peer, text);
        println!("\n🔓 {}: {}", peer, text);
        println!("> ");
    }

    /// Drain any queued sends / recvs that were waiting on this prekey.
    /// Called after [`Self::verify_and_store_prekey`] succeeds.
    fn process_pending(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        prekey_pub: X25519Pub,
    ) {
        // Pending recvs first — these are messages from the peer that need
        // responder bootstrap. Order matters: we must process them before
        // pending sends so a session exists if both directions are queued.
        if let Some(payloads) = self.pending_recvs.remove(&peer) {
            for payload in payloads {
                if self.restore_session_if_persisted(&peer) {
                    self.decrypt_and_store(peer, &payload);
                } else if let Some(eph_bytes) = payload.x3dh_eph {
                    self.bootstrap_responder_and_decrypt(peer, eph_bytes, prekey_pub, &payload);
                } else {
                    warn!(
                        "Pending recv from {} has no x3dh_eph and no session; dropping",
                        peer
                    );
                }
            }
        }

        if let Some(plaintexts) = self.pending_sends.remove(&peer) {
            for plaintext in plaintexts {
                if self.restore_session_if_persisted(&peer) {
                    self.encrypt_and_send_existing(swarm, peer, &plaintext, None);
                } else {
                    self.bootstrap_initiator_and_send(swarm, peer, &plaintext, prekey_pub);
                }
            }
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    /// Associated data the ratchet AEAD is bound to. Includes both peer
    /// IDs so a message captured from session A→B can't be replayed into
    /// session B→A or any other session with a different recipient.
    fn ratchet_ad(sender: &PeerId, recipient: &PeerId) -> Vec<u8> {
        let s = sender.to_bytes();
        let r = recipient.to_bytes();
        let mut out = Vec::with_capacity(8 + s.len() + r.len());
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(&s);
        out.extend_from_slice(&(r.len() as u32).to_be_bytes());
        out.extend_from_slice(&r);
        out
    }

    /// Try to retrieve a peer's prekey from the persistent cache. Does not
    /// re-verify the signature — `verify_and_store_prekey` did that before
    /// the row was inserted.
    fn cached_prekey(&self, peer: &PeerId) -> Option<X25519Pub> {
        let store = self.message_store.as_ref()?;
        match store.load_prekey(&peer.to_bytes()) {
            Ok(Some((pub_bytes, _sig))) => Some(X25519Pub::from(pub_bytes)),
            _ => None,
        }
    }

    /// Serialize the current ratchet state for a peer and write it to the
    /// store. Called after every encrypt and decrypt.
    fn persist_session(&self, peer: &PeerId) {
        let Some(store) = self.message_store.as_ref() else { return; };
        let Some(session) = self.sessions.get(peer) else { return; };
        match session.to_json() {
            Ok(json) => {
                if let Err(e) = store.save_session(&peer.to_bytes(), json.as_bytes()) {
                    warn!("Failed to persist session for {}: {}", peer, e);
                }
            }
            Err(e) => warn!("Failed to serialize session for {}: {}", peer, e),
        }
    }

    /// Target size of the unused one-time prekey pool. Each `prekey/Request`
    /// from a peer pops one OTPK; we top the pool back up at startup and
    /// whenever it gets depleted.
    const OTPK_POOL_TARGET: i64 = 20;

    /// Ensure we have at least `OTPK_POOL_TARGET` unused OTPKs by
    /// generating fresh ones and signing them with our Ed25519 identity.
    /// Safe to call any number of times — only generates the deficit.
    pub fn replenish_otpk_pool(&self) -> Result<()> {
        let Some(store) = self.message_store.as_ref() else {
            return Ok(());
        };
        let unused = store.unused_otpk_count()?;
        if unused >= Self::OTPK_POOL_TARGET {
            return Ok(());
        }
        let needed = (Self::OTPK_POOL_TARGET - unused) as usize;
        for _ in 0..needed {
            let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let public = X25519Pub::from(&secret);
            // Reuse the same Ed25519 domain-separated signing layout as
            // the long-term signed prekey — recipients verify both with
            // `prekey_signing_bytes`.
            let sig = self
                .identity
                .signing_key()
                .sign(&prekey_signing_bytes(public.as_bytes()));
            store.add_my_otpk(&secret.to_bytes(), public.as_bytes(), &sig.to_bytes())?;
        }
        info!(
            "Replenished OTPK pool: generated {} new keys (was {} unused, target {})",
            needed,
            unused,
            Self::OTPK_POOL_TARGET
        );
        Ok(())
    }

    /// Pop one unused OTPK from the store for inclusion in a prekey
    /// response. Returns `None` if the pool is empty (responder will
    /// reply without an OTPK and the initiator falls back to 2-DH).
    /// After popping, asynchronously top up the pool.
    fn pop_one_otpk_bundle(&mut self) -> Option<OneTimePrekey> {
        let store = self.message_store.as_ref()?;
        let popped = match store.pop_unused_otpk() {
            Ok(Some((id, pub_arr, sig_arr))) => Some(OneTimePrekey {
                id,
                x25519_public: pub_arr,
                signature: sig_arr,
            }),
            Ok(None) => {
                warn!("OTPK pool empty — peer will fall back to 2-DH X3DH");
                None
            }
            Err(e) => {
                warn!("Failed to pop OTPK: {}", e);
                None
            }
        };
        // Best-effort top-up; failures are logged inside.
        if let Err(e) = self.replenish_otpk_pool() {
            warn!("Failed to replenish OTPK pool: {}", e);
        }
        popped
    }

    /// Verify the Ed25519 signature on an OTPK bundle against `peer`'s
    /// PeerId-embedded identity key. Same verification path as the
    /// long-term signed prekey.
    fn verify_otpk(&self, peer: PeerId, otpk: &OneTimePrekey) -> Result<()> {
        let multihash = peer.as_ref();
        if multihash.code() != 0 {
            anyhow::bail!("peer id does not embed an inline public key");
        }
        let libp2p_pk = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest())
            .map_err(|e| anyhow::anyhow!("decode peer pubkey: {}", e))?;
        let ed_bytes = libp2p_pk
            .try_into_ed25519()
            .map_err(|_| anyhow::anyhow!("peer is not Ed25519"))?
            .to_bytes();
        let verifying = VerifyingKey::from_bytes(&ed_bytes)
            .map_err(|e| anyhow::anyhow!("ed25519 key decode: {}", e))?;
        let sig = Ed25519Sig::from_bytes(&otpk.signature);
        verifying
            .verify_strict(&prekey_signing_bytes(&otpk.x25519_public), &sig)
            .map_err(|_| anyhow::anyhow!("OTPK signature did not verify"))?;
        Ok(())
    }

    /// Lazily restore an in-memory session from the persistent store. Called
    /// before paths that look up `self.sessions`; returns true if a session
    /// now exists for the peer.
    fn restore_session_if_persisted(&mut self, peer: &PeerId) -> bool {
        if self.sessions.contains_key(peer) {
            return true;
        }
        let Some(store) = self.message_store.as_ref() else { return false; };
        match store.load_session(&peer.to_bytes()) {
            Ok(Some(blob)) => match std::str::from_utf8(&blob)
                .ok()
                .and_then(|s| RatchetState::from_json(s).ok())
            {
                Some(state) => {
                    self.sessions.insert(*peer, state);
                    true
                }
                None => {
                    warn!("Stored session blob for {} is corrupt; ignoring", peer);
                    false
                }
            },
            Ok(None) => false,
            Err(e) => {
                warn!("Failed to load session for {}: {}", peer, e);
                false
            }
        }
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

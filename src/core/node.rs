use anyhow::Result;
use libp2p::{
    kad,
    noise,
    swarm::Swarm,
    tcp, yamux, PeerId, SwarmBuilder, Multiaddr,
    request_response,
};
use libp2p::futures::StreamExt;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

use crate::core::{Config, Identity};
use crate::core::identity::prekey_signing_bytes;
use crate::crypto::{ratchet::RatchetState, x3dh};
use crate::network::{
    mailbox, Behaviour, DirectMessageRequest, OneTimePrekey, PrekeyRequest, PrekeyResponse,
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
    /// Phase-4-mailbox: Kad `get_providers` queries we issued, keyed by
    /// the Kademlia QueryId so we can correlate the result back to the
    /// slot we polled. On result we kick off `get_record` for each
    /// provider, tracked in `pending_record_queries`.
    pending_provider_queries: HashMap<kad::QueryId, i64>,
    /// Phase-4-mailbox: Kad `get_record` queries we issued, keyed by
    /// the Kademlia QueryId. The value is `(slot_id, sender_pid)` so
    /// we can verify decryption attribution.
    pending_record_queries: HashMap<kad::QueryId, (i64, PeerId)>,
    /// Phase-5-mailbox-ACK: Kad `get_record` queries against the ACK
    /// namespace (`ack_kad_key`). Value is the local `mailbox_drops.id`
    /// so we can call `mailbox_drop_ack` on FoundRecord and skip
    /// future republishes of that drop. Distinct map from
    /// `pending_record_queries` because the GetRecord result handler
    /// branches on which side fired the query.
    pending_ack_queries: HashMap<kad::QueryId, i64>,
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
            pending_provider_queries: HashMap::new(),
            pending_record_queries: HashMap::new(),
            pending_ack_queries: HashMap::new(),
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
        let obfs_key = self.config.obfs_key;
        let obfs_jitter_ms = self.config.obfs_jitter_ms;

        if obfs_key.is_some() {
            info!(
                "ScrambleStream active: TCP traffic XOR'd with ChaCha20 keystream before Noise"
            );
            if let Some(j) = obfs_jitter_ms {
                if j > 0 {
                    info!(
                        "ScrambleStream jitter active: per-frame uniform delay in [0, {}] ms",
                        j
                    );
                }
            }
        }

        // NOTE: .with_quic() is disabled while the "quic" libp2p feature is off
        // (see Cargo.toml). TCP+Noise+Yamux is enough for LAN testing. Restore
        // both when the local toolchain can build `ring` again.
        //
        // We bypass `.with_tcp(...)` and assemble the transport manually via
        // `.with_other_transport(...)` so we can splice the optional
        // `ScrambleStream` obfuscation layer in BETWEEN raw TCP and the Noise
        // XX upgrade. Without that injection point, DPI boxes can still
        // recognise the Noise handshake signature. See `audit/INVARIANTS.md`
        // §17 (Phase 4b).
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|kp| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                use libp2p::core::muxing::StreamMuxerBox;
                use libp2p::core::transport::Transport as _;
                use libp2p::core::upgrade::Version;
                use libp2p::core::ConnectedPoint;
                use crate::network::{scramble_handshake, MaybeScrambled};

                let tcp_cfg = tcp::Config::default().port_reuse(true).nodelay(true);
                let base = libp2p::tcp::tokio::Transport::new(tcp_cfg);

                // Always go through the same `.and_then` so the Output
                // type is uniformly `MaybeScrambled<TcpStream>` — without
                // the enum the if/else branches produce different
                // concrete types and the upgrade chain can't be applied.
                let inner = base.and_then(move |stream, endpoint| {
                    // Listener vs Dialer determines who picks the nonce
                    // (dialer) and who reads it (listener).
                    let is_dialer = matches!(endpoint, ConnectedPoint::Dialer { .. });
                    let key = obfs_key;
                    let jitter = obfs_jitter_ms;
                    async move {
                        match key {
                            Some(k) => scramble_handshake(stream, &k, is_dialer, jitter)
                                .await
                                .map(MaybeScrambled::Scrambled),
                            None => Ok(MaybeScrambled::Plain(stream)),
                        }
                    }
                });

                // Standard Noise XX → Yamux upgrade chain, identical to what
                // `with_tcp` would have produced — just sitting on top of an
                // optionally-scrambled TCP stream rather than raw TCP.
                let noise_cfg = noise::Config::new(kp)?;
                Ok(inner
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise_cfg)
                    .multiplex(yamux::Config::default())
                    .map(|(p, c), _| (p, StreamMuxerBox::new(c))))
            })?
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

        // Phase-4-mailbox: republish drops to the DHT periodically so
        // they outlive Kad's per-record TTL.
        let mut republish_tick =
            tokio::time::interval(Duration::from_secs(mailbox::REPUBLISH_TICK_SECS));
        republish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        republish_tick.tick().await;

        // Phase-4-mailbox: walk the DHT for drops addressed to us.
        let mut poll_tick =
            tokio::time::interval(Duration::from_secs(mailbox::POLL_TICK_SECS));
        poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Fire the first poll soon after startup (1 second) so users
        // running `zerocenter` after being offline don't wait 10 min
        // for a stale-mailbox sweep.
        tokio::time::sleep(Duration::from_secs(1)).await;

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
                            // `message` is plaintext — keep at debug so it
                            // doesn't end up in a remote log aggregator's
                            // info stream. INVARIANTS §19.
                            debug!("Send requested to {}: {}", peer_id, message);
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
                        match store.mailbox_drops_cleanup() {
                            Ok(0) => {}
                            Ok(n) => info!("Mailbox sweep: deleted {} expired/ACK'd drops", n),
                            Err(e) => warn!("Mailbox sweep failed: {}", e),
                        }
                    }
                }

                // Phase-4-mailbox republish.
                _ = republish_tick.tick() => {
                    self.republish_mailbox_drops(&mut swarm);
                }

                // Phase-4-mailbox poll.
                _ = poll_tick.tick() => {
                    self.poll_mailbox_slots(&mut swarm);
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
                self.handle_kad_event(swarm, kad_event);
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
                    // Audit F7: full identify payload includes the
                    // peer's listening addresses, agent string, and
                    // protocol set. None is plaintext-secret but all
                    // is network-topology metadata; demote to debug
                    // so it doesn't reach remote log aggregators
                    // configured at INFO. Keep only the PeerId +
                    // count-of-protocols at info level for liveness
                    // visibility.
                    debug!("Identify from {}: agent={:?} protocols={:?} listen_addrs={:?}",
                        peer_id, info.agent_version, info.protocols, info.listen_addrs);
                    info!(
                        "Identify from {} ({} protocols announced)",
                        peer_id,
                        info.protocols.len()
                    );
                }
                libp2p::identify::Event::Sent { peer_id } => {
                    debug!("Sent identify info to {}", peer_id);
                }
                libp2p::identify::Event::Pushed { peer_id, .. } => {
                    debug!("Pushed identify info to {}", peer_id);
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
            // Phase 5 encrypt-once. If we can ratchet-encrypt right
            // now (session exists OR cached prekey allows X3DH
            // bootstrap), do it ONCE and feed the same ciphertext into
            // BOTH the outbox AND the mailbox publish — so when the
            // recipient eventually receives the message via either
            // path, the OTHER path's copy is byte-identical and the
            // ratchet's already-consumed-mk check makes the second
            // arrival a silent no-op. No more F8 duplicate delivery.
            //
            // If we can't encrypt yet (no session, no cached prekey),
            // fall through to the legacy plaintext outbox path. The
            // mailbox can't help — the recipient hasn't published a
            // prekey to us — so they must come online to us directly
            // for the first message.
            let outbox_result = if let Some(wire_bytes) =
                self.try_encrypt_offline(peer, &plaintext)
            {
                self.put_mailbox_drop_bytes(swarm, peer, &wire_bytes);
                self.message_store.as_ref().map(|store| {
                    store.outbox_add_wire(&peer.to_bytes(), &wire_bytes, 7 * 24 * 3600)
                })
            } else {
                self.message_store.as_ref().map(|store| {
                    store.outbox_add(&peer.to_bytes(), plaintext.as_bytes(), 7 * 24 * 3600)
                })
            };
            match outbox_result {
                Some(Ok(_)) => {
                    info!("Peer {} not connected — queued in outbox", peer);
                    println!(
                        "📭 Peer not connected — message queued (will send when peer appears)"
                    );
                }
                Some(Err(e)) => {
                    error!("Failed to add to outbox for {}: {}", peer, e);
                }
                None => {
                    error!("No message store available; message to {} is lost", peer);
                }
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
    /// reachable (ConnectionEstablished or mDNS discovery). Two row
    /// kinds, distinguished by `is_wire_bytes`:
    ///
    /// - `false` (legacy / no-session-at-queue-time): content is
    ///   plaintext. Re-feed through `try_send_or_queue`, which encrypts
    ///   now (session probably exists by now, having just connected).
    /// - `true` (Phase 5 encrypt-once): content is the already-encrypted
    ///   `ProtocolMessage` wire bytes. Send directly via
    ///   `request_response::send_request` so the recipient sees the
    ///   byte-identical ciphertext that was published to the DHT —
    ///   ratchet dedup makes the second arrival a no-op.
    ///
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

        for (row_id, content, is_wire) in entries {
            if is_wire {
                // Phase 5 encrypt-once: send the stored ProtocolMessage
                // bytes directly. The ratchet has already advanced for
                // this message at outbox-add time; re-encrypting now
                // would produce a different ciphertext and the
                // recipient would treat them as two distinct messages.
                debug!("Draining outbox row {} for {} as wire bytes ({}B)",
                    row_id, peer, content.len());
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer, DirectMessageRequest(content));
            } else {
                let plaintext = String::from_utf8_lossy(&content).into_owned();
                self.try_send_or_queue(swarm, peer, plaintext);
            }
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
        let Some((wire_bytes, ttl)) = self.ratchet_encrypt_and_wrap(peer, plaintext, hello) else {
            return;
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
                ttl,
            ) {
                warn!("Failed to store local plaintext copy: {}", e);
            }
        }
        self.persist_session(&peer);

        println!("📤 Encrypted message sent to {}", peer);
    }

    /// Phase-4-mailbox helper. Ratchet-encrypts `plaintext` for `peer`,
    /// wraps it in a signed `ProtocolMessage`, returns the wire bytes
    /// AND the message's TTL. Side-effects (advance ratchet state, log
    /// errors) are identical to the send path, but no actual network
    /// I/O happens — the caller decides whether to `send_request` or
    /// `put_record` the bytes. Returns `None` on any encrypt/serialize
    /// failure (every internal error path is logged at `error!`).
    ///
    /// Caller must ensure a session exists for `peer` first — typically
    /// by calling `restore_session_if_persisted` and only invoking this
    /// when that succeeded. `hello` is `None` for an existing-session
    /// send and `Some(...)` only for the first message of a fresh X3DH
    /// session.
    fn ratchet_encrypt_and_wrap(
        &mut self,
        peer: PeerId,
        plaintext: &str,
        hello: Option<FirstMessageHello>,
    ) -> Option<(Vec<u8>, i64)> {
        let ad = Self::ratchet_ad(&self.identity.peer_id(), &peer);

        let ratchet_msg = {
            let session = self.sessions.get_mut(&peer)?;
            match session.encrypt(plaintext.as_bytes(), &ad) {
                Ok(m) => m,
                Err(e) => {
                    error!("Ratchet encrypt failed for {}: {}", peer, e);
                    return None;
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
                return None;
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
                return None;
            }
        };

        let ttl = proto_msg.ttl;
        let wire_bytes = match proto_msg.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize ProtocolMessage: {}", e);
                return None;
            }
        };

        Some((wire_bytes, ttl))
    }

    /// Phase 5 encrypt-once helper. Performs the ratchet encryption
    /// (existing session OR fresh X3DH bootstrap from a cached prekey)
    /// for `peer` and returns the resulting `ProtocolMessage` wire
    /// bytes. Returns `None` if neither encryption path is available
    /// (no session and no cached prekey — typical for a brand-new
    /// contact whose prekey we've never fetched).
    ///
    /// Centralizing the encryption here lets the offline branch of
    /// `try_send_or_queue` encrypt EXACTLY ONCE and feed the same
    /// wire bytes into both the persistent outbox and the DHT mailbox
    /// publish path, so the recipient sees one ciphertext (not two
    /// distinct ones at different ratchet positions — audit F8).
    fn try_encrypt_offline(&mut self, peer: PeerId, plaintext: &str) -> Option<Vec<u8>> {
        if self.restore_session_if_persisted(&peer) {
            return self
                .ratchet_encrypt_and_wrap(peer, plaintext, None)
                .map(|(b, _ttl)| b);
        }
        let prekey_pub = self.cached_prekey(&peer)?;
        // Inline X3DH bootstrap (parallel to `bootstrap_initiator_and_send`
        // but without the network send — the wire bytes are returned
        // to the caller for delivery via outbox + mailbox).
        let hello = match self.cached_otpks.remove(&peer) {
            Some(otpk_bundle) => {
                let otpk_pub = X25519Pub::from(otpk_bundle.x25519_public);
                let (eph_pub, sk) = x3dh::initiator_derive_with_otpk(
                    self.identity.x25519_secret(),
                    &prekey_pub,
                    &otpk_pub,
                );
                let session = RatchetState::new_initiator(sk, prekey_pub);
                self.sessions.insert(peer, session);
                FirstMessageHello {
                    x3dh_eph: eph_pub,
                    otpk_id: Some(otpk_bundle.id),
                }
            }
            None => {
                let (eph_pub, sk) = x3dh::initiator_derive(
                    self.identity.x25519_secret(),
                    &prekey_pub,
                );
                let session = RatchetState::new_initiator(sk, prekey_pub);
                self.sessions.insert(peer, session);
                FirstMessageHello {
                    x3dh_eph: eph_pub,
                    otpk_id: None,
                }
            }
        };
        self.ratchet_encrypt_and_wrap(peer, plaintext, Some(hello))
            .map(|(b, _ttl)| b)
    }

    /// Phase 5 encrypt-once helper. Publishes pre-encrypted
    /// `ProtocolMessage` wire bytes to the DHT mailbox at
    /// `(slot_kad_key(recipient, slot), drop_kad_key(recipient, self, slot))`.
    /// Records the drop locally so the republish loop keeps it alive
    /// until `expires_at` or recipient ACK.
    ///
    /// The caller supplies the wire bytes — typically from
    /// `try_encrypt_offline` — so the same ciphertext can also be
    /// queued into the outbox via `outbox_add_wire`.
    fn put_mailbox_drop_bytes(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        wire_bytes: &[u8],
    ) {
        let now = unix_seconds_now();
        let slot = mailbox::slot_id_for(now);
        let recipient_bytes = peer.to_bytes();
        let sender_bytes = self.identity.peer_id().to_bytes();
        let slot_key = mailbox::slot_kad_key(&recipient_bytes, slot);
        let drop_key = mailbox::drop_kad_key(&recipient_bytes, &sender_bytes, slot);

        if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(slot_key.clone()) {
            warn!("Mailbox start_providing({}) failed: {:?}", peer, e);
        }

        let record = kad::Record {
            key: drop_key.clone(),
            value: wire_bytes.to_vec(),
            publisher: None,
            expires: None,
        };
        match swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
        {
            Ok(_qid) => {
                debug!(
                    "Mailbox put_record submitted for {} at slot {} ({}B)",
                    peer,
                    slot,
                    wire_bytes.len()
                );
            }
            Err(e) => {
                warn!("Mailbox put_record({}) failed: {:?}", peer, e);
                return;
            }
        }

        if let Some(ref store) = self.message_store {
            let expires_at = now + mailbox::DEFAULT_DROP_TTL_SECS;
            if let Err(e) = store.mailbox_drop_record(&recipient_bytes, slot, wire_bytes, expires_at)
            {
                warn!("Failed to persist mailbox_drop for {}: {}", peer, e);
            }
        }

        info!("📨 Mailbox drop published for {} (slot {})", peer, slot);
    }

    /// Phase-4-mailbox republish tick body. Reads
    /// `mailbox_drops_due_for_republish(REPUBLISH_AFTER_SECS)` and
    /// re-`put_record` + re-`start_providing` each row. Touches the
    /// `last_published_at` column on each successful put so it isn't
    /// re-due next tick.
    ///
    /// We process all due rows in a single tick — typically just a
    /// handful, since each republish is on a ~30-minute interval and
    /// most users send only intermittent DMs. Worst case (a burst of
    /// offline sends followed by a republish), Kad backpressures
    /// internally; `put_record` returns immediately whether or not
    /// the query has actually finished.
    fn republish_mailbox_drops(&mut self, swarm: &mut Swarm<Behaviour>) {
        let Some(ref store) = self.message_store else {
            return;
        };
        let due = match store.mailbox_drops_due_for_republish(mailbox::REPUBLISH_AFTER_SECS) {
            Ok(v) => v,
            Err(e) => {
                warn!("mailbox_drops_due_for_republish failed: {}", e);
                return;
            }
        };
        if due.is_empty() {
            return;
        }
        info!("Republishing {} mailbox drop(s)", due.len());
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        for (id, recipient_pid, slot, wire_bytes) in due {
            let slot_key = mailbox::slot_kad_key(&recipient_pid, slot);
            let drop_key = mailbox::drop_kad_key(&recipient_pid, &my_pid_bytes, slot);
            let ack_key = mailbox::ack_kad_key(&recipient_pid, &my_pid_bytes, slot);

            // Phase 5 mailbox ACK polling. Issue a `get_record` against
            // the recipient's ACK key for this drop. If they've already
            // ingested + ACK'd, the response handler will call
            // `mailbox_drop_ack(id)` and the next republish tick skips
            // this row entirely. We still issue the put_record below
            // optimistically — one wasted republish per drop after the
            // ACK lands but before our query sees it is acceptable.
            let ack_qid = swarm.behaviour_mut().kademlia.get_record(ack_key);
            self.pending_ack_queries.insert(ack_qid, id);

            if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(slot_key) {
                warn!("Republish start_providing failed for id={}: {:?}", id, e);
            }
            let record = kad::Record {
                key: drop_key,
                value: wire_bytes,
                publisher: None,
                expires: None,
            };
            match swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, kad::Quorum::One)
            {
                Ok(_qid) => {
                    if let Err(e) = store.mailbox_drop_touch(id) {
                        warn!("mailbox_drop_touch({}) failed: {}", id, e);
                    }
                }
                Err(e) => warn!("Republish put_record failed for id={}: {:?}", id, e),
            }
        }
    }

    /// Phase-4-mailbox poll tick body. Queries the providers DHT for
    /// every slot in `last_polled..now_slot`, capped at the last 24
    /// slots so a fresh install doesn't fan out into a week of queries.
    /// Results come in async via `OutboundQueryProgressed` events,
    /// correlated through `pending_provider_queries`.
    ///
    /// We optimistically set `last_polled_slot = now_slot - 1` AFTER
    /// kicking off the queries — re-querying the in-progress slot on
    /// every tick ensures drops added during the current hour are
    /// still picked up, while completed past slots only need one
    /// query attempt.
    fn poll_mailbox_slots(&mut self, swarm: &mut Swarm<Behaviour>) {
        let Some(ref store) = self.message_store else {
            return;
        };
        let now_slot = mailbox::slot_id_for(unix_seconds_now());
        let last_polled = store.mailbox_last_polled_slot().unwrap_or(0);
        // Cap range to 24 slots so a long-offline recipient doesn't
        // blast the DHT with a 168-slot fan-out. Older drops are
        // still kept alive by the sender's republish loop.
        let start = std::cmp::max(last_polled + 1, now_slot - 23);
        if start > now_slot {
            return;
        }

        let my_pid_bytes = self.identity.peer_id().to_bytes();
        let mut queued = 0;
        for slot in start..=now_slot {
            let slot_key = mailbox::slot_kad_key(&my_pid_bytes, slot);
            let qid = swarm.behaviour_mut().kademlia.get_providers(slot_key);
            self.pending_provider_queries.insert(qid, slot);
            queued += 1;
        }
        if queued > 0 {
            debug!("Mailbox poll: queued {} provider queries (slots {}..={})",
                queued, start, now_slot);
        }
        // Bump last_polled to one before now_slot — the current slot
        // remains "in progress" and gets re-queried each tick.
        if now_slot > 0 {
            if let Err(e) = store.mailbox_set_last_polled_slot(now_slot - 1) {
                warn!("mailbox_set_last_polled_slot failed: {}", e);
            }
        }
    }

    /// Handle a Kademlia event. Most events we ignore (libp2p's kad
    /// behaviour is chatty); the two we care about are the results of
    /// our own `get_providers` and `get_record` queries, correlated
    /// back through `pending_provider_queries` / `pending_record_queries`.
    fn handle_kad_event(&mut self, swarm: &mut Swarm<Behaviour>, event: kad::Event) {
        let kad::Event::OutboundQueryProgressed { id, result, .. } = event else {
            // Bootstrap, routing-table updates, etc. — log only if
            // they look unusual; the default kad behaviour is very
            // verbose.
            return;
        };
        match result {
            kad::QueryResult::GetProviders(Ok(ok)) => {
                self.handle_mailbox_providers_result(swarm, id, ok);
            }
            kad::QueryResult::GetProviders(Err(e)) => {
                if let Some(slot) = self.pending_provider_queries.remove(&id) {
                    debug!("Mailbox get_providers for slot {} failed: {:?}", slot, e);
                }
            }
            kad::QueryResult::GetRecord(Ok(ok)) => {
                // Phase 5: GetRecord results come from two distinct
                // query sources — the recipient-side drop fetch
                // (`pending_record_queries`) and the sender-side ACK
                // poll (`pending_ack_queries`). Dispatch by which map
                // owns the QueryId. We check ACK first because it has
                // simpler semantics (no decrypt path).
                if self.pending_ack_queries.contains_key(&id) {
                    self.handle_mailbox_ack_result(id, ok);
                } else {
                    self.handle_mailbox_record_result(swarm, id, ok);
                }
            }
            kad::QueryResult::GetRecord(Err(e)) => {
                if let Some(drop_id) = self.pending_ack_queries.remove(&id) {
                    debug!("Mailbox ACK get_record for drop_id={} failed: {:?}", drop_id, e);
                } else if let Some((slot, sender)) = self.pending_record_queries.remove(&id) {
                    debug!("Mailbox get_record for slot {} sender {} failed: {:?}",
                        slot, sender, e);
                }
            }
            kad::QueryResult::PutRecord(_) | kad::QueryResult::StartProviding(_) => {
                // Our own put/announce queries; nothing more to do.
            }
            _ => {}
        }
    }

    /// Branch of `handle_kad_event` that processes a `GetProviders`
    /// result for one of our outstanding mailbox poll queries.
    fn handle_mailbox_providers_result(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        id: kad::QueryId,
        ok: kad::GetProvidersOk,
    ) {
        let Some(&slot) = self.pending_provider_queries.get(&id) else {
            return;
        };
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        match ok {
            kad::GetProvidersOk::FoundProviders { providers, .. } => {
                if providers.is_empty() {
                    return;
                }
                debug!(
                    "Mailbox slot {} has {} provider(s)",
                    slot,
                    providers.len()
                );
                for sender in providers {
                    if sender == self.identity.peer_id() {
                        // We see ourselves as a provider for our own
                        // outgoing drops — skip; we don't want to fetch
                        // our own records back.
                        continue;
                    }
                    let drop_key = mailbox::drop_kad_key(&my_pid_bytes, &sender.to_bytes(), slot);
                    let qid = swarm.behaviour_mut().kademlia.get_record(drop_key);
                    self.pending_record_queries.insert(qid, (slot, sender));
                }
            }
            kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
                // Final step for this query — clean up.
                self.pending_provider_queries.remove(&id);
            }
        }
    }

    /// Branch of `handle_kad_event` that processes a `GetRecord` result
    /// — i.e. the actual encrypted ProtocolMessage bytes for one drop.
    /// Routes through the same `process_incoming_dm` pipeline used for
    /// directly-delivered DMs, so signature verification, ratchet
    /// decrypt, dedup, etc. all happen identically.
    fn handle_mailbox_record_result(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        id: kad::QueryId,
        ok: kad::GetRecordOk,
    ) {
        let Some((slot, sender)) = self.pending_record_queries.get(&id).copied() else {
            return;
        };
        match ok {
            kad::GetRecordOk::FoundRecord(rec) => {
                let bytes = rec.record.value.clone();
                debug!(
                    "Mailbox drop fetched for slot {} sender {} ({}B)",
                    slot,
                    sender,
                    bytes.len()
                );
                // Reuse the existing DM ingestion pipeline. The
                // sender PeerId is the transport-level attribution
                // we'd normally get from the request-response source;
                // we pass it through here even though the bytes came
                // out of the DHT, because `process_incoming_dm`
                // cross-checks the signed envelope's `from` against
                // this value (INVARIANTS §2). A mailbox drop is
                // legitimate iff the signed envelope's `from` equals
                // the provider PeerId we fetched it from.
                let ingested = self.process_incoming_dm(swarm, sender, &bytes);

                // Phase 5 ACK loop. If ingestion succeeded, publish an
                // empty record at `ack_kad_key(self, sender, slot)`
                // so the sender's republish loop sees the ACK and
                // stops re-putting this drop. If ingestion FAILED
                // (envelope-verify mismatch, signature mismatch,
                // §2 cross-check failure, ratchet-decrypt failure),
                // we DON'T ACK — that tells the sender to keep
                // republishing, which is the right behaviour for a
                // legitimately-broken delivery attempt.
                if ingested {
                    self.publish_mailbox_ack(swarm, sender, slot);
                }
            }
            kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. } => {
                self.pending_record_queries.remove(&id);
            }
        }
    }

    /// Phase 5 ACK consumer (sender side). A previously-issued
    /// `get_record(ack_kad_key)` returned a record — that means the
    /// recipient has fetched + ingested the drop we published. Call
    /// `mailbox_drop_ack(id)` so the storage row marks
    /// `acknowledged_at`; the next `mailbox_drops_due_for_republish`
    /// scan will skip it, and the next cleanup tick will GC it after
    /// the 24-hour ACK retention window.
    ///
    /// We don't validate the record VALUE — the v0 ACK record carries
    /// the recipient's PeerId for debuggability but it's not
    /// cryptographically authenticated. A malicious third party
    /// publishing a fake ACK only DoSes the sender (stops republish);
    /// the actual recipient's eventual re-poll would still surface
    /// the drop on any DHT node that hasn't expired it yet.
    fn handle_mailbox_ack_result(&mut self, id: kad::QueryId, ok: kad::GetRecordOk) {
        let Some(drop_id) = self.pending_ack_queries.remove(&id) else {
            return;
        };
        if let kad::GetRecordOk::FoundRecord(_) = ok {
            debug!("Mailbox ACK observed for drop_id={}", drop_id);
            if let Some(ref store) = self.message_store {
                if let Err(e) = store.mailbox_drop_ack(drop_id) {
                    warn!("mailbox_drop_ack({}) failed: {}", drop_id, e);
                }
            }
        }
    }

    /// Phase 5 ACK publisher. After successfully ingesting a mailbox-
    /// fetched drop from `sender` at `slot`, publish a tiny presence
    /// record at `ack_kad_key(self, sender, slot)`. The value is just
    /// the recipient's PeerId bytes (for debuggability — the sender
    /// can confirm the ACK came from the right peer); it's not
    /// cryptographically authenticated because the obfs envelope
    /// already authenticates the underlying message and the sender
    /// only needs to know SOMEONE retrieved their drop. A malicious
    /// third party publishing a fake ACK would only DoS the sender
    /// (they'd stop republishing legitimate drops); the legitimate
    /// recipient's eventual re-poll would still surface the drop
    /// from any DHT node that hasn't expired it yet.
    fn publish_mailbox_ack(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        sender: PeerId,
        slot: i64,
    ) {
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        let sender_bytes = sender.to_bytes();
        let ack_key = mailbox::ack_kad_key(&my_pid_bytes, &sender_bytes, slot);
        let record = kad::Record {
            key: ack_key,
            value: my_pid_bytes.clone(),
            publisher: None,
            expires: None,
        };
        match swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
        {
            Ok(_qid) => {
                debug!("Mailbox ACK published for sender {} at slot {}", sender, slot);
            }
            Err(e) => {
                warn!(
                    "Mailbox ACK put_record failed for sender {} at slot {}: {:?}",
                    sender, slot, e
                );
            }
        }
    }

    // ============================================================
    // Ratchet integration: receive path
    // ============================================================

    /// Returns `true` iff the inbound message was successfully
    /// decrypted and stored. Used by the mailbox path to decide
    /// whether to publish an ACK (Phase 5). The boolean is `false` on
    /// any failure path (parse / signature / cross-check / expiry /
    /// payload-parse / decrypt) AND on the "queued waiting for prekey
    /// fetch" path — that case may eventually become a success but
    /// the caller can't know yet, and the sender should keep
    /// republishing until it does. The non-mailbox call-site
    /// (request-response Request handler) ignores the return value.
    fn process_incoming_dm(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        transport_peer: PeerId,
        request_bytes: &[u8],
    ) -> bool {
        // Step 1: parse the outer envelope.
        let proto_msg = match ProtocolMessage::from_bytes(request_bytes) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse DM from {}: {}", transport_peer, e);
                return false;
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
                return false;
            }
        };

        // Step 3: transport peer must equal the signed sender.
        if verified_sender != transport_peer {
            warn!(
                "Dropping DM: transport peer {} != signed sender {}",
                transport_peer, verified_sender
            );
            return false;
        }

        // Step 3.5 (audit F5): drop expired envelopes BEFORE doing any
        // state-modifying work.
        if proto_msg.is_expired() {
            debug!(
                "Dropping stale DM from {}: envelope past its TTL",
                verified_sender
            );
            return false;
        }

        // Step 4: parse the encrypted payload.
        let payload = match EncryptedPayload::from_bytes(&proto_msg.payload) {
            Ok(p) => p,
            Err(e) => {
                warn!("Malformed EncryptedPayload from {}: {}", verified_sender, e);
                return false;
            }
        };

        // Step 5: route to the right decrypt path.
        if self.restore_session_if_persisted(&verified_sender) {
            return self.decrypt_and_store(verified_sender, &payload);
        }

        // No session yet — need responder bootstrap. We need both the
        // initiator's X3DH ephemeral (in the payload) AND the initiator's
        // long-term X25519 prekey (cached or fetched).
        let Some(eph_bytes) = payload.x3dh_eph else {
            warn!(
                "Dropping DM from {}: no session and no x3dh_eph in payload",
                verified_sender
            );
            return false;
        };

        if let Some(initiator_x25519) = self.cached_prekey(&verified_sender) {
            self.bootstrap_responder_and_decrypt(
                verified_sender,
                eph_bytes,
                initiator_x25519,
                &payload,
            )
        } else {
            // Queue and fetch. Caller treats this as a non-ACK case.
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
            false
        }
    }

    /// Returns `true` iff bootstrap succeeded AND first-message decrypt
    /// succeeded. Used by `process_incoming_dm` to propagate
    /// success/fail up to the Phase 5 mailbox ACK loop.
    fn bootstrap_responder_and_decrypt(
        &mut self,
        peer: PeerId,
        eph_bytes: [u8; 32],
        initiator_x25519: X25519Pub,
        payload: &EncryptedPayload,
    ) -> bool {
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
                    return false;
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

        // Audit F9: install the session ONLY if first-message decrypt
        // succeeds.
        self.sessions.insert(peer, session);
        let decrypted_ok = self.decrypt_first_message(peer, payload);
        if !decrypted_ok {
            self.sessions.remove(&peer);
            return false;
        }

        // Success path: delete the consumed OTPK row so it can't be
        // reused even by ourselves. (Failure path above doesn't touch
        // the OTPK row — it stays marked consumed by `pop_unused_otpk`
        // and is now blocked from re-load by the audit-F3 consumed_at
        // gate in `load_otpk_private`, so even a future replay of the
        // same first-message can't re-bootstrap. One OTPK burned per
        // bad-first-message is also mild DoS resistance.)
        if let (Some(id), Some(store)) = (payload.otpk_id, self.message_store.as_ref()) {
            if let Err(e) = store.delete_otpk(id) {
                warn!("Failed to delete consumed OTPK id={}: {}", id, e);
            }
        }
        true
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
        // Plaintext stays at debug; the println! below is the user-facing
        // terminal output. INVARIANTS §19.
        debug!("Decrypted first DM from {}: {}", peer, text);
        println!("\n🔓 {}: {}", peer, text);
        println!("> ");
        true
    }

    /// Returns `true` iff the message was successfully ratchet-
    /// decrypted and stored. Phase 5 mailbox ACK path uses this signal.
    fn decrypt_and_store(&mut self, peer: PeerId, payload: &EncryptedPayload) -> bool {
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
                    return false;
                }
            };
            match session.decrypt(&ratchet_msg, &ad) {
                Ok(pt) => pt,
                Err(e) => {
                    warn!("Ratchet decrypt failed from {}: {}", peer, e);
                    return false;
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
        // Plaintext stays at debug; the println! below is the user-facing
        // terminal output. INVARIANTS §19.
        debug!("Decrypted DM from {}: {}", peer, text);
        println!("\n🔓 {}: {}", peer, text);
        println!("> ");
        true
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
fn unix_seconds_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

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

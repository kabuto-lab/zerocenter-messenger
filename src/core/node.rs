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
    /// Phase 5 OTPK-pool-drain defence. Tracks the last time we
    /// honored a PrekeyRequest from each peer with a one-time prekey
    /// attached. Within `OTPK_FETCH_COOLDOWN_SECS` of a previous
    /// honored fetch, we still respond to the same peer's request but
    /// without attaching an OTPK — forcing rapid-fire requesters into
    /// the 2-DH fallback path. Pruned periodically on the cleanup
    /// tick to bound memory.
    recent_otpk_fetches: HashMap<PeerId, i64>,
    /// Push-refresh channel for the GUI. `None` on the headless CLI path
    /// (no listener); `Some` when `--gui` wired a receiver via
    /// [`Self::set_gui_event_sender`]. Sends use `try_send` so a slow
    /// or stalled webview never blocks the node event loop — dropped
    /// events just mean the user sees the new message on their next
    /// manual action (still better than the old "must reopen chat" gap).
    gui_tx: Option<mpsc::Sender<GuiEvent>>,
}

/// Events the node pushes to a connected GUI frontend. Currently only
/// inbound-DM notifications; structured as an enum so adding future
/// event kinds (connection state, prekey-fetch outcomes, ...) stays
/// non-breaking on the wire.
#[derive(Debug, Clone)]
pub enum GuiEvent {
    /// A DM from `peer` (base58 PeerId) was just decrypted and stored.
    /// Tauri side translates this into a `"dm-received"` event with
    /// `peer` as the payload.
    DmReceived { peer: String },
    /// A group message from `sender` (base58 PeerId) in `group_id`
    /// (lowercase hex) was just decrypted and stored. Tauri side
    /// translates this into a `"group-msg-received"` event — see the
    /// task #7 GUI commit for the forwarder wiring.
    GroupMessageReceived { group_id: String, sender: String },
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

    // ---- Phase 5 group chats, CLI-shaped fire-and-forget ----
    /// Create a new group with `name` and the given members. Founder
    /// (self) is implicitly included if not already in the list.
    /// Prints the new group_id on success.
    GroupCreate(String, Vec<PeerId>),
    /// Print all local groups.
    GroupList,
    /// Send a text message into the named group.
    GroupSend(crate::protocol::GroupId, String),
    /// Founder-issued: add `peer_id` to the group.
    GroupAdd(crate::protocol::GroupId, PeerId),
    /// Founder-issued: remove `peer_id` from the group.
    GroupRemove(crate::protocol::GroupId, PeerId),
    /// Self-issued: leave the group.
    GroupLeave(crate::protocol::GroupId),

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
    /// Phase 5 GUI: return all local groups as GroupDto rows.
    QueryGroups(tokio::sync::oneshot::Sender<Vec<GroupDto>>),
    /// Phase 5 GUI: return the message history for `group_id` (newest last).
    QueryGroupMessages(crate::protocol::GroupId, tokio::sync::oneshot::Sender<Vec<GroupMessageDto>>),
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

/// DTO returned to the GUI by `QueryGroups`. `group_id` is lowercase
/// hex (64 chars), `founder` is the base58 PeerId of the founder, and
/// `is_founder` lets the webview show / hide founder-only controls
/// (add / remove member) without a separate round-trip.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupDto {
    pub group_id: String,
    pub name: String,
    pub founder: String,
    pub epoch: u64,
    pub member_count: usize,
    pub is_founder: bool,
}

/// DTO returned to the GUI by `QueryGroupMessages`. Mirrors `MessageDto`
/// (sender base58, content as a UTF-8-lossy string, timestamp seconds,
/// `is_own` for bubble styling).
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupMessageDto {
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
            recent_otpk_fetches: HashMap::new(),
            gui_tx: None,
        })
    }

    /// Install a push-refresh channel. Call before [`Self::run_with_commands`]
    /// if a Tauri frontend wants `GuiEvent::DmReceived` notifications;
    /// the CLI path leaves this `None`.
    pub fn set_gui_event_sender(&mut self, tx: mpsc::Sender<GuiEvent>) {
        self.gui_tx = Some(tx);
    }

    /// Fire-and-forget event push. `try_send` drops on full/closed —
    /// see the `gui_tx` field comment for why that's intentional.
    fn emit_gui(&self, ev: GuiEvent) {
        if let Some(tx) = &self.gui_tx {
            let _ = tx.try_send(ev);
        }
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
                        // ─────── Phase 5 group-chat handlers ───────
                        Some(NodeCommand::GroupCreate(name, members)) => {
                            self.handle_group_create(&mut swarm, name, members);
                        }
                        Some(NodeCommand::GroupList) => {
                            self.handle_group_list();
                        }
                        Some(NodeCommand::GroupSend(group_id, content)) => {
                            self.group_send(&mut swarm, group_id, &content);
                        }
                        Some(NodeCommand::GroupAdd(group_id, peer_id)) => {
                            self.handle_group_add(&mut swarm, group_id, peer_id);
                        }
                        Some(NodeCommand::GroupRemove(group_id, peer_id)) => {
                            self.handle_group_remove(&mut swarm, group_id, peer_id);
                        }
                        Some(NodeCommand::GroupLeave(group_id)) => {
                            self.handle_group_leave(&mut swarm, group_id);
                        }
                        Some(NodeCommand::QueryGroups(reply)) => {
                            let dtos = self.query_groups();
                            let _ = reply.send(dtos);
                        }
                        Some(NodeCommand::QueryGroupMessages(group_id, reply)) => {
                            let dtos = self.query_group_messages(&group_id);
                            let _ = reply.send(dtos);
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
                    // Phase 5: bound the OTPK-fetch rate-limit map.
                    self.prune_recent_otpk_fetches();
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
                    // Phase 5 OTPK-pool-drain defence: only attach an
                    // OTPK if this peer hasn't fetched one recently. The
                    // signed prekey is ALWAYS sent (it's our public,
                    // long-term, signed key — nothing to drain). The
                    // OTPK is the consumable resource, so it's the one
                    // we gate.
                    let attach_otpk = self.should_attach_otpk(peer);
                    let otpk_bundle = if attach_otpk {
                        self.pop_one_otpk_bundle()
                    } else {
                        debug!(
                            "Skipping OTPK for {}: rate-limited (within {}s cooldown)",
                            peer,
                            Self::OTPK_FETCH_COOLDOWN_SECS
                        );
                        None
                    };
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
        self.ratchet_encrypt_and_wrap_bytes(peer, plaintext.as_bytes(), hello, 0)
    }

    /// Bytes-and-kind variant of [`Self::ratchet_encrypt_and_wrap`].
    /// Group send paths (Phase 5) use this directly so they can stamp
    /// the right `kind` (1 = GroupControl, 2 = GroupMessageEnvelope)
    /// onto the produced `EncryptedPayload`. The legacy text-DM helper
    /// above forwards here with `kind=0`.
    fn ratchet_encrypt_and_wrap_bytes(
        &mut self,
        peer: PeerId,
        plaintext: &[u8],
        hello: Option<FirstMessageHello>,
        kind: u8,
    ) -> Option<(Vec<u8>, i64)> {
        let ad = Self::ratchet_ad(&self.identity.peer_id(), &peer);

        let ratchet_msg = {
            let session = self.sessions.get_mut(&peer)?;
            match session.encrypt(plaintext, &ad) {
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
            kind,
        };

        let payload_bytes = match payload.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to serialize EncryptedPayload: {}", e);
                return None;
            }
        };

        // Phase 5 sealed sender: if we know the recipient's X25519
        // prekey (cached from a previous fetch or current X3DH path)
        // use `new_sealed` so transport-layer observers see only `to`
        // and the encrypted payload — not our own sender PeerId.
        // Falls back to the legacy direct path when the prekey isn't
        // cached (typically only the very first send to a brand-new
        // contact before the prekey-fetch reply has landed).
        let proto_msg_result = if let Some(recipient_prekey) = self.cached_prekey(&peer) {
            ProtocolMessage::new_sealed(
                peer.to_bytes(),
                self.identity.peer_id().to_bytes(),
                payload_bytes,
                self.identity.keypair(),
                recipient_prekey.as_bytes(),
            )
        } else {
            ProtocolMessage::new_direct_signed(
                peer.to_bytes(),
                self.identity.peer_id().to_bytes(),
                payload_bytes,
                self.identity.keypair(),
            )
        };
        let proto_msg = match proto_msg_result {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to build outbound envelope: {}", e);
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
        // Two paths: sealed envelopes need the recipient's X25519
        // prekey private to unseal; direct envelopes verify against
        // the clear `from` field.
        let sealed = proto_msg.is_sealed();
        let verified_sender = if sealed {
            match proto_msg.verify_sealed(self.identity.x25519_secret()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Dropping sealed DM from transport peer {}: {}",
                        transport_peer, e
                    );
                    return false;
                }
            }
        } else {
            match proto_msg.verify() {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "Dropping DM from transport peer {}: signature verification failed ({})",
                        transport_peer, e
                    );
                    return false;
                }
            }
        };

        // Step 3: transport peer must equal the signed sender — for
        // direct envelopes only. Sealed envelopes intentionally
        // decouple the transport peer (a relay / DHT-mailbox provider)
        // from the signed sender; that's the whole point of Phase 5
        // sealed sender. The signature inside the seal authenticates
        // the sender; the transport peer is just a delivery agent.
        if !sealed && verified_sender != transport_peer {
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
            return self.decrypt_and_store(swarm, verified_sender, &payload);
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
                swarm,
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
        swarm: &mut Swarm<Behaviour>,
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
        let decrypted_ok = self.decrypt_first_message(swarm, peer, payload);
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
    fn decrypt_first_message(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        payload: &EncryptedPayload,
    ) -> bool {
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

        self.persist_session(&peer);
        self.dispatch_decrypted_content(swarm, peer, payload.kind, &plaintext);
        true
    }

    /// Returns `true` iff the message was successfully ratchet-
    /// decrypted and stored. Phase 5 mailbox ACK path uses this signal.
    fn decrypt_and_store(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        payload: &EncryptedPayload,
    ) -> bool {
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

        self.persist_session(&peer);
        self.dispatch_decrypted_content(swarm, peer, payload.kind, &plaintext);
        true
    }

    /// Route a successfully ratchet-decrypted plaintext to its
    /// per-`kind` handler. Centralises the post-decrypt logic that
    /// previously lived in two near-identical tail blocks across
    /// `decrypt_first_message` and `decrypt_and_store`.
    ///
    /// kind=0: text DM — auto-add contact, persist plaintext, print,
    ///         emit DmReceived to the GUI.
    /// kind=1: GroupControl — parse JSON, verify signatures, install
    ///         membership / sender-key state.
    /// kind=2: GroupMessageEnvelope — wired in commit 4 of the group
    ///         track; debug-log for now.
    /// other:  warn and drop.
    fn dispatch_decrypted_content(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        kind: u8,
        plaintext: &[u8],
    ) {
        match kind {
            0 => {
                if let Some(ref store) = self.message_store {
                    if let Err(e) = store.add_contact(&peer.to_bytes(), &peer.to_bytes(), None) {
                        warn!("Failed to persist contact: {}", e);
                    }
                    if let Err(e) = store.store_message(
                        &peer.to_bytes(),
                        &self.identity.peer_id().to_bytes(),
                        plaintext,
                        7 * 24 * 3600,
                    ) {
                        warn!("Failed to store plaintext copy: {}", e);
                    }
                }
                let text = String::from_utf8_lossy(plaintext);
                // Plaintext stays at debug; the println! below is the
                // user-facing terminal output (INVARIANTS §19).
                debug!("Decrypted DM from {}: {}", peer, text);
                println!("\n🔓 {}: {}", peer, text);
                println!("> ");
                self.emit_gui(GuiEvent::DmReceived {
                    peer: peer.to_base58(),
                });
            }
            1 => match crate::protocol::GroupControl::from_bytes(plaintext) {
                Ok(ctrl) => self.process_group_control(swarm, peer, ctrl),
                Err(e) => warn!("Malformed GroupControl from {}: {}", peer, e),
            },
            2 => match crate::protocol::GroupMessageEnvelope::from_bytes(plaintext) {
                Ok(env) => self.process_group_message(peer, env),
                Err(e) => warn!("Malformed GroupMessageEnvelope from {}: {}", peer, e),
            },
            unknown => {
                warn!("Unknown EncryptedPayload.kind={} from {}", unknown, peer);
            }
        }
    }

    /// Handle an inbound GroupControl after signature checks. The
    /// outer 1:1 DR channel already authenticates `sender` — we trust
    /// that bind. Inner signatures (founder / leaver) are verified
    /// against the relevant PID's inlined Ed25519 pubkey before any
    /// state mutation.
    fn process_group_control(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        sender: PeerId,
        ctrl: crate::protocol::GroupControl,
    ) {
        use crate::protocol::GroupControl;
        match &ctrl {
            GroupControl::CreateGroup {
                group_id,
                name,
                founder_pid,
                members,
                epoch,
                founder_sig: _,
            } => {
                if let Err(e) = ctrl.verify_signature() {
                    warn!("CreateGroup from {} failed signature: {}", sender, e);
                    return;
                }
                if sender.to_bytes() != *founder_pid {
                    warn!(
                        "CreateGroup from {} doesn't match founder field — rejecting",
                        sender
                    );
                    return;
                }
                let my_pid = self.identity.peer_id().to_bytes();
                if !members.iter().any(|m| m == &my_pid) {
                    debug!(
                        "CreateGroup {} excludes me — ignoring",
                        hex::encode(group_id)
                    );
                    return;
                }
                let Some(ref store) = self.message_store else { return };
                if let Err(e) = store.group_upsert(group_id, name, founder_pid, *epoch) {
                    warn!("group_upsert failed: {}", e);
                    return;
                }
                for m in members {
                    if let Err(e) = store.group_member_add(group_id, m) {
                        warn!("group_member_add failed: {}", e);
                    }
                }
                info!(
                    "Joined group '{}' (id={}, founder={})",
                    name,
                    hex::encode(group_id),
                    sender
                );
            }
            GroupControl::MembershipUpdate {
                group_id,
                added,
                removed,
                epoch,
                founder_sig: _,
            } => {
                // Phase A: pre-flight + apply, all under an immutable
                // self-borrow. We collect what we need to react in
                // Phase B (rotation + onboarding) into owned locals so
                // the store borrow ends before the mutable calls.
                let group_id_local: crate::protocol::GroupId = *group_id;
                let new_epoch: u64 = *epoch;
                let added_local: Vec<Vec<u8>> = added.clone();
                let removed_nonempty = !removed.is_empty();
                {
                    let Some(ref store) = self.message_store else { return };
                    let row = match store.group_get(group_id) {
                        Ok(Some(r)) => r,
                        Ok(None) => {
                            debug!(
                                "MembershipUpdate for unknown group {} — ignoring",
                                hex::encode(group_id)
                            );
                            return;
                        }
                        Err(e) => {
                            warn!("group_get failed: {}", e);
                            return;
                        }
                    };
                    if *epoch <= row.epoch {
                        warn!(
                            "MembershipUpdate epoch {} <= stored {} for group {} — rejecting stale update",
                            epoch,
                            row.epoch,
                            hex::encode(group_id)
                        );
                        return;
                    }
                    if let Err(e) = ctrl.verify_membership_update(&row.founder_pid) {
                        warn!("MembershipUpdate from {} failed signature: {}", sender, e);
                        return;
                    }
                    for m in added {
                        let _ = store.group_member_add(group_id, m);
                    }
                    for m in removed {
                        let _ = store.group_member_remove(group_id, m);
                        let _ = store.their_sender_key_delete(group_id, m);
                    }
                    if let Err(e) = store.group_bump_epoch(group_id, *epoch) {
                        warn!("group_bump_epoch failed: {}", e);
                    }
                    info!(
                        "Applied MembershipUpdate to group {} (epoch -> {}, +{} -{})",
                        hex::encode(group_id),
                        epoch,
                        added.len(),
                        removed.len()
                    );
                }

                // Phase B: forward-secrecy rotation on remove + onboarding
                // distribution on add. Both need &mut self for the
                // swarm-touching deliver_kind_to_member call.
                if removed_nonempty {
                    self.rotate_my_sender_chain_and_broadcast(
                        swarm,
                        &group_id_local,
                        new_epoch,
                    );
                }
                for added_pid_bytes in &added_local {
                    let Ok(added_pid) = PeerId::from_bytes(added_pid_bytes) else {
                        continue;
                    };
                    self.send_my_bundle_to(swarm, &group_id_local, added_pid);
                }
            }
            GroupControl::SenderKeyDistribution {
                group_id,
                bundle,
                epoch: _,
            } => {
                let Some(ref store) = self.message_store else { return };
                let members = match store.group_members(group_id) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("group_members failed: {}", e);
                        return;
                    }
                };
                let sender_bytes = sender.to_bytes();
                if !members.iter().any(|m| m == &sender_bytes) {
                    warn!(
                        "SenderKeyDistribution from {} who isn't a member of group {} — ignoring",
                        sender,
                        hex::encode(group_id)
                    );
                    return;
                }
                let receiver = crate::crypto::megolm::ReceiverChain::from_bundle(bundle);
                let blob = match receiver.to_json() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to serialize ReceiverChain: {}", e);
                        return;
                    }
                };
                if let Err(e) = store.their_sender_key_save(group_id, &sender_bytes, &blob) {
                    warn!("their_sender_key_save failed: {}", e);
                    return;
                }
                info!(
                    "Installed sender-key from {} in group {} at index {}",
                    sender,
                    hex::encode(group_id),
                    bundle.index
                );
            }
            GroupControl::Leave {
                group_id,
                leaver_pid,
                epoch: _,
                leaver_sig: _,
            } => {
                if let Err(e) = ctrl.verify_signature() {
                    warn!("Leave from {} failed signature: {}", sender, e);
                    return;
                }
                let group_id_local: crate::protocol::GroupId = *group_id;
                let rotation_epoch = {
                    let Some(ref store) = self.message_store else { return };
                    let _ = store.group_member_remove(group_id, leaver_pid);
                    let _ = store.their_sender_key_delete(group_id, leaver_pid);
                    info!(
                        "Removed member {} from group {} (Leave)",
                        hex::encode(leaver_pid),
                        hex::encode(group_id)
                    );
                    store
                        .group_get(group_id)
                        .ok()
                        .flatten()
                        .map(|r| r.epoch)
                        .unwrap_or(0)
                };
                // Forward-secrecy: rotate my chain so the leaver's
                // cached copy of my chain key can't decrypt anything
                // we send post-Leave. Reuses the existing epoch (no
                // bump — Leave isn't a founder-issued state change).
                self.rotate_my_sender_chain_and_broadcast(
                    swarm,
                    &group_id_local,
                    rotation_epoch,
                );
            }
        }
    }

    // ─────────────────── Phase 5 group send / receive ───────────────────

    /// User-facing group send entry point. Loads (or creates) my
    /// per-group Megolm SenderChain, encrypts the plaintext once,
    /// fans out the resulting `GroupMessageEnvelope` as N-1 unicasts
    /// via the existing 1:1 Double Ratchet channel.
    ///
    /// When the chain is freshly created (first send to this group),
    /// a `SenderKeyDistribution` control message is broadcast to
    /// every other member FIRST so they can install our chain at
    /// index 0 — without that they'd be unable to decrypt the first
    /// message. Members without an active DR session at the moment
    /// of the call are skipped with a warn (membership-rotation
    /// flows in task #6 cover the new-member prekey-fetch dance).
    pub fn group_send(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: crate::protocol::GroupId,
        plaintext: &str,
    ) {
        // Read-only borrows of the store happen in short scopes so the
        // subsequent `&mut self` calls (ratchet encrypt, send_request)
        // don't conflict with them.
        let group_row = {
            let Some(store) = self.message_store.as_ref() else {
                error!("group_send: no message store");
                return;
            };
            match store.group_get(&group_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    warn!("group_send: unknown group {}", hex::encode(group_id));
                    return;
                }
                Err(e) => {
                    warn!("group_send: group_get failed: {}", e);
                    return;
                }
            }
        };
        let members = {
            let Some(store) = self.message_store.as_ref() else { return };
            match store.group_members(&group_id) {
                Ok(m) => m,
                Err(e) => {
                    warn!("group_send: group_members failed: {}", e);
                    return;
                }
            }
        };

        // Load or create my SenderChain for this group.
        let (mut my_chain, fresh) = {
            let Some(store) = self.message_store.as_ref() else { return };
            match store.my_sender_key_load(&group_id) {
                Ok(Some(blob)) => match crate::crypto::megolm::SenderChain::from_json(&blob) {
                    Ok(c) => (c, false),
                    Err(e) => {
                        warn!("group_send: SenderChain deser failed: {}", e);
                        return;
                    }
                },
                Ok(None) => (crate::crypto::megolm::SenderChain::new(), true),
                Err(e) => {
                    warn!("group_send: my_sender_key_load failed: {}", e);
                    return;
                }
            }
        };

        let my_pid_bytes = self.identity.peer_id().to_bytes();

        // First send to this group: distribute my chain bundle to every
        // other member before the first message. Recipients without an
        // active session at this moment are skipped — the chain still
        // advances on our end and they'll catch up after their session
        // bootstraps, but they'll see MessageKeyMissing for any messages
        // we sent before they installed the bundle (chain-install
        // forward secrecy is the design).
        if fresh {
            let bundle = my_chain.current_bundle();
            let ctrl = crate::protocol::GroupControl::new_sender_key_distribution(
                group_id,
                bundle,
                group_row.epoch,
            );
            let ctrl_bytes = match ctrl.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    warn!("group_send: GroupControl serialize failed: {}", e);
                    return;
                }
            };
            for member_bytes in &members {
                if member_bytes == &my_pid_bytes {
                    continue;
                }
                let member_pid = match PeerId::from_bytes(member_bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("group_send: bad member PID: {}", e);
                        continue;
                    }
                };
                self.deliver_kind_to_member(swarm, member_pid, 1, &ctrl_bytes);
            }
        }

        // Megolm-encrypt the user plaintext.
        let group_ad = crate::protocol::build_group_ad(&group_id, &my_pid_bytes);
        let encrypted_msg = my_chain.encrypt(plaintext.as_bytes(), &group_ad);

        // Persist advanced chain state + local plaintext copy.
        if let Some(store) = self.message_store.as_ref() {
            if let Ok(blob) = my_chain.to_json() {
                if let Err(e) = store.my_sender_key_save(&group_id, &blob) {
                    warn!("group_send: my_sender_key_save failed: {}", e);
                }
            }
            let _ = store.group_message_store(
                &group_id,
                &my_pid_bytes,
                plaintext.as_bytes(),
                7 * 24 * 3600,
            );
        }

        // Wrap as kind=2 envelope and fan out.
        let envelope = crate::protocol::GroupMessageEnvelope {
            group_id,
            msg: encrypted_msg,
        };
        let envelope_bytes = match envelope.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                warn!("group_send: envelope serialize failed: {}", e);
                return;
            }
        };

        let mut delivered = 0usize;
        let mut targeted = 0usize;
        for member_bytes in &members {
            if member_bytes == &my_pid_bytes {
                continue;
            }
            targeted += 1;
            let member_pid = match PeerId::from_bytes(member_bytes) {
                Ok(p) => p,
                Err(e) => {
                    warn!("group_send: bad member PID: {}", e);
                    continue;
                }
            };
            if self.deliver_kind_to_member(swarm, member_pid, 2, &envelope_bytes) {
                delivered += 1;
            }
        }
        info!(
            "Group send to {}: {}/{} member(s) reached",
            hex::encode(group_id),
            delivered,
            targeted
        );
        println!(
            "📨 Group message sent to {}/{} member(s) of {}",
            delivered,
            targeted,
            hex::encode(group_id)
        );
    }

    /// Encrypt `body` with the 1:1 DR session to `peer` and send it as
    /// a request-response message tagged with `kind`. Used by group
    /// fan-out (kind=2 messages and kind=1 control distribution).
    ///
    /// Returns `true` on a successful send (queued onto the libp2p
    /// outbound queue), `false` if no session exists yet or encrypt
    /// failed. Group ops drop on `false` rather than mailbox-queueing
    /// to keep this commit small — task #6 will wire mailbox + outbox
    /// fallbacks for control-message delivery.
    fn deliver_kind_to_member(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        peer: PeerId,
        kind: u8,
        body: &[u8],
    ) -> bool {
        // Require an established session. Group ops in v0 expect a
        // live (or persisted-and-restored) DR session with every
        // member; the CLI surfaces a warning to the user if any are
        // missing, and task #6 wires the prekey-fetch onboarding for
        // new members.
        let have_session = self.sessions.contains_key(&peer)
            || self.restore_session_if_persisted(&peer);
        if !have_session {
            warn!(
                "deliver_kind: no session with {} (kind={}); group payload dropped",
                peer, kind
            );
            return false;
        }
        let Some((wire_bytes, _ttl)) =
            self.ratchet_encrypt_and_wrap_bytes(peer, body, None, kind)
        else {
            return false;
        };
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, DirectMessageRequest(wire_bytes));
        self.persist_session(&peer);
        true
    }

    /// Handle an inbound `GroupMessageEnvelope` after the outer 1:1 DR
    /// has decrypted it (kind=2). Sender is the DR-verified peer
    /// identity — we trust that bind. Verifies sender is a member of
    /// the group, loads the cached `ReceiverChain` for their sender
    /// chain, decrypts the Megolm payload (which itself verifies the
    /// per-message Ed25519 signature), persists the advanced chain
    /// state + plaintext copy, prints + emits GUI event.
    fn process_group_message(
        &mut self,
        sender: PeerId,
        env: crate::protocol::GroupMessageEnvelope,
    ) {
        let Some(store) = self.message_store.as_ref() else { return };
        let sender_bytes = sender.to_bytes();

        // Membership cross-check: non-members can't send into the group.
        let members = match store.group_members(&env.group_id) {
            Ok(m) => m,
            Err(e) => {
                warn!("process_group_message: group_members: {}", e);
                return;
            }
        };
        if !members.iter().any(|m| m == &sender_bytes) {
            warn!(
                "Group message from non-member {} in group {} — dropping",
                sender,
                hex::encode(env.group_id)
            );
            return;
        }

        // Load sender's ReceiverChain. If absent, we haven't been told
        // their bundle yet — this happens when a message races ahead of
        // its SenderKeyDistribution. Drop with warn; sender will retry
        // (in v0, sender's perspective is "send succeeded" but
        // recipient saw chain-not-installed).
        let blob = match store.their_sender_key_load(&env.group_id, &sender_bytes) {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(
                    "No sender-key for {} in group {} — dropping (their distribution hasn't arrived?)",
                    sender,
                    hex::encode(env.group_id)
                );
                return;
            }
            Err(e) => {
                warn!("their_sender_key_load: {}", e);
                return;
            }
        };
        let mut receiver = match crate::crypto::megolm::ReceiverChain::from_json(&blob) {
            Ok(r) => r,
            Err(e) => {
                warn!("ReceiverChain deserialize: {}", e);
                return;
            }
        };

        let ad = crate::protocol::build_group_ad(&env.group_id, &sender_bytes);
        let plaintext = match receiver.decrypt(&env.msg, &ad) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    "Megolm decrypt failed from {} in group {}: {}",
                    sender,
                    hex::encode(env.group_id),
                    e
                );
                return;
            }
        };

        // Persist advanced chain + plaintext copy.
        if let Ok(blob) = receiver.to_json() {
            if let Err(e) = store.their_sender_key_save(&env.group_id, &sender_bytes, &blob) {
                warn!("their_sender_key_save failed: {}", e);
            }
        }
        let _ = store.group_message_store(
            &env.group_id,
            &sender_bytes,
            &plaintext,
            7 * 24 * 3600,
        );

        let text = String::from_utf8_lossy(&plaintext);
        debug!(
            "Decrypted group msg from {} in {}: {}",
            sender,
            hex::encode(env.group_id),
            text
        );
        // Print a short group-id prefix to disambiguate concurrent groups
        // in the CLI terminal. The full hex hits debug-level only.
        println!(
            "\n👥 [{}] {}: {}",
            hex::encode(&env.group_id[..4]),
            sender,
            text
        );
        println!("> ");
        self.emit_gui(GuiEvent::GroupMessageReceived {
            group_id: hex::encode(env.group_id),
            sender: sender.to_base58(),
        });
    }

    // ───────────────────── Phase 5 group CLI handlers ─────────────────────

    /// Founder-side group creation. Generates a random 32-byte
    /// `group_id`, builds a signed `CreateGroup` control message,
    /// installs the group locally, then broadcasts the control
    /// message to each (non-self) member via the existing 1:1 DR
    /// channel.
    ///
    /// Self is implicitly included in the member list if the caller
    /// didn't already put us there. The first `group send` after
    /// create will trigger `SenderKeyDistribution` for our chain
    /// (task #4 wired that already).
    fn handle_group_create(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        name: String,
        mut members: Vec<PeerId>,
    ) {
        let my_pid = self.identity.peer_id();
        if !members.contains(&my_pid) {
            members.insert(0, my_pid);
        }

        // Random 32-byte group id. OsRng matches the convention used
        // elsewhere (otpk gen, x25519 ephemeral gen). The id is
        // unlinkable (no founder bits leaked into the bytes).
        let mut group_id = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut group_id);

        let founder_pid_bytes = my_pid.to_bytes();
        let member_bytes: Vec<Vec<u8>> =
            members.iter().map(|p| p.to_bytes()).collect();

        let ctrl = match crate::protocol::GroupControl::new_create_group(
            group_id,
            name.clone(),
            founder_pid_bytes.clone(),
            member_bytes.clone(),
            0,
            self.identity.keypair(),
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Group create: signature failed: {}", e);
                return;
            }
        };
        let ctrl_bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("❌ Group create: serialize failed: {}", e);
                return;
            }
        };

        // Install locally before broadcast so a partial fan-out
        // doesn't leave the founder without their own row.
        let Some(store) = self.message_store.as_ref() else {
            println!("❌ Group create: no message store");
            return;
        };
        if let Err(e) = store.group_upsert(&group_id, &name, &founder_pid_bytes, 0) {
            println!("❌ Group create: group_upsert failed: {}", e);
            return;
        }
        for m in &member_bytes {
            let _ = store.group_member_add(&group_id, m);
        }

        let mut delivered = 0usize;
        let mut targeted = 0usize;
        for peer in &members {
            if *peer == my_pid {
                continue;
            }
            targeted += 1;
            if self.deliver_kind_to_member(swarm, *peer, 1, &ctrl_bytes) {
                delivered += 1;
            }
        }

        println!(
            "✅ Created group '{}' id={}",
            name,
            hex::encode(group_id)
        );
        println!(
            "   Broadcast CreateGroup to {}/{} member(s) — your sender-key bundle is distributed on first `group send`",
            delivered, targeted
        );
    }

    /// Print all local groups with member counts.
    fn handle_group_list(&self) {
        let Some(store) = self.message_store.as_ref() else {
            println!("Group store not available");
            return;
        };
        let rows = match store.group_list() {
            Ok(r) => r,
            Err(e) => {
                println!("Error loading groups: {}", e);
                return;
            }
        };
        if rows.is_empty() {
            println!("\nGroups: (none)");
            return;
        }
        println!("\nGroups:");
        println!("─────────────────────────────────────");
        for row in rows {
            let members = store.group_members(&row.group_id).unwrap_or_default();
            let founder = PeerId::from_bytes(&row.founder_pid)
                .map(|p| p.to_string())
                .unwrap_or_else(|_| "?".to_string());
            println!(
                "  {} '{}' epoch={} members={} founder={}",
                hex::encode(row.group_id),
                row.name,
                row.epoch,
                members.len(),
                founder,
            );
        }
        println!("─────────────────────────────────────");
    }

    /// GUI-shaped read: return every local group as a `GroupDto`.
    /// `is_founder` is set when the row's founder_pid matches our
    /// own PeerId so the webview can hide founder-only controls
    /// without an extra round-trip.
    fn query_groups(&self) -> Vec<GroupDto> {
        let Some(store) = self.message_store.as_ref() else {
            return Vec::new();
        };
        let rows = match store.group_list() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        rows.into_iter()
            .map(|r| {
                let founder_pid = PeerId::from_bytes(&r.founder_pid)
                    .map(|p| p.to_base58())
                    .unwrap_or_else(|_| "?".to_string());
                let member_count = store.group_members(&r.group_id).map(|v| v.len()).unwrap_or(0);
                GroupDto {
                    group_id: hex::encode(r.group_id),
                    name: r.name,
                    founder: founder_pid,
                    epoch: r.epoch,
                    member_count,
                    is_founder: r.founder_pid == my_pid_bytes,
                }
            })
            .collect()
    }

    /// GUI-shaped read: return the local message history for `group_id`.
    fn query_group_messages(&self, group_id: &crate::protocol::GroupId) -> Vec<GroupMessageDto> {
        let Some(store) = self.message_store.as_ref() else {
            return Vec::new();
        };
        let me_bytes = self.identity.peer_id().to_bytes();
        match store.group_messages_get(group_id) {
            Ok(rows) => rows
                .into_iter()
                .map(|m| {
                    let is_own = m.sender == me_bytes;
                    let sender = PeerId::from_bytes(&m.sender)
                        .map(|p| p.to_base58())
                        .unwrap_or_else(|_| "?".to_string());
                    GroupMessageDto {
                        sender,
                        content: String::from_utf8_lossy(&m.plaintext).into_owned(),
                        timestamp: m.timestamp,
                        is_own,
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Founder-side member add. Bumps the local epoch, builds a
    /// signed `MembershipUpdate`, applies it locally, and broadcasts
    /// to every group member (including the newly-added one — they
    /// need the update to know they're now a member). Sender-key
    /// distribution to/from the new joiner is wired in task #6.
    fn handle_group_add(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: crate::protocol::GroupId,
        new_member: PeerId,
    ) {
        let row = {
            let Some(store) = self.message_store.as_ref() else {
                println!("❌ no message store");
                return;
            };
            match store.group_get(&group_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    println!("❌ unknown group {}", hex::encode(group_id));
                    return;
                }
                Err(e) => {
                    println!("❌ group_get: {}", e);
                    return;
                }
            }
        };

        let my_pid_bytes = self.identity.peer_id().to_bytes();
        if row.founder_pid != my_pid_bytes {
            println!("❌ group add: only the founder can add members");
            return;
        }

        let new_epoch = row.epoch + 1;
        let new_member_bytes = new_member.to_bytes();

        let ctrl = match crate::protocol::GroupControl::new_membership_update(
            group_id,
            vec![new_member_bytes.clone()],
            vec![],
            new_epoch,
            self.identity.keypair(),
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ MembershipUpdate sign failed: {}", e);
                return;
            }
        };
        let ctrl_bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("❌ MembershipUpdate serialize failed: {}", e);
                return;
            }
        };

        // Apply locally first.
        let Some(store) = self.message_store.as_ref() else { return };
        let _ = store.group_member_add(&group_id, &new_member_bytes);
        let _ = store.group_bump_epoch(&group_id, new_epoch);

        // Broadcast to the FULL new member set (existing + newly added).
        let current_members = store.group_members(&group_id).unwrap_or_default();
        let mut delivered = 0usize;
        let mut targeted = 0usize;
        for m_bytes in &current_members {
            if m_bytes == &my_pid_bytes {
                continue;
            }
            targeted += 1;
            let member_pid = match PeerId::from_bytes(m_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if self.deliver_kind_to_member(swarm, member_pid, 1, &ctrl_bytes) {
                delivered += 1;
            }
        }

        // Onboarding: if I (the founder) already have a SenderChain
        // for this group, send my current bundle to the new joiner
        // straight away so they can decrypt my next message without
        // waiting for my next `group send` to trigger fresh-chain
        // distribution. Other current members react symmetrically on
        // receiving the MembershipUpdate (see process_group_control).
        self.send_my_bundle_to(swarm, &group_id, new_member);

        println!(
            "✅ Added {} to group {} (epoch {} → {}); broadcast to {}/{} member(s)",
            new_member,
            hex::encode(group_id),
            row.epoch,
            new_epoch,
            delivered,
            targeted,
        );
    }

    /// Founder-side member remove. Mirrors `handle_group_add` but
    /// deletes the removed member from local state and drops their
    /// cached sender-chain. Sender-chain rotation on our own end
    /// (to deny the removed member future plaintext) is task #6.
    fn handle_group_remove(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: crate::protocol::GroupId,
        gone: PeerId,
    ) {
        let row = {
            let Some(store) = self.message_store.as_ref() else {
                println!("❌ no message store");
                return;
            };
            match store.group_get(&group_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    println!("❌ unknown group {}", hex::encode(group_id));
                    return;
                }
                Err(e) => {
                    println!("❌ group_get: {}", e);
                    return;
                }
            }
        };
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        if row.founder_pid != my_pid_bytes {
            println!("❌ group remove: only the founder can remove members");
            return;
        }

        let new_epoch = row.epoch + 1;
        let gone_bytes = gone.to_bytes();

        let ctrl = match crate::protocol::GroupControl::new_membership_update(
            group_id,
            vec![],
            vec![gone_bytes.clone()],
            new_epoch,
            self.identity.keypair(),
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ MembershipUpdate sign failed: {}", e);
                return;
            }
        };
        let ctrl_bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("❌ MembershipUpdate serialize failed: {}", e);
                return;
            }
        };

        // Apply locally first.
        let Some(store) = self.message_store.as_ref() else { return };
        let _ = store.group_member_remove(&group_id, &gone_bytes);
        let _ = store.their_sender_key_delete(&group_id, &gone_bytes);
        let _ = store.group_bump_epoch(&group_id, new_epoch);

        // Broadcast to remaining members only. We deliberately do
        // NOT send the update to the removed peer — they'll learn
        // they're out from the absence of subsequent messages.
        let remaining = store.group_members(&group_id).unwrap_or_default();
        let mut delivered = 0usize;
        let mut targeted = 0usize;
        for m_bytes in &remaining {
            if m_bytes == &my_pid_bytes || m_bytes == &gone_bytes {
                continue;
            }
            targeted += 1;
            let member_pid = match PeerId::from_bytes(m_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if self.deliver_kind_to_member(swarm, member_pid, 1, &ctrl_bytes) {
                delivered += 1;
            }
        }

        // Forward-secrecy step: rotate MY sender chain so the removed
        // peer's cached chain key is dead-on-arrival for any future
        // message of mine. Remaining members rotate themselves in
        // response to the MembershipUpdate (see process_group_control).
        self.rotate_my_sender_chain_and_broadcast(swarm, &group_id, new_epoch);

        println!(
            "✅ Removed {} from group {} (epoch {} → {}); broadcast to {}/{} remaining member(s); rotated my chain",
            gone,
            hex::encode(group_id),
            row.epoch,
            new_epoch,
            delivered,
            targeted,
        );
    }

    /// Self-issued leave. Builds a `Leave` control message signed by
    /// our identity, broadcasts to every other member, then drops the
    /// group from local state.
    fn handle_group_leave(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: crate::protocol::GroupId,
    ) {
        // Phase A: collect the snapshot we need under an immutable
        // self-borrow, then drop it before any &mut self calls.
        let (row_epoch, members) = {
            let Some(store) = self.message_store.as_ref() else { return };
            let row = match store.group_get(&group_id) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    println!("❌ unknown group {}", hex::encode(group_id));
                    return;
                }
                Err(e) => {
                    println!("❌ group_get: {}", e);
                    return;
                }
            };
            let members = store.group_members(&group_id).unwrap_or_default();
            (row.epoch, members)
        };

        let my_pid_bytes = self.identity.peer_id().to_bytes();
        let ctrl = match crate::protocol::GroupControl::new_leave(
            group_id,
            my_pid_bytes.clone(),
            row_epoch,
            self.identity.keypair(),
        ) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Leave sign failed: {}", e);
                return;
            }
        };
        let ctrl_bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                println!("❌ Leave serialize failed: {}", e);
                return;
            }
        };

        // Phase B: mutable fan-out.
        let mut delivered = 0usize;
        let mut targeted = 0usize;
        for m_bytes in &members {
            if m_bytes == &my_pid_bytes {
                continue;
            }
            targeted += 1;
            let member_pid = match PeerId::from_bytes(m_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if self.deliver_kind_to_member(swarm, member_pid, 1, &ctrl_bytes) {
                delivered += 1;
            }
        }

        // Phase C: drop the group locally. Group-message history rows
        // survive (group_forget keeps the history table for audit).
        if let Some(store) = self.message_store.as_ref() {
            if let Err(e) = store.group_forget(&group_id) {
                println!("⚠ group_forget failed: {}", e);
            }
        }

        println!(
            "✅ Left group {}; Leave broadcast to {}/{} member(s)",
            hex::encode(group_id),
            delivered,
            targeted,
        );
    }

    // ────────────────── Phase 5 membership rotation (task #6) ──────────────────

    /// Rotate my SenderChain for `group_id`: drop the old chain,
    /// generate a fresh one, overwrite the stored `my_sender_keys`
    /// row, and broadcast the new bundle as a kind=1
    /// `SenderKeyDistribution` to every other member. Called on
    /// remove / leave events so the removed-or-departed peer can no
    /// longer decrypt our future messages even if they cached the
    /// old chain key.
    ///
    /// `new_epoch` is stamped onto the SenderKeyDistribution.epoch
    /// field so recipients can spot a distribution that pre-dates a
    /// MembershipUpdate they haven't seen yet.
    ///
    /// Members without an active 1:1 DR session are skipped with a
    /// warn — same v0 limitation as the rest of group fan-out.
    fn rotate_my_sender_chain_and_broadcast(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: &crate::protocol::GroupId,
        new_epoch: u64,
    ) {
        let new_chain = crate::crypto::megolm::SenderChain::new();
        let bundle = new_chain.current_bundle();
        let blob = match new_chain.to_json() {
            Ok(b) => b,
            Err(e) => {
                warn!("rotate: SenderChain serialize failed: {}", e);
                return;
            }
        };

        // Phase A: write under a short immutable self.message_store borrow.
        let members = {
            let Some(store) = self.message_store.as_ref() else { return };
            if let Err(e) = store.my_sender_key_save(group_id, &blob) {
                warn!("rotate: my_sender_key_save failed: {}", e);
                return;
            }
            store.group_members(group_id).unwrap_or_default()
        };

        let ctrl = crate::protocol::GroupControl::new_sender_key_distribution(
            *group_id, bundle, new_epoch,
        );
        let ctrl_bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                warn!("rotate: SenderKeyDistribution serialize failed: {}", e);
                return;
            }
        };

        // Phase B: mutable fan-out.
        let my_pid_bytes = self.identity.peer_id().to_bytes();
        let mut delivered = 0usize;
        for m_bytes in &members {
            if m_bytes == &my_pid_bytes {
                continue;
            }
            let member_pid = match PeerId::from_bytes(m_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if self.deliver_kind_to_member(swarm, member_pid, 1, &ctrl_bytes) {
                delivered += 1;
            }
        }
        info!(
            "Rotated sender-chain for group {} at epoch {}; redistributed bundle to {} member(s)",
            hex::encode(group_id),
            new_epoch,
            delivered
        );
    }

    /// Send my CURRENT (non-rotated) SenderChain bundle for
    /// `group_id` to `peer` as kind=1 SenderKeyDistribution. Used on
    /// member-add: existing members onboard the new joiner by
    /// forwarding their current bundle. No-op if I don't have a
    /// chain for the group yet — the new joiner will pick it up
    /// from the freshman bundle distribution on my next `group_send`.
    fn send_my_bundle_to(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        group_id: &crate::protocol::GroupId,
        peer: PeerId,
    ) -> bool {
        let (bundle, epoch) = {
            let Some(store) = self.message_store.as_ref() else { return false };
            let row = match store.group_get(group_id) {
                Ok(Some(r)) => r,
                _ => return false,
            };
            let blob = match store.my_sender_key_load(group_id) {
                Ok(Some(b)) => b,
                _ => return false,
            };
            let chain = match crate::crypto::megolm::SenderChain::from_json(&blob) {
                Ok(c) => c,
                Err(_) => return false,
            };
            (chain.current_bundle(), row.epoch)
        };
        let ctrl = crate::protocol::GroupControl::new_sender_key_distribution(
            *group_id, bundle, epoch,
        );
        let bytes = match ctrl.to_bytes() {
            Ok(b) => b,
            Err(_) => return false,
        };
        self.deliver_kind_to_member(swarm, peer, 1, &bytes)
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
                    self.decrypt_and_store(swarm, peer, &payload);
                } else if let Some(eph_bytes) = payload.x3dh_eph {
                    self.bootstrap_responder_and_decrypt(swarm, peer, eph_bytes, prekey_pub, &payload);
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
    /// whenever it gets depleted. Bumped to 100 in Phase 5 for higher
    /// raw cost-to-drain — combined with [`Self::OTPK_FETCH_COOLDOWN_SECS`]
    /// per-peer rate limiting, an attacker controlling N Sybil
    /// identities still needs `100 / (1 + uptime_seconds / cooldown)`
    /// distinct identities active simultaneously to keep the pool
    /// depleted, which scales linearly with attacker resources.
    const OTPK_POOL_TARGET: i64 = 100;

    /// Phase 5 OTPK-pool-drain defence: minimum gap between two
    /// honored OTPK-attached PrekeyResponses to the same remote peer.
    /// Within this window, repeat PrekeyRequests from the same peer
    /// still get a valid signed-prekey response, but without an OTPK
    /// attached — forcing rapid-fire fetchers to fall back to 2-DH
    /// X3DH on their subsequent attempts.
    ///
    /// 60 seconds is a deliberately loose window: legitimate retry
    /// scenarios (network glitch, peer briefly disconnected mid-
    /// handshake) typically resolve in much less than that, so the
    /// only callers that hit the gate are scripts or attackers.
    /// A motivated attacker who can Sybil their PeerId can bypass
    /// the per-peer limit, which is why we ALSO bumped
    /// `OTPK_POOL_TARGET` to 100 — raising the per-identity throw-
    /// away cost.
    const OTPK_FETCH_COOLDOWN_SECS: i64 = 60;

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

    /// Phase 5 OTPK-pool-drain defence. Returns `true` iff we should
    /// attach a one-time prekey to a `PrekeyResponse` for `peer` right
    /// now. The signed prekey is always sent regardless; only the OTPK
    /// is gated.
    ///
    /// Updates `recent_otpk_fetches[peer]` to the current timestamp on
    /// an honored attempt, so the next request from the same peer is
    /// rate-limited until `OTPK_FETCH_COOLDOWN_SECS` has elapsed.
    fn should_attach_otpk(&mut self, peer: PeerId) -> bool {
        check_and_update_otpk_gate(
            &mut self.recent_otpk_fetches,
            peer,
            unix_seconds_now(),
            Self::OTPK_FETCH_COOLDOWN_SECS,
        )
    }

    /// Periodic prune of the OTPK-fetch tracking map. Drops entries
    /// older than `OTPK_FETCH_COOLDOWN_SECS` since they no longer
    /// affect the gate. Called from the hourly cleanup tick so the
    /// map can't grow unboundedly under a high-churn workload.
    fn prune_recent_otpk_fetches(&mut self) {
        let now = unix_seconds_now();
        let cutoff = now - Self::OTPK_FETCH_COOLDOWN_SECS;
        self.recent_otpk_fetches.retain(|_, last| *last >= cutoff);
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

/// Phase 5 pure helper for the OTPK rate-limit gate. Factored out of
/// `P2PNode::should_attach_otpk` so the cooldown logic is testable
/// without spinning up a full P2PNode.
///
/// Returns `true` iff `peer` should be honored with an OTPK attached
/// right now. On `true`, the map is updated with `now` so the next
/// call within `cooldown_secs` returns `false`.
fn check_and_update_otpk_gate(
    recent: &mut HashMap<PeerId, i64>,
    peer: PeerId,
    now: i64,
    cooldown_secs: i64,
) -> bool {
    let allow = match recent.get(&peer) {
        Some(&last) if now - last < cooldown_secs => false,
        _ => true,
    };
    if allow {
        recent.insert(peer, now);
    }
    allow
}

#[cfg(test)]
mod otpk_gate_tests {
    use super::*;

    fn fresh_peer() -> PeerId {
        // Generate a unique PeerId from a random Ed25519 keypair —
        // each test gets distinct identities for free.
        let kp = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(kp.public())
    }

    #[test]
    fn first_call_allows_and_records() {
        let mut recent = HashMap::new();
        let p = fresh_peer();
        assert!(check_and_update_otpk_gate(&mut recent, p, 1_000, 60));
        assert_eq!(recent.get(&p), Some(&1_000));
    }

    #[test]
    fn repeat_within_cooldown_is_blocked() {
        let mut recent = HashMap::new();
        let p = fresh_peer();
        assert!(check_and_update_otpk_gate(&mut recent, p, 1_000, 60));
        // Same peer at +30s → still within 60s cooldown → blocked.
        assert!(!check_and_update_otpk_gate(&mut recent, p, 1_030, 60));
        // Map timestamp not updated on blocked attempt — the original
        // "last honored" timestamp stands.
        assert_eq!(recent.get(&p), Some(&1_000));
    }

    #[test]
    fn repeat_past_cooldown_is_allowed() {
        let mut recent = HashMap::new();
        let p = fresh_peer();
        assert!(check_and_update_otpk_gate(&mut recent, p, 1_000, 60));
        // Same peer at +60s → boundary is exclusive; allowed.
        assert!(check_and_update_otpk_gate(&mut recent, p, 1_060, 60));
        assert_eq!(recent.get(&p), Some(&1_060));
    }

    #[test]
    fn distinct_peers_do_not_share_the_cooldown() {
        let mut recent = HashMap::new();
        let p1 = fresh_peer();
        let p2 = fresh_peer();
        assert!(check_and_update_otpk_gate(&mut recent, p1, 1_000, 60));
        // Different peer is independent.
        assert!(check_and_update_otpk_gate(&mut recent, p2, 1_001, 60));
        assert_eq!(recent.get(&p1), Some(&1_000));
        assert_eq!(recent.get(&p2), Some(&1_001));
    }
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

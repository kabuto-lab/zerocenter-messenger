//! Shared startup body for the `ME55` and `ME55AGUI` binaries.
//!
//! Both binaries share this code path so the GUI-default exe and the
//! CLI-default exe behave identically apart from their Windows
//! subsystem (CONSOLE for ME55.exe, WINDOWS for ME55AGUI.exe so it
//! doesn't spawn an extra console window on launch).
//!
//! The split exists because `#![windows_subsystem]` is a crate-level
//! attribute and can't be conditionally applied per `[[bin]]` target
//! when both bins point at the same source file.

use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{info, error};
use crate::core::{Config, GuiEvent, Identity, P2PNode, NodeCommand};
use crate::cli::Cli;
use crate::crypto::keyring as me55_keyring;
use libp2p::{PeerId, Multiaddr};

/// Full body of the `main()` for both ME55 and ME55AGUI binaries.
///
/// The caller is responsible for running this inside a Tokio runtime
/// (typically via `#[tokio::main]` on the binary's `main` fn).
pub async fn run() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // GUI is the default surface; `--cli` forces the headless REPL,
    // `--daemon` skips both REPL and GUI (the swarm runs in a spawned
    // task and main blocks forever). On a binary built without the
    // `gui` feature there is no webview to launch, so fall back to
    // the REPL unless `--gui` was explicitly passed.
    let use_gui = !cli.cli && !cli.daemon && (cfg!(feature = "gui") || cli.gui);

    // Get profile directory
    let profile_dir = get_profile_dir(&cli.profile)?;

    info!("Starting ME55 Messenger");
    info!("Profile: {}", cli.profile);
    info!("Data directory: {:?}", profile_dir);

    // Load or create identity
    let identity = Identity::load_or_create(&profile_dir)?;
    let peer_id = identity.peer_id();

    // Look up (or generate) the at-rest data-encryption key in the OS
    // keyring. Falls back to an ephemeral DEK with a loud warning if the
    // keyring is unreachable — see `keyring::load_or_create_dek` docs.
    let dek = me55_keyring::load_or_create_dek(&cli.profile)?;

    // Parse the optional obfuscation key. Stored on Config for the
    // future transport wrapper; for now it's a no-op on the wire and
    // we warn loudly so nobody assumes traffic is obfuscated yet.
    let obfs_key = match cli.obfs_key.as_deref() {
        Some(s) => match crate::network::scramble::parse_obfs_key(s) {
            Ok(k) => {
                info!(
                    "--obfs-key supplied (32 bytes); both peers must share this key for the wire format to negotiate."
                );
                Some(k)
            }
            Err(e) => {
                anyhow::bail!("--obfs-key invalid: {}", e);
            }
        },
        None => None,
    };

    info!("Peer ID: {}", peer_id);
    // Console banner — meaningful only for the CLI surface (the GUI
    // build has no console window to print into). Gate it on
    // `!use_gui` so we don't waste cycles formatting strings nobody
    // will ever see.
    if !use_gui {
        println!("\n📡 ME55 Messenger");
        println!("══════════════════════════════════════");
        println!("Profile: {}", cli.profile);
        println!("Peer ID: {}", peer_id);
        println!("\nType 'help' for commands, 'quit' to exit.\n");
    }

    // Surface jitter intent to the operator. The flag has no effect
    // without `--obfs-key`; we warn rather than error so users testing
    // baseline-vs-obfs behaviour can keep the flag in their command
    // history.
    if let Some(j) = cli.obfs_jitter_ms {
        if obfs_key.is_some() {
            info!(
                "--obfs-jitter-ms = {} ms: per-frame uniform jitter active",
                j
            );
        } else {
            tracing::warn!(
                "--obfs-jitter-ms = {} given without --obfs-key; jitter is ignored (no scramble layer to gate).",
                j
            );
        }
    }

    // Create configuration
    let config = Config {
        profile: cli.profile.clone(),
        data_dir: profile_dir,
        listen_port: cli.port,
        bootstrap_nodes: cli.bootstrap.clone(),
        obfs_key,
        obfs_jitter_ms: cli.obfs_jitter_ms,
        relay_addrs: cli.relay.clone(),
        enable_relay_server: cli.relay_server,
        use_default_bootstraps: !cli.no_default_bootstrap,
        deniable_dm: cli.deniable_dm,
    };

    // Initialize P2P node
    let mut node = P2PNode::new(config, identity, dek).await?;

    // GUI push-refresh channel — only wired when the GUI surface runs.
    // CLI path leaves the sender None so `emit_gui` becomes a no-op.
    let gui_event_rx = if use_gui {
        let (tx, rx) = mpsc::channel::<GuiEvent>(32);
        node.set_gui_event_sender(tx);
        Some(rx)
    } else {
        None
    };

    // Start listening
    node.start().await?;

    // Create channel for CLI commands
    let (cmd_tx, cmd_rx) = mpsc::channel::<NodeCommand>(32);

    // Clone for CLI handlers — each handler closure moves its own Sender.
    let cmd_tx_for_connect = cmd_tx.clone();
    let cmd_tx_for_send = cmd_tx.clone();
    let cmd_tx_for_peers = cmd_tx.clone();
    let cmd_tx_for_contacts = cmd_tx.clone();
    let cmd_tx_for_history = cmd_tx.clone();
    let cmd_tx_for_addr = cmd_tx.clone();
    let cmd_tx_for_group = cmd_tx.clone();

    // Build command handlers
    let mut handlers: std::collections::HashMap<String, crate::cli::CommandHandler> =
        std::collections::HashMap::new();

    handlers.insert("connect".to_string(), Box::new(move |addr_str: &str| -> Result<()> {
        let addr: Multiaddr = addr_str.parse()
            .map_err(|e| anyhow::anyhow!("Invalid multiaddr '{}': {}", addr_str, e))?;
        futures::executor::block_on(cmd_tx_for_connect.send(NodeCommand::Connect(addr)))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    handlers.insert("send".to_string(), Box::new(move |args: &str| -> Result<()> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() < 2 {
            anyhow::bail!("Usage: send <peer_id> <message>");
        }
        let peer_id_str = parts[0];
        let message = parts[1].to_string();
        let target_peer: PeerId = peer_id_str.parse()
            .map_err(|e| anyhow::anyhow!("Invalid peer ID '{}': {}", peer_id_str, e))?;
        futures::executor::block_on(cmd_tx_for_send.send(NodeCommand::Send(target_peer, message)))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    handlers.insert("peers".to_string(), Box::new(move |_: &str| -> Result<()> {
        futures::executor::block_on(cmd_tx_for_peers.send(NodeCommand::ListPeers))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    handlers.insert("contacts".to_string(), Box::new(move |_: &str| -> Result<()> {
        futures::executor::block_on(cmd_tx_for_contacts.send(NodeCommand::ListContacts))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    handlers.insert("history".to_string(), Box::new(move |args: &str| -> Result<()> {
        let limit: usize = args.trim().parse().unwrap_or(20);
        futures::executor::block_on(cmd_tx_for_history.send(NodeCommand::History(limit)))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    handlers.insert("whoami".to_string(), Box::new(move |_: &str| -> Result<()> {
        println!("\nYour Peer ID:");
        println!("  {}\n", peer_id);
        Ok(())
    }));

    handlers.insert("addr".to_string(), Box::new(move |_: &str| -> Result<()> {
        futures::executor::block_on(cmd_tx_for_addr.send(NodeCommand::ListAddrs))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    let my_pid_bytes = peer_id.to_bytes();
    handlers.insert("safety".to_string(), Box::new(move |peer_str: &str| -> Result<()> {
        let their_pid: PeerId = peer_str.trim().parse()
            .map_err(|e| anyhow::anyhow!("Invalid peer ID '{}': {}", peer_str, e))?;
        let their_bytes = their_pid.to_bytes();

        let (a, b) = if my_pid_bytes <= their_bytes {
            (&my_pid_bytes[..], &their_bytes[..])
        } else {
            (&their_bytes[..], &my_pid_bytes[..])
        };

        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ME55-safety-v1");
        h.update(&(a.len() as u32).to_be_bytes());
        h.update(a);
        h.update(&(b.len() as u32).to_be_bytes());
        h.update(b);
        let digest = h.finalize();

        let hex_str: String = digest[..20]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let groups: Vec<String> = hex_str
            .as_bytes()
            .chunks(5)
            .map(|c| std::str::from_utf8(c).unwrap().to_string())
            .collect();

        println!("\n🔐 Safety number for {}", their_pid);
        println!("    {}", groups.join(" "));
        println!(
            "\nCompare with the output of `safety {}` on the peer's device —",
            peer_id
        );
        println!("out of band (voice, video, in person). If they match, the X25519");
        println!("prekey exchange was not intercepted by a MITM.\n");
        Ok(())
    }));

    handlers.insert("group".to_string(), Box::new(move |args: &str| -> Result<()> {
        let mut head = args.trim().splitn(2, char::is_whitespace);
        let sub = head.next().unwrap_or("").to_lowercase();
        let rest = head.next().unwrap_or("").trim();

        let send_cmd = |cmd: NodeCommand| -> Result<()> {
            futures::executor::block_on(cmd_tx_for_group.send(cmd))
                .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))
        };

        match sub.as_str() {
            "create" => {
                let toks: Vec<&str> = rest.split_whitespace().collect();
                if toks.len() < 1 {
                    anyhow::bail!("Usage: group create <name> [<pid1> <pid2> ...]");
                }
                let name = toks[0].to_string();
                let members: Result<Vec<PeerId>, _> =
                    toks[1..].iter().map(|s| s.parse::<PeerId>()).collect();
                let members = members
                    .map_err(|e| anyhow::anyhow!("Invalid peer id in member list: {}", e))?;
                send_cmd(NodeCommand::GroupCreate(name, members))
            }
            "list" | "ls" => send_cmd(NodeCommand::GroupList),
            "send" => {
                let mut parts = rest.splitn(2, char::is_whitespace);
                let gid_str = parts.next().unwrap_or("");
                let message = parts.next().unwrap_or("").trim();
                if gid_str.is_empty() || message.is_empty() {
                    anyhow::bail!("Usage: group send <group_id_hex> <message>");
                }
                let gid = parse_group_id_hex(gid_str)?;
                send_cmd(NodeCommand::GroupSend(gid, message.to_string()))
            }
            "add" => {
                let toks: Vec<&str> = rest.split_whitespace().collect();
                if toks.len() != 2 {
                    anyhow::bail!("Usage: group add <group_id_hex> <peer_id>");
                }
                let gid = parse_group_id_hex(toks[0])?;
                let peer: PeerId = toks[1]
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid peer id: {}", e))?;
                send_cmd(NodeCommand::GroupAdd(gid, peer))
            }
            "remove" | "rm" => {
                let toks: Vec<&str> = rest.split_whitespace().collect();
                if toks.len() != 2 {
                    anyhow::bail!("Usage: group remove <group_id_hex> <peer_id>");
                }
                let gid = parse_group_id_hex(toks[0])?;
                let peer: PeerId = toks[1]
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid peer id: {}", e))?;
                send_cmd(NodeCommand::GroupRemove(gid, peer))
            }
            "leave" => {
                let gid_str = rest.trim();
                if gid_str.is_empty() {
                    anyhow::bail!("Usage: group leave <group_id_hex>");
                }
                let gid = parse_group_id_hex(gid_str)?;
                send_cmd(NodeCommand::GroupLeave(gid))
            }
            other => anyhow::bail!(
                "Unknown group subcommand '{}'. Try: create, list, send, add, remove, leave.",
                other
            ),
        }
    }));

    // Start the node in background with command receiver
    let node_handle = tokio::spawn(async move {
        if let Err(e) = P2PNode::run_with_commands(node, cmd_rx).await {
            error!("Node error: {}", e);
        }
    });

    if cli.daemon {
        info!("Daemon mode — node running headless. Send SIGINT (Ctrl+C) or SIGTERM to stop.");
        // Block forever; the swarm runs inside `node_handle`. We could
        // wait for Ctrl+C explicitly via `tokio::signal::ctrl_c` but
        // for a background launcher (no TTY) the process is normally
        // killed externally, and a plain pending future achieves the
        // same shutdown latency.
        futures::future::pending::<()>().await;
    } else if use_gui {
        let rx = gui_event_rx.expect("gui_event_rx initialized when use_gui is set");
        run_gui(cmd_tx, rx).await?;
    } else {
        if let Err(e) = crate::cli::run_cli_with_handlers(handlers).await {
            error!("CLI error: {}", e);
        }
    }

    node_handle.abort();

    info!("Shutdown complete");

    Ok(())
}

#[cfg(feature = "gui")]
async fn run_gui(
    cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>,
    gui_event_rx: tokio::sync::mpsc::Receiver<GuiEvent>,
) -> Result<()> {
    crate::gui::run(cmd_tx, gui_event_rx).await
}

#[cfg(not(feature = "gui"))]
async fn run_gui(
    _cmd_tx: tokio::sync::mpsc::Sender<NodeCommand>,
    _gui_event_rx: tokio::sync::mpsc::Receiver<GuiEvent>,
) -> Result<()> {
    anyhow::bail!(
        "--gui was passed but this binary was built without the `gui` feature. \
         Rebuild with: cargo build --release --features gui \
         (and see plans/phase4-gui.md for the Tauri integration checklist)."
    )
}

fn parse_group_id_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim())
        .map_err(|e| anyhow::anyhow!("group id must be 64 hex chars: {}", e))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "group id must be exactly 32 bytes (64 hex chars); got {} bytes",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn get_profile_dir(profile: &str) -> Result<PathBuf> {
    let base_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ME55");
    let profile_dir = base_dir.join(profile);
    std::fs::create_dir_all(&profile_dir)?;
    Ok(profile_dir)
}

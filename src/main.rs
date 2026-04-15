use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{info, error};
use zerocenter_messenger::core::{Config, Identity, P2PNode, NodeCommand};
use zerocenter_messenger::cli::Cli;
use libp2p::{PeerId, Multiaddr};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Get profile directory
    let profile_dir = get_profile_dir(&cli.profile)?;

    info!("Starting ZeroCenter Messenger");
    info!("Profile: {}", cli.profile);
    info!("Data directory: {:?}", profile_dir);

    // Load or create identity
    let identity = Identity::load_or_create(&profile_dir)?;
    let peer_id = identity.peer_id();

    info!("Peer ID: {}", peer_id);
    println!("\n📡 ZeroCenter Messenger");
    println!("══════════════════════════════════════");
    println!("Profile: {}", cli.profile);
    println!("Peer ID: {}", peer_id);
    println!("\nType 'help' for commands, 'quit' to exit.\n");

    // Create configuration
    let config = Config {
        profile: cli.profile.clone(),
        data_dir: profile_dir,
        listen_port: cli.port,
        bootstrap_nodes: vec![],
    };

    // Initialize P2P node
    let mut node = P2PNode::new(config, identity).await?;

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

    // Build command handlers
    let mut handlers: std::collections::HashMap<String, zerocenter_messenger::cli::CommandHandler> = 
        std::collections::HashMap::new();

    // Connect handler
    handlers.insert("connect".to_string(), Box::new(move |addr_str: &str| -> Result<()> {
        let addr: Multiaddr = addr_str.parse()
            .map_err(|e| anyhow::anyhow!("Invalid multiaddr '{}': {}", addr_str, e))?;
        
        futures::executor::block_on(cmd_tx_for_connect.send(NodeCommand::Connect(addr)))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        
        Ok(())
    }));

    // Send handler
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

    // Peers handler
    handlers.insert("peers".to_string(), Box::new(move |_: &str| -> Result<()> {
        futures::executor::block_on(cmd_tx_for_peers.send(NodeCommand::ListPeers))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    // Contacts handler
    handlers.insert("contacts".to_string(), Box::new(move |_: &str| -> Result<()> {
        futures::executor::block_on(cmd_tx_for_contacts.send(NodeCommand::ListContacts))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    // History handler
    handlers.insert("history".to_string(), Box::new(move |args: &str| -> Result<()> {
        let limit: usize = args.trim().parse().unwrap_or(20);
        futures::executor::block_on(cmd_tx_for_history.send(NodeCommand::History(limit)))
            .map_err(|e| anyhow::anyhow!("Failed to send command: {}", e))?;
        Ok(())
    }));

    // Start the node in background with command receiver
    let node_handle = tokio::spawn(async move {
        if let Err(e) = P2PNode::run_with_commands(node, cmd_rx).await {
            error!("Node error: {}", e);
        }
    });

    // Run CLI interface with handlers
    if let Err(e) = zerocenter_messenger::cli::run_cli_with_handlers(handlers).await {
        error!("CLI error: {}", e);
    }

    node_handle.abort();

    info!("Shutdown complete");

    Ok(())
}

fn get_profile_dir(profile: &str) -> Result<PathBuf> {
    let base_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ZeroCenter");

    let profile_dir = base_dir.join(profile);

    // Create directory if it doesn't exist
    std::fs::create_dir_all(&profile_dir)?;

    Ok(profile_dir)
}

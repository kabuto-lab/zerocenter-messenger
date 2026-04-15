use anyhow::Result;
use clap::Parser;
use tracing::info;
use std::io::{self, BufRead};
use libp2p::{PeerId, Multiaddr};

/// ZeroCenter Messenger - Censorship-Resistant P2P Communication
#[derive(Parser, Debug)]
#[command(name = "zerocenter")]
#[command(author, version, about = "Censorship-Resistant, Zero-Trust, Leaderless P2P Messenger", long_about = None)]
pub struct Cli {
    /// Profile name (allows running multiple instances)
    #[arg(short, long, default_value = "default")]
    pub profile: String,

    /// Port to listen on (0 = random)
    #[arg(short = 'P', long, default_value_t = 0)]
    pub port: u16,
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse() -> Self {
        Parser::parse()
    }
}

/// Callback type for CLI commands
pub type CommandHandler = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Run the CLI interface with command handlers
pub async fn run_cli_with_handlers(
    handlers: std::collections::HashMap<String, CommandHandler>,
) -> Result<()> {
    info!("Running in CLI mode");
    info!("");
    info!("Commands:");
    info!("  quit - Exit the application");
    info!("  help - Show available commands");
    info!("  connect <address> - Connect to a peer");
    info!("  send <peer_id> <message> - Send a message");
    info!("  peers - List connected peers");
    info!("  contacts - List contacts");
    info!("  history [n] - Show last n messages (default: 20)");
    info!("");

    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        let cmd = parts[0].to_lowercase();

        match cmd.as_str() {
            "quit" | "exit" | "q" => {
                info!("Shutting down...");
                break;
            }
            "help" | "h" => {
                print_help();
            }
            "connect" | "c" => {
                if parts.len() < 2 {
                    println!("Usage: connect <multiaddr>");
                    println!("Example: connect /ip4/192.168.1.100/tcp/4001/p2p/12D3KooW...");
                    continue;
                }
                
                if let Some(handler) = handlers.get("connect") {
                    match handler(parts[1]) {
                        Ok(_) => println!("Connecting..."),
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("Connect handler not available");
                }
            }
            "send" | "s" => {
                if parts.len() < 2 {
                    println!("Usage: send <peer_id> <message>");
                    println!("Example: send 12D3KooW... Hello!");
                    continue;
                }
                
                if let Some(handler) = handlers.get("send") {
                    match handler(parts[1]) {
                        Ok(_) => {}
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("Send handler not available");
                }
            }
            "peers" | "p" => {
                if let Some(handler) = handlers.get("peers") {
                    match handler("") {
                        Ok(_) => {}
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("Peers handler not available");
                }
            }
            "contacts" | "co" => {
                if let Some(handler) = handlers.get("contacts") {
                    match handler("") {
                        Ok(_) => {}
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("Contacts handler not available");
                }
            }
            "history" | "hist" | "hi" => {
                let arg = if parts.len() > 1 { parts[1] } else { "20" };
                if let Some(handler) = handlers.get("history") {
                    match handler(arg) {
                        Ok(_) => {}
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("History handler not available");
                }
            }
            _ => {
                println!("Unknown command: {}. Type 'help' for commands.", cmd);
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!();
    println!("Available Commands:");
    println!("  quit, exit, q          - Exit the application");
    println!("  help, h                - Show this help");
    println!("  connect, c <addr>      - Connect to a peer by multiaddr");
    println!("  send, s <peer> <msg>   - Send a direct message");
    println!("  peers, p               - List connected peers");
    println!("  contacts, co           - List contacts");
    println!("  history, hi [n]        - Show last n messages (default: 20)");
    println!();
}

/// Run the basic CLI interface (legacy, for backward compatibility)
pub async fn run_cli() -> Result<()> {
    info!("Running in CLI mode");
    info!("");
    info!("Commands:");
    info!("  quit - Exit the application");
    info!("  help - Show this help");
    info!("");

    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        match line.trim() {
            "quit" | "exit" | "q" => {
                info!("Shutting down...");
                break;
            }
            "help" | "h" => {
                println!("Commands: quit, exit, q, help");
            }
            "" => {}
            cmd => {
                println!("Unknown command: {}. Type 'help' for commands.", cmd);
            }
        }
    }

    Ok(())
}

/// Parse a peer ID from string
pub fn parse_peer_id(s: &str) -> Result<PeerId> {
    PeerId::from_bytes(&bs58::decode(s).into_vec()?)
        .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))
}

/// Parse a multiaddr from string
pub fn parse_multiaddr(s: &str) -> Result<Multiaddr> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("Invalid multiaddr: {}", e))
}

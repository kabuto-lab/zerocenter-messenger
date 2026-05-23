use anyhow::Result;
use clap::Parser;
use tracing::info;
use std::io::{self, BufRead};

/// ME55 Messenger - Censorship-Resistant P2P Communication
#[derive(Parser, Debug)]
#[command(name = "ME55")]
#[command(author, version, about = "Censorship-Resistant, Zero-Trust, Leaderless P2P Messenger", long_about = None)]
pub struct Cli {
    /// Profile name (allows running multiple instances)
    #[arg(short, long, default_value = "default")]
    pub profile: String,

    /// Port to listen on (0 = random)
    #[arg(short = 'P', long, default_value_t = 0)]
    pub port: u16,

    /// Bootstrap node multiaddr (repeatable). Each address must include
    /// the peer's `/p2p/<PeerId>` suffix so we can seed the Kademlia
    /// routing table. Without a bootstrap node the DHT is reachable
    /// only via mDNS on the local network.
    ///
    /// Example: --bootstrap /ip4/198.51.100.1/tcp/4001/p2p/12D3KooW...
    #[arg(short = 'B', long = "bootstrap", value_name = "MULTIADDR")]
    pub bootstrap: Vec<String>,

    /// 32-byte shared obfuscation key (64 hex chars). When set, the TCP
    /// transport is wrapped with a ChaCha20-keystream XOR layer so the
    /// libp2p Noise handshake no longer matches DPI signatures. Both
    /// peers must use the **same** key. Without this flag, traffic is
    /// vanilla libp2p.
    #[arg(long = "obfs-key", value_name = "HEX64")]
    pub obfs_key: Option<String>,

    /// Inter-arrival-time jitter cap (milliseconds). When set together
    /// with `--obfs-key`, ScrambleStream waits a uniform-random delay in
    /// `[0, max]` before emitting each new frame, hiding the natural
    /// burst-pattern of libp2p traffic from statistical-timing analysis.
    /// Cost: up to `max` ms of added per-frame latency. Has no effect
    /// without `--obfs-key` (no scramble layer to gate). Off by default.
    #[arg(long = "obfs-jitter-ms", value_name = "MAX_MS")]
    pub obfs_jitter_ms: Option<u32>,

    /// Launch the Tauri webview UI. The GUI is the **default** surface
    /// on a binary built with the `gui` feature, so this flag is now
    /// only useful to force the explicit "rebuild with --features gui"
    /// error out of a headless build. See also `--cli`.
    #[arg(long = "gui")]
    pub gui: bool,

    /// Force the headless line-based REPL even on a GUI-capable build.
    /// Used by the `bats/` test scripts and the TEST_GUIDE flow.
    #[arg(long = "cli")]
    pub cli: bool,
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
            "safety" | "verify" | "sn" => {
                if parts.len() < 2 {
                    println!("Usage: safety <peer_id>");
                    println!("Prints a short fingerprint you can compare with the peer");
                    println!("out of band (voice/video) to detect a MITM on first contact.");
                    continue;
                }
                if let Some(handler) = handlers.get("safety") {
                    match handler(parts[1]) {
                        Ok(_) => {}
                        Err(e) => println!("Error: {}", e),
                    }
                } else {
                    println!("Safety handler not available");
                }
            }
            "whoami" | "me" => {
                if let Some(handler) = handlers.get("whoami") {
                    let _ = handler("");
                } else {
                    println!("whoami handler not available");
                }
            }
            "addr" | "addrs" | "a" => {
                if let Some(handler) = handlers.get("addr") {
                    let _ = handler("");
                } else {
                    println!("addr handler not available");
                }
            }
            "group" | "g" => {
                let args = if parts.len() > 1 { parts[1] } else { "" };
                if args.trim().is_empty() {
                    print_group_help();
                    continue;
                }
                if let Some(handler) = handlers.get("group") {
                    if let Err(e) = handler(args) {
                        println!("Error: {}", e);
                    }
                } else {
                    println!("Group handler not available");
                }
            }
            _ => {
                println!("Unknown command: {}. Type 'help' for commands.", cmd);
            }
        }
    }

    Ok(())
}

fn print_group_help() {
    println!();
    println!("Group subcommands:");
    println!("  group create <name> <pid1> [<pid2> ...]");
    println!("                        Create a new group with you as founder + the listed peers.");
    println!("  group list            List local groups (with id, epoch, member count, founder).");
    println!("  group send <gid> <message>");
    println!("                        Send a text message to all members of the group.");
    println!("  group add <gid> <pid> Add a peer to the group (founder only).");
    println!("  group remove <gid> <pid>");
    println!("                        Remove a peer from the group (founder only).");
    println!("  group leave <gid>     Leave the group (broadcasts a signed Leave).");
    println!();
    println!("  <gid> is the 64-character hex group id printed by `group create` / `group list`.");
    println!();
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
    println!("  safety, sn <peer>      - Print fingerprint to compare with peer (anti-MITM)");
    println!("  whoami, me             - Print your own PeerId");
    println!("  addr, addrs, a         - Print your shareable multiaddrs");
    println!("  group, g <subcmd>      - Group chats (create/list/send/add/remove/leave). `group` alone for help.");
    println!();
}


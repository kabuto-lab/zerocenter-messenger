//! Tauri 2.x webview frontend.
//!
//! This module is gated on the `gui` Cargo feature. Enabling the
//! feature alone is **not enough** to build the GUI — `Cargo.toml`
//! also needs the `tauri` / `tauri-build` deps, a top-level
//! `build.rs`, and a `tauri.conf.json` migrated to the 2.x schema.
//! See `plans/phase4-gui.md` for the full integration checklist.
//!
//! ## Architecture
//!
//! - `main.rs` builds the node and gets back a `mpsc::Sender<NodeCommand>`.
//! - With `--gui`, instead of running the line-reader CLI, `main.rs`
//!   calls [`run`] (this file), handing over that sender.
//! - Tauri commands wrap each call as `NodeCommand::Query*` carrying
//!   a `oneshot::Sender` for the reply. The node loop processes the
//!   command, fills the reply channel, the Tauri command awaits the
//!   receiver and returns the result to the webview's `invoke()`.
//!
//! This avoids any direct sharing of mutable node state with Tauri —
//! all interaction goes through the existing async command channel.

use anyhow::Result;
use libp2p::PeerId;
use tauri::{Emitter, Manager};
use tokio::sync::{mpsc, oneshot};

use crate::core::{GuiEvent, NodeCommand};

/// State held by Tauri and made available to every `#[tauri::command]`.
struct AppState {
    cmd_tx: mpsc::Sender<NodeCommand>,
}

/// Launch the Tauri application. Returns when the webview window is
/// closed by the user. `cmd_tx` is the same channel `main.rs` would
/// otherwise hand to `run_cli_with_handlers`. `gui_event_rx` carries
/// node-side push events (e.g. inbound-DM-decrypted) that the frontend
/// listens for to refresh in real time.
pub async fn run(
    cmd_tx: mpsc::Sender<NodeCommand>,
    gui_event_rx: mpsc::Receiver<GuiEvent>,
) -> Result<()> {
    let state = AppState { cmd_tx };
    // The setup closure runs once at startup; it consumes `gui_event_rx`
    // into a forwarder task. Wrap in Mutex<Option<_>> so the FnMut
    // signature `setup` requires is satisfied even though we move out
    // exactly once.
    let rx_slot = std::sync::Mutex::new(Some(gui_event_rx));

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            cmd::get_peer_id,
            cmd::get_contacts,
            cmd::get_messages,
            cmd::send_message,
            cmd::add_contact,
            cmd::get_groups,
            cmd::get_group_messages,
            cmd::create_group,
            cmd::send_group_message,
            cmd::add_group_member,
            cmd::remove_group_member,
            cmd::leave_group,
        ])
        .setup(move |app| {
            // Ensure the main window is visible on startup. Tauri 2.x
            // sometimes defers showing if the dev tools attached.
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
            }

            // Pump node-side GuiEvents onto the webview's event bus.
            // AppHandle is Clone+Send, so a tokio task can hold it for
            // the lifetime of the receiver.
            if let Some(mut rx) = rx_slot.lock().ok().and_then(|mut g| g.take()) {
                let handle = app.handle().clone();
                tokio::spawn(async move {
                    while let Some(ev) = rx.recv().await {
                        match ev {
                            GuiEvent::DmReceived { peer } => {
                                let _ = handle.emit("dm-received", peer);
                            }
                            GuiEvent::GroupMessageReceived { group_id, sender } => {
                                // Frontend listener for "group-msg-received"
                                // is wired in task #7. The forwarder arm is
                                // here now so the variant compiles end-to-end.
                                let _ = handle.emit(
                                    "group-msg-received",
                                    serde_json::json!({
                                        "group_id": group_id,
                                        "sender": sender,
                                    }),
                                );
                            }
                        }
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| anyhow::anyhow!("tauri runtime error: {}", e))?;

    Ok(())
}

mod cmd {
    //! Tauri command handlers. Each one constructs a oneshot channel,
    //! sends the matching `NodeCommand::Query*` to the node loop, and
    //! awaits the reply.

    use super::*;

    /// Convert any error type into the `String` Tauri expects in
    /// command error returns. We don't propagate structured errors to
    /// the webview yet — strings render fine in JS catches.
    fn err<E: std::fmt::Display>(e: E) -> String {
        e.to_string()
    }

    /// Send a command and await a oneshot reply. Centralizes the
    /// boilerplate so each command handler stays a 3-liner.
    async fn round_trip<T, F>(
        state: &AppState,
        build: F,
    ) -> Result<T, String>
    where
        F: FnOnce(oneshot::Sender<T>) -> NodeCommand,
    {
        let (tx, rx) = oneshot::channel();
        state.cmd_tx.send(build(tx)).await.map_err(err)?;
        rx.await.map_err(err)
    }

    #[tauri::command]
    pub async fn get_peer_id(state: tauri::State<'_, AppState>) -> Result<String, String> {
        round_trip(&state, NodeCommand::QueryPeerId).await
    }

    #[tauri::command]
    pub async fn get_contacts(
        state: tauri::State<'_, AppState>,
    ) -> Result<Vec<crate::core::ContactDto>, String> {
        round_trip(&state, NodeCommand::QueryContacts).await
    }

    #[tauri::command]
    pub async fn get_messages(
        state: tauri::State<'_, AppState>,
        contact: String,
    ) -> Result<Vec<crate::core::MessageDto>, String> {
        let peer = contact.parse::<PeerId>().map_err(err)?;
        round_trip(&state, |reply| NodeCommand::QueryMessages(peer, reply)).await
    }

    #[tauri::command]
    pub async fn send_message(
        state: tauri::State<'_, AppState>,
        recipient: String,
        content: String,
    ) -> Result<(), String> {
        let peer = recipient.parse::<PeerId>().map_err(err)?;
        // `Send` is fire-and-forget on the CLI path; for the GUI we
        // mirror that for now and rely on a follow-up Query to refresh
        // the conversation. A more responsive design would emit a
        // Tauri event from the node once the message is actually on
        // the wire — Phase 4 GUI v1.
        state
            .cmd_tx
            .send(NodeCommand::Send(peer, content))
            .await
            .map_err(err)
    }

    #[tauri::command]
    pub async fn add_contact(
        state: tauri::State<'_, AppState>,
        peer_id: String,
        alias: String,
    ) -> Result<(), String> {
        let peer = peer_id.parse::<PeerId>().map_err(err)?;
        let alias = if alias.trim().is_empty() {
            None
        } else {
            Some(alias.trim().to_string())
        };
        let result: Result<(), String> = round_trip(&state, |reply| NodeCommand::AddContact {
            peer_id: peer,
            alias,
            reply,
        })
        .await?;
        result
    }

    // ───────────────────── Phase 5 group commands ─────────────────────

    /// Decode a 64-char hex group id into raw 32 bytes. Shared by all
    /// group commands that take a group id from the webview.
    fn parse_gid(s: &str) -> Result<crate::protocol::GroupId, String> {
        let bytes = hex::decode(s.trim())
            .map_err(|e| format!("group id must be 64 hex chars: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "group id must be exactly 32 bytes (64 hex chars); got {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    #[tauri::command]
    pub async fn get_groups(
        state: tauri::State<'_, AppState>,
    ) -> Result<Vec<crate::core::GroupDto>, String> {
        round_trip(&state, NodeCommand::QueryGroups).await
    }

    #[tauri::command]
    pub async fn get_group_messages(
        state: tauri::State<'_, AppState>,
        group_id: String,
    ) -> Result<Vec<crate::core::GroupMessageDto>, String> {
        let gid = parse_gid(&group_id)?;
        round_trip(&state, |reply| NodeCommand::QueryGroupMessages(gid, reply)).await
    }

    #[tauri::command]
    pub async fn create_group(
        state: tauri::State<'_, AppState>,
        name: String,
        members: Vec<String>,
    ) -> Result<(), String> {
        let parsed: Result<Vec<PeerId>, _> =
            members.iter().map(|s| s.parse::<PeerId>()).collect();
        let parsed = parsed.map_err(|e| format!("invalid member peer id: {}", e))?;
        state
            .cmd_tx
            .send(NodeCommand::GroupCreate(name, parsed))
            .await
            .map_err(err)
    }

    #[tauri::command]
    pub async fn send_group_message(
        state: tauri::State<'_, AppState>,
        group_id: String,
        content: String,
    ) -> Result<(), String> {
        let gid = parse_gid(&group_id)?;
        state
            .cmd_tx
            .send(NodeCommand::GroupSend(gid, content))
            .await
            .map_err(err)
    }

    #[tauri::command]
    pub async fn add_group_member(
        state: tauri::State<'_, AppState>,
        group_id: String,
        peer_id: String,
    ) -> Result<(), String> {
        let gid = parse_gid(&group_id)?;
        let peer = peer_id.parse::<PeerId>().map_err(err)?;
        state
            .cmd_tx
            .send(NodeCommand::GroupAdd(gid, peer))
            .await
            .map_err(err)
    }

    #[tauri::command]
    pub async fn remove_group_member(
        state: tauri::State<'_, AppState>,
        group_id: String,
        peer_id: String,
    ) -> Result<(), String> {
        let gid = parse_gid(&group_id)?;
        let peer = peer_id.parse::<PeerId>().map_err(err)?;
        state
            .cmd_tx
            .send(NodeCommand::GroupRemove(gid, peer))
            .await
            .map_err(err)
    }

    #[tauri::command]
    pub async fn leave_group(
        state: tauri::State<'_, AppState>,
        group_id: String,
    ) -> Result<(), String> {
        let gid = parse_gid(&group_id)?;
        state
            .cmd_tx
            .send(NodeCommand::GroupLeave(gid))
            .await
            .map_err(err)
    }
}

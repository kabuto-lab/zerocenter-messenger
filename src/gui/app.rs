use anyhow::Result;
use tauri::{Manager, Window};

use crate::core::P2PNode;

/// Run the Tauri GUI application
pub async fn run(node: P2PNode) -> Result<()> {
    // Store node in app state
    let app_state = AppState { node };

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_peer_id,
            commands::send_message,
            commands::get_messages,
            commands::add_contact,
            commands::get_contacts,
        ])
        .run(tauri::generate_context!())
        .expect("Error running Tauri app");

    Ok(())
}

/// Application state shared with frontend
pub struct AppState {
    node: P2PNode,
}

/// Tauri commands (called from frontend)
mod commands {
    use super::*;

    #[tauri::command]
    fn get_peer_id(state: tauri::State<AppState>) -> String {
        state.node.peer_id().to_string()
    }

    #[tauri::command]
    async fn send_message(
        _state: tauri::State<'_, AppState>,
        _recipient: String,
        _content: String,
    ) -> Result<(), String> {
        // TODO: Implement message sending
        Ok(())
    }

    #[tauri::command]
    async fn get_messages(
        _state: tauri::State<'_, AppState>,
        _contact: String,
    ) -> Result<Vec<serde_json::Value>, String> {
        // TODO: Implement message retrieval
        Ok(vec![])
    }

    #[tauri::command]
    async fn add_contact(
        _state: tauri::State<'_, AppState>,
        _peer_id: String,
        _alias: String,
    ) -> Result<(), String> {
        // TODO: Implement contact management
        Ok(())
    }

    #[tauri::command]
    async fn get_contacts(
        _state: tauri::State<'_, AppState>,
    ) -> Result<Vec<serde_json::Value>, String> {
        // TODO: Implement contact list
        Ok(vec![])
    }
}

// VoiceFlow - Tauri Backend
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{
    CustomMenuItem, GlobalShortcutManager, Manager, SystemTray, SystemTrayEvent,
    SystemTrayMenu, SystemTrayMenuItem, WindowEvent, AppHandle, Window
};
use std::sync::Mutex;
use std::thread;
use std::sync::Arc;

struct AppState {
    recording: Arc<Mutex<bool>>,
    python_process: Arc<Mutex<Option<std::process::Child>>>,
}

#[tauri::command]
fn toggle_recording(state: tauri::State<AppState>, window: Window) -> Result<bool, String> {
    let mut recording = state.recording.lock().unwrap();
    *recording = !*recording;
    
    // Send message to frontend
    window.emit("recording-state", *recording).unwrap();
    
    // Send WebSocket message to Python server
    if *recording {
        window.emit("start-recording", {}).unwrap();
    } else {
        window.emit("stop-recording", {}).unwrap();
    }
    
    Ok(*recording)
}

#[tauri::command]
fn get_recording_state(state: tauri::State<AppState>) -> bool {
    *state.recording.lock().unwrap()
}

#[tauri::command]
async fn show_window(window: Window) {
    window.show().unwrap();
    window.set_focus().unwrap();
}

#[tauri::command]
async fn hide_window(window: Window) {
    window.hide().unwrap();
}

fn start_python_server(app_handle: AppHandle) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    // For development, assume Python server is started separately
    // In production, we would bundle and start it here
    Ok(std::process::Command::new("python")
        .arg("python/stt_server.py")
        .spawn()?)
}

fn main() {
    let app_state = AppState {
        recording: Arc::new(Mutex::new(false)),
        python_process: Arc::new(Mutex::new(None)),
    };

    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let show = CustomMenuItem::new("show".to_string(), "Show");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide");
    let toggle = CustomMenuItem::new("toggle".to_string(), "Toggle Recording");
    
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(toggle)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);

    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .manage(app_state)
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick {
                position: _,
                size: _,
                ..
            } => {
                let window = app.get_window("main").unwrap();
                if window.is_visible().unwrap() {
                    window.hide().unwrap();
                } else {
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    // Kill Python process before quitting
                    let state: tauri::State<AppState> = app.state();
                    if let Some(mut child) = state.python_process.lock().unwrap().take() {
                        let _ = child.kill();
                    }
                    std::process::exit(0);
                }
                "show" => {
                    let window = app.get_window("main").unwrap();
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
                "hide" => {
                    let window = app.get_window("main").unwrap();
                    window.hide().unwrap();
                }
                "toggle" => {
                    let window = app.get_window("main").unwrap();
                    let state: tauri::State<AppState> = app.state();
                    let mut recording = state.recording.lock().unwrap();
                    *recording = !*recording;
                    window.emit("recording-state", *recording).unwrap();
                }
                _ => {}
            },
            _ => {}
        })
        .setup(|app| {
            let app_handle = app.handle();
            
            // Register global hotkey (Ctrl+Alt+Space)
            let window = app.get_window("main").unwrap();
            let window_clone = window.clone();
            
            app.global_shortcut_manager()
                .register("Ctrl+Alt+Space", move || {
                    window_clone.emit("hotkey-pressed", {}).unwrap();
                })
                .unwrap();
            
            // Start minimized to tray
            window.hide().unwrap();
            
            // Note: Python server should be started separately for now
            println!("VoiceFlow started. Python server should be running on port 8765.");
            
            Ok(())
        })
        .on_window_event(|event| match event.event() {
            WindowEvent::CloseRequested { api, .. } => {
                // Hide window instead of closing
                event.window().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            toggle_recording,
            get_recording_state,
            show_window,
            hide_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
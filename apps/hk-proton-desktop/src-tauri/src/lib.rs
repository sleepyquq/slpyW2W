#[cfg(windows)]
mod commands;
mod dto;
mod error;
#[cfg(windows)]
mod live_runtime;
mod runtime;
mod scanner;
mod service;

#[cfg(feature = "pyxis")]
const PRODUCT_NAME: &str = "slpyW2W - Pyxis VPN";
#[cfg(not(feature = "pyxis"))]
const PRODUCT_NAME: &str = "slpyW2W";

#[cfg(windows)]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use std::sync::{Arc, Mutex};

    use hk_proton_manager::WindowsPrivateDirectory;
    use tauri::{
        Manager,
        menu::{Menu, MenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    };

    tauri::Builder::default()
        // 必须最先注册：第二次启动只通知首个实例，不进入 setup，也不会再创建托盘图标。
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_root = app.path().app_local_data_dir().map_err(|_| {
                std::io::Error::other(format!("无法定位 {PRODUCT_NAME} 本地状态目录"))
            })?;
            let state_root = app_data_root.join("state-vault");
            // GUI 在 release 下已提升权限；进入服务层前先封住用户可写路径中的 junction。
            let state_directory = WindowsPrivateDirectory::create(&app_data_root, &state_root)
                .map_err(|_| std::io::Error::other(format!("{PRODUCT_NAME} 本地状态目录不安全")))?;
            // 产品版只接受用户在文件选择器中明确选择的配置；不读取旧工具目录。
            let service = service::DesktopService::open(state_directory).map_err(|_| {
                std::io::Error::other(format!("无法初始化 {PRODUCT_NAME} 加密状态"))
            })?;
            app.manage(Arc::new(Mutex::new(service)));

            let show_item = MenuItem::with_id(
                app,
                "show",
                format!("显示 {PRODUCT_NAME}"),
                true,
                None::<&str>,
            )?;
            let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;
            TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .tooltip(PRODUCT_NAME)
                .icon(app.default_window_icon().cloned().ok_or_else(|| {
                    std::io::Error::other(format!("{PRODUCT_NAME} 托盘图标不可用"))
                })?)
                .on_menu_event(move |handle, event| match event.id().as_ref() {
                    "show" => show_main_window(handle),
                    "quit" => handle.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_status,
            commands::activate_pyxis_member,
            commands::import_config_files,
            commands::delete_profile,
            commands::update_selection,
            commands::validate_current,
            commands::connect,
            commands::disconnect,
            commands::poll_status,
            commands::measure_node_delays,
        ])
        .run(tauri::generate_context!())
        .expect("启动 slpyW2W 桌面应用失败");
}

#[cfg(windows)]
fn show_main_window(app: &tauri::AppHandle) {
    use tauri::Manager;

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(not(windows))]
pub fn run() {
    panic!("slpyW2W 桌面应用当前仅支持 Windows");
}

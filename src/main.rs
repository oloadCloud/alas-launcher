// No default console window createion on Windows
#![windows_subsystem = "windows"]

mod autostart;
mod backend;
mod i18n;
mod launcher_control;
mod notify;
mod setup;
mod window_util;

#[macro_use]
extern crate rust_i18n;
i18n!("locales", fallback = "en");

use std::{
    cell::Cell,
    fs,
    net::{SocketAddr, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self},
    time::{Duration, Instant},
};

use crate::{
    backend::{ManagedBackend, WebuiLaunchConfig},
    launcher_control::start_launcher_control_stream,
    notify::{start_notify_stream, NotificationClickHandler},
    setup::{
        get_deploy_config, setup_alas_repo, setup_environment, SplashUpdate,
    },
};
use anyhow::{anyhow, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::Local;
use reqwest::blocking::Client;
use rust_i18n::t;
use serde_json::to_string;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::TrayIconBuilder,
    webview::{PageLoadEvent, PageLoadPayload},
    Manager, Url, WebviewWindow,
};
use tauri_plugin_dialog::{DialogExt, FilePath};
use tauri_plugin_window_state::StateFlags;
#[cfg(test)]
use tempfile::Builder as TempDirBuilder;
use tracing::{debug, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

#[cfg(target_os = "macos")]
const MENUBAR_ICON_2X: &[u8] = include_bytes!("../icons/menubar@2x.png");
#[cfg(target_os = "macos")]
const MENUBAR_ICON_1X: &[u8] = include_bytes!("../icons/menubar.png");
#[cfg(windows)]
const WINDOWS_TRAY_ICON: &[u8] = include_bytes!("../icons/icon.png");
const SPLASH_BG_VIDEO: &[u8] = include_bytes!("../bg/bg.mp4");
const MI_SANS_FONT: &[u8] = include_bytes!("../fonts/MiSansLauncher.ttf");
const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const BACKEND_NAVIGATION_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(any(windows, target_os = "android"))]
const BACKEND_ERROR_URL_BASE: &str = "http://alas-error.localhost/backend";
#[cfg(not(any(windows, target_os = "android")))]
const BACKEND_ERROR_URL_BASE: &str = "alas-error://localhost/backend";
#[cfg(any(windows, target_os = "android"))]
const SPLASH_URL: &str = "http://alas-splash.localhost/";
#[cfg(not(any(windows, target_os = "android")))]
const SPLASH_URL: &str = "alas-splash://localhost/";
#[cfg(test)]
const TAURI_CONFIG_SOURCE: &str = include_str!("../tauri.conf.json");
const PREVIEW_NO_UPDATE_ARGS: &[&str] = &[
    "--preview-no-update",
    "--skip-update",
    "--no-update",
    "--disable-update",
    "/preview-no-update",
    "/skip-update",
    "/no-update",
];
const PREVIEW_CRASH_ARGS: &[&str] = &[
    "--preview-crash",
    "--preview-error",
    "--crash-preview",
    "--error-preview",
    "/preview-crash",
    "/preview-error",
];
const START_MINIMIZED_ARGS: &[&str] = &["--start-minimized", "/start-minimized"];

// ---------------------------------------------------------------------------
// 启动器信任免密登录
//
// 启动器为每次会话生成一个随机信任密钥，经环境变量 TRUST_SECRET_ENV 注入到
// gui.py 子进程。WebUI 启动后会据当前 --key / deploy.yaml Password 登记该
// 密钥；启动器窗口导航前先向后端换发一次性令牌，再进入 /launcher-login 页面
// 预置登录态实现免密。信任密钥与会话密钥解耦，其它浏览器仍走原密码门禁。
// 手动 gui.py 启动时密钥未注入，WebUI 端整体关闭该通道。
// ---------------------------------------------------------------------------
pub(crate) const TRUST_SECRET_ENV: &str = "ALAS_WEBUI_TRUST_SECRET";
const TRUST_SECRET_LENGTH: usize = 24;
const TRUST_LOGIN_TIMEOUT: Duration = Duration::from_secs(3);

static LAUNCHER_TRUST_SECRET: OnceLock<String> = OnceLock::new();

/// 生成（首次）并返回本次会话的启动器信任密钥。
pub(crate) fn launcher_trust_secret() -> &'static str {
    LAUNCHER_TRUST_SECRET.get_or_init(|| {
        use rand::RngCore;
        let mut bytes = [0u8; TRUST_SECRET_LENGTH];
        rand::rng().fill_bytes(&mut bytes);
        BASE64_STANDARD.encode(bytes)
    })
}

/// 计算主窗口应导航到的后端地址：若后端支持启动器免密（本机回环 + 密钥匹配），
/// 则返回带一次性令牌的 /launcher-login 页面；否则回退普通后端首页，维持原有
/// 登录行为。本函数不抛错，任何失败都静默回退。
fn webui_navigate_url(port: u16) -> String {
    let fallback = || backend_url(port);
    let secret = launcher_trust_secret();
    let client = match Client::builder()
        .timeout(TRUST_LOGIN_TIMEOUT)
        .no_proxy()
        .build()
    {
        Ok(client) => client,
        Err(_) => return fallback(),
    };
    let response = client
        .post(format!("http://127.0.0.1:{port}/api/launcher/trusted-login"))
        .header("X-Webui-Launcher-Secret", secret)
        .send();
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        _ => return fallback(),
    };
    // reqwest 未启用 json feature，手动解析 body。
    let body_text = match response.text() {
        Ok(body_text) => body_text,
        Err(_) => return fallback(),
    };
    let body: serde_json::Value = match serde_json::from_str(&body_text) {
        Ok(body) => body,
        Err(_) => return fallback(),
    };
    let Some(token) = body.get("token").and_then(|token| token.as_str()) else {
        return fallback();
    };
    if token.is_empty() {
        return fallback();
    }
    // 令牌为 URL-safe 随机串（secrets.token_urlsafe），可直接置于 query。
    format!("http://127.0.0.1:{port}/launcher-login?token={token}")
}

/// URL 的日志安全形式：只保留 scheme/host/port/path，剔除 query，避免
/// /launcher-login 的一次性令牌经日志落盘。
fn redacted_url_log(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return url.to_string();
    };
    let mut out = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(url.path());
    out
}

#[cfg(target_os = "macos")]
fn tray_icon_for_platform() -> Image<'static> {
    info!("Loading macOS tray icon from embedded bytes...");
    let result = Image::from_bytes(MENUBAR_ICON_2X)
        .or_else(|_| {
            info!("2x icon failed, trying 1x...");
            Image::from_bytes(MENUBAR_ICON_1X)
        })
        .unwrap_or_else(|err| {
            error!(
                ?err,
                "Failed to load tray icon from embedded menubar icon bytes (2x and 1x)."
            );
            panic!("Failed to load tray icon from embedded menubar icon bytes: {err}");
        });
    info!("Tray icon loaded successfully");
    result
}

#[cfg(windows)]
fn tray_icon_for_platform() -> Image<'static> {
    Image::from_bytes(WINDOWS_TRAY_ICON).unwrap_or_else(|err| {
        error!(?err, "Failed to load tray icon from embedded icon bytes.");
        panic!("Failed to load tray icon from embedded icon bytes: {err}");
    })
}

fn launcher_arg_present(flags: &[&str]) -> bool {
    std::env::args().skip(1).any(|arg| {
        let arg = arg.to_ascii_lowercase();
        flags.iter().any(|flag| arg == *flag)
    })
}

fn preview_no_update_arg_present() -> bool {
    launcher_arg_present(PREVIEW_NO_UPDATE_ARGS)
}

fn preview_crash_arg_present() -> bool {
    launcher_arg_present(PREVIEW_CRASH_ARGS)
}

fn start_minimized_arg_present() -> bool {
    launcher_arg_present(START_MINIMIZED_ARGS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_splash_i18n_uses_json_literals() {
        rust_i18n::set_locale("en");

        let html = splash_redesigned_shell_html("video", "font");

        assert!(html.contains(r#""defaultTip":"Sakura Empire's cherry blossoms"#));
        assert!(!html.contains("const defaultTip = '"));
        assert!(html.contains("window.__ALAS_SPLASH_READY = true;"));
        assert!(html.contains("data:video/mp4;base64,video"));
        assert!(html.contains("font-family: \"MiSans\""));
        assert!(html.contains("data:font/ttf;base64,font"));
        assert!(!html.contains("text-transform: uppercase;"));
    }

    #[test]
    fn test_splash_includes_optional_uv_progress() {
        let html = splash_redesigned_shell_html("video", "font");

        assert!(html.contains("data:video/mp4;base64,video"));
        assert!(html.contains("id=\"uv-progress-container\""));
        assert!(html.contains("payload.uv_progress"));
        assert!(html.contains("id=\"uv-progress-detail\""));
        assert!(html.contains("grid-template-columns: minmax(0, 1fr) auto"));
        assert!(html.contains("background: rgba(250, 250, 247, 0.78)"));
        assert!(html.contains("content: \"✦\""));
        assert!(!html.contains("'Tips: ' + subtitle.tip"));
        assert!(!html.contains("animation: sweep"));
    }

    #[test]
    fn test_truncate_log_file_replaces_existing_contents() {
        let temp_dir = TempDirBuilder::new()
            .prefix("launcher-log-truncate-test-")
            .tempdir()
            .expect("create temporary log directory");
        let filename = "launcher.txt";
        let path = temp_dir.path().join(filename);
        fs::write(&path, "old launcher log").expect("write old log");

        truncate_log_file(temp_dir.path(), filename).expect("truncate launcher log");

        assert_eq!(fs::read(&path).expect("read truncated log"), b"");
    }

    #[test]
    fn test_titlebars_use_webview_draggable_regions_for_touch_dragging() {
        let splash_html = splash_redesigned_shell_html("video", "font");

        assert!(splash_html.contains("touch-action: none;"));
        assert!(splash_html.contains("addEventListener('pointerdown'"));
        assert!(splash_html.contains("-webkit-app-region: drag;"));
        assert!(splash_html.contains("-webkit-app-region: no-drag;"));
        assert!(splash_html.contains("webviewDraggableRegionsEnabled"));
        assert!(splash_html.contains("if (webviewDraggableRegionsEnabled) {"));
        assert!(!splash_html.contains("$NATIVE_TOUCH_DRAG"));

        #[cfg(windows)]
        assert!(splash_html.contains("const webviewDraggableRegionsEnabled = true;"));

        #[cfg(not(target_os = "macos"))]
        let titlebar_script = main_window_titlebar_injection_script();

        #[cfg(not(target_os = "macos"))]
        {
            assert!(titlebar_script.contains("touch-action:none"));
            assert!(titlebar_script.contains("addEventListener('pointerdown'"));
            assert!(titlebar_script.contains("-webkit-app-region:drag"));
            assert!(titlebar_script.contains("-webkit-app-region:no-drag"));
            assert!(titlebar_script.contains("webviewDraggableRegionsEnabled"));
            assert!(titlebar_script.contains("if (webviewDraggableRegionsEnabled)"));
            assert!(titlebar_script.contains(
                ".alas-titlebar-drag-zone{position:absolute;inset:0 148px 0 0;height:100%;pointer-events:none"
            ));
            assert!(titlebar_script.contains(".alas-titlebar-drag-segment{"));
            assert!(titlebar_script.contains("const rebuildDragSegments = () =>"));
            assert!(titlebar_script.contains("getComputedStyle(element).cursor !== 'pointer'"));
            assert!(titlebar_script.contains("dragZone.replaceChildren(fragment)"));
            assert!(titlebar_script.contains("min-height:28px"));
            assert!(titlebar_script.contains("background:rgba(250,250,247,.78)"));
            assert!(titlebar_script.contains(".icon-close{color:#e64f58}"));
            assert!(titlebar_script.contains("--alas-titlebar-height:56px"));
            assert!(titlebar_script.contains("transform:translateY(-6px) scale(.96)"));
            assert!(!titlebar_script.contains("scale(.72)"));
            assert!(titlebar_script.contains("alas-close-menu"));
            assert!(!titlebar_script.contains("alas-close-optics"));
            assert!(!titlebar_script.contains("alas-island-open"));
            assert!(titlebar_script.contains("__ALAS_OPEN_CLOSE_PROMPT"));
            assert!(titlebar_script.contains("window_exit_application"));
            #[cfg(windows)]
            assert!(titlebar_script.contains("const webviewDraggableRegionsEnabled = true;"));
        }
    }

    #[test]
    fn test_windows_enable_webview_draggable_regions() {
        let config: serde_json::Value =
            serde_json::from_str(TAURI_CONFIG_SOURCE).expect("valid config");
        let windows = config["app"]["windows"].as_array().expect("window configs");

        for window in windows {
            let args = window["additionalBrowserArgs"]
                .as_str()
                .expect("draggable regions arguments");
            assert!(args.contains("msWebView2EnableDraggableRegions"));
            assert!(args.contains("ElasticOverscroll"));
            assert!(args.contains("msWebOOUI,msPdfOOUI,msSmartScreenProtection"));
            assert!(args.contains("--no-proxy-server"));
        }
    }
}

/// Set macOS activation policy to Regular (show in dock) or Accessory (hide from dock).
#[cfg(target_os = "macos")]
fn set_macos_activation_policy(app: &tauri::AppHandle, regular: bool) {
    let policy = if regular {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    if let Err(e) = app.set_activation_policy(policy) {
        error!("Failed to set activation policy: {}", e);
    }
}

fn main() -> Result<()> {
    #[cfg(windows)]
    unsafe {
        use crate::window_util::HAS_CONSOLE;
        use std::sync::atomic::Ordering;
        use winapi::um::wincon::{AttachConsole, ATTACH_PARENT_PROCESS};
        HAS_CONSOLE.store(AttachConsole(ATTACH_PARENT_PROCESS) != 0, Ordering::Relaxed);
    }
    setup_environment()?;
    let _log_guard = initialize_logging()?;
    crate::i18n::init();
    let preview_crash = preview_crash_arg_present();
    let preview_no_update = preview_crash || preview_no_update_arg_present();
    let start_minimized = start_minimized_arg_present();

    info!("=== AzurPilot starting ===");
    info!("Launcher log file: log/{}", today_launcher_log_filename());
    if preview_crash {
        info!("Preview crash mode enabled; splash will stop on an artificial error state");
    }
    if start_minimized {
        info!("Start minimized mode enabled; main window will stay in tray after backend is ready");
    }

    let deploy_config = get_deploy_config();
    let webui_config = WebuiLaunchConfig::from_deploy_config(deploy_config.as_ref());
    if deploy_config.is_none() {
        warn!("config/deploy.yaml not found or invalid, using default WebUI launch config");
    }
    let port = webui_config.port;

    let backend = Arc::new(Mutex::new(None));
    let allow_exit = Arc::new(AtomicBool::new(false));
    let setup_cancel_requested = Arc::new(AtomicBool::new(false));
    let setup_completed = Arc::new(AtomicBool::new(false));
    let recreating_main_window = Arc::new(AtomicBool::new(false));

    let allow_exit_for_setup = allow_exit.clone();
    let recreating_main_window_for_single_instance = recreating_main_window.clone();
    let recreating_main_window_for_setup = recreating_main_window.clone();
    let recreating_main_window_for_run = recreating_main_window.clone();
    let start_minimized_for_run = start_minimized;

    info!("Starting Webview...");
    tauri::Builder::default()
        .register_uri_scheme_protocol("alas-error", |_ctx, request| {
            backend_error_response(request)
        })
        .register_uri_scheme_protocol("alas-splash", |_ctx, _request| splash_response())
        .invoke_handler(tauri::generate_handler![
            save_as,
            download_today_gui_log,
            download_today_launcher_log,
            retry_backend_connection,
            window_hide,
            window_minimize,
            window_toggle_maximize,
            window_close,
            window_is_maximized
        ])
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
		.plugin(
            tauri_plugin_window_state::Builder::default()
                .with_filter(|label| label == "main")
                .with_state_flags(StateFlags::all() ^ StateFlags::VISIBLE)
                .build()
        )
        .plugin(tauri_plugin_single_instance::init(
            move |app, _argv, _cwd| {
                restore_main_window_from_tray(
                    app,
                    port,
                    recreating_main_window_for_single_instance.clone(),
                );
            },
        ))
        .setup(move |app| {
            create_main_window(&app.handle(), port)?;

            // Windows and macOS: create system tray
            #[cfg(any(windows, target_os = "macos"))]
            {
                info!("Creating system tray...");
                let allow_exit = allow_exit_for_setup.clone();
                let recreating_main_window_for_menu = recreating_main_window_for_setup.clone();
                #[cfg(windows)]
                let recreating_main_window_for_tray = recreating_main_window_for_setup.clone();
                let show_item = MenuItemBuilder::new(t!("tray.toggle_visibility"))
                    .id("toggle_visibility")
                    .build(app)?;
                let quit_item = MenuItemBuilder::new(t!("tray.quit"))
                    .id("quit")
                    .build(app)?;
                let tray_menu = MenuBuilder::new(app)
                    .item(&show_item)
                    .separator()
                    .item(&quit_item)
                    .build()?;

                info!("Tray menu created successfully");

                // Use embedded icon bytes so packaged apps always load the tray icon correctly.
                let icon = tray_icon_for_platform();

                info!("Building tray icon...");
                let mut tray_builder = TrayIconBuilder::with_id("main-tray")
                    .icon(icon)
                    .tooltip("AzurPilot")
                    .menu(&tray_menu);

                // On Windows, show menu on right click
                #[cfg(windows)]
                {
                    tray_builder = tray_builder.show_menu_on_left_click(false);
                }

                // On macOS, show menu on left click
                #[cfg(target_os = "macos")]
                {
                    info!("Setting macOS tray to show menu on left click");
                    tray_builder = tray_builder.show_menu_on_left_click(true);
                }

                match tray_builder
                    .on_menu_event(move |app, event| {
                        debug!("Tray menu event: {:?}", event.id());
                        match event.id().as_ref() {
                            "toggle_visibility" => {
                                toggle_main_window_visibility(
                                    app,
                                    port,
                                    recreating_main_window_for_menu.clone(),
                                );
                            }
                            "quit" => {
                                allow_exit.store(true, Ordering::SeqCst);
                                app.exit(0);
                            }
                            _ => {}
                        }
                    })
                    .on_tray_icon_event(move |tray, event| {
                        #[cfg(windows)]
                        if let tauri::tray::TrayIconEvent::Click {
                            button: tauri::tray::MouseButton::Left,
                            button_state: tauri::tray::MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            toggle_main_window_visibility(
                                &app,
                                port,
                                recreating_main_window_for_tray.clone(),
                            );
                        }

                        #[cfg(target_os = "macos")]
                        {
                            let _ = tray;
                            let _ = event;
                        }
                    })
                    .build(app)
                {
                    Ok(_) => {
                        info!("System tray created successfully!");
                    }
                    Err(e) => {
                        error!("Failed to create system tray: {:?}", e);
                        return Err(Box::new(e));
                    }
                }
            }

            Ok(())
        })
        .build(tauri::generate_context!())?
        .run(move |app_handle, event| {
            match event {
                tauri::RunEvent::Ready => {
                    debug!("RunEvent::Ready");
                    let allow_exit = allow_exit.clone();
                    let allow_exit_for_ctrlc = allow_exit.clone();
                    let handle1 = app_handle.clone();
                    ctrlc::set_handler(move || {
                        allow_exit_for_ctrlc.store(true, Ordering::SeqCst);
                        handle1.exit(0);
                    })
                    .expect("Error setting Ctrl-C handler");
                    let app_handle = app_handle.clone();
                    let backend = backend.clone();
                    let webui_config = webui_config.clone();
                    let setup_cancel_requested = setup_cancel_requested.clone();
                    let setup_completed = setup_completed.clone();
                    let recreating_main_window_for_notify = recreating_main_window_for_run.clone();
                    let start_minimized = start_minimized_for_run;
                    thread::spawn(move || {
                        let splash = app_handle.get_webview_window("splash").unwrap();
                        initialize_splash(&splash, !start_minimized);
                        let last_progress = Cell::new(0u8);
                        let mut status_updater = |mut update: SplashUpdate| {
                            update.progress = update.progress.max(last_progress.get());
                            last_progress.set(update.progress);
                            update_splash(&splash, &update);
                        };

                        status_updater(
                            SplashUpdate::loading(
                                t!("splash.starting"),
                                t!("splash.webui_init"),
                                4,
                            )
                            .with_subtitle(format!(
                                "{} | Tips:{}",
                                t!("splash.initializing"),
                                crate::setup::get_tip()
                            )),
                        );

                        if preview_crash {
                            if start_minimized {
                                let _ = reveal_window(&splash);
                            }
                            status_updater(
                                SplashUpdate::error(
                                    t!("dialog.startup_failed"),
                                    t!("splash.preview_crash_detail"),
                                    42,
                                )
                                .with_subtitle(format!(
                                    "{} | Tips：{}",
                                    t!("splash.preview_crash_mode"),
                                    crate::setup::get_tip()
                                )),
                            );
                            setup_completed.store(true, Ordering::SeqCst);
                            return;
                        }
                        if let Err(e) = setup_alas_repo(
                            &mut status_updater,
                            setup_cancel_requested.clone(),
                            preview_no_update,
                        ) {
                            error!("{e}");
                            if setup_cancel_requested.load(Ordering::SeqCst) {
                                return;
                            }
                            if start_minimized {
                                let _ = reveal_window(&splash);
                            }
                            status_updater(SplashUpdate::error(
                                t!("dialog.startup_failed"),
                                t!("dialog.repo_setup_failed", error = e.to_string()),
                                last_progress.get().max(8),
                            ));
                            return;
                        }
                        info!("Starting gui.py on http://127.0.0.1:{}/", port);
                        status_updater(
                            SplashUpdate::loading(
                                t!("splash.starting"),
                                t!("splash.webui_init_slow"),
                                97,
                            )
                            .with_subtitle(format!(
                                "{} | Tips:{}",
                                t!("splash.starting_backend"),
                                crate::setup::get_tip()
                            )),
                        );
                        let b = match ManagedBackend::new(&webui_config) {
                            Ok(backend) => backend,
                            Err(e) => {
                                error!("{e}");
                                if setup_cancel_requested.load(Ordering::SeqCst) {
                                    return;
                                }
                                if start_minimized {
                                    let _ = reveal_window(&splash);
                                }
                                status_updater(SplashUpdate::error(
                                    t!("dialog.startup_failed"),
                                    t!("dialog.backend_launch_failed", error = e.to_string()),
                                    last_progress.get().max(97),
                                ));
                                return;
                            }
                        };
                        *backend.lock().unwrap() = Some(b);
                        let notification_click: NotificationClickHandler = {
                            let app_handle = app_handle.clone();
                            let recreating_main_window = recreating_main_window_for_notify.clone();
                            Arc::new(move || {
                                restore_main_window_from_any_thread(
                                    app_handle.clone(),
                                    port,
                                    recreating_main_window.clone(),
                                );
                            })
                        };
                        start_notify_stream(
                            app_handle.clone(),
                            port,
                            allow_exit.clone(),
                            notification_click,
                        );
                        start_launcher_control_stream(port, allow_exit.clone());
                        status_updater(
                            SplashUpdate::loading(t!("splash.opening"), t!("splash.ready"), 100)
                                .with_subtitle(format!(
                                    "{} | Tips:{}",
                                    t!("splash.startup_complete"),
                                    crate::setup::get_tip()
                                )),
                        );
                        let _ = splash.destroy();
                        debug!("Destroyed splash window after startup");

                        info!("Webview is ready");
                        let window = app_handle.get_webview_window("main").unwrap();
                        window.set_resizable(true).unwrap();
                        if let Err(e) = navigate_backend_or_error(&window, port) {
                            error!("Failed to navigate main window: {:?}", e);
                        }
                        if start_minimized {
                            info!("Backend is ready; keeping main window hidden in tray");
                            let _ = window.hide();
                        } else {
                            reveal_window(&window).unwrap();
                        }
                        setup_completed.store(true, Ordering::SeqCst);
                    });
                }
                tauri::RunEvent::ExitRequested { api, .. } => {
                    if !setup_completed.load(Ordering::SeqCst) {
						info!("Exit requested during setup; stopping setup and exiting without environment rebuild");
						setup_cancel_requested.store(true, Ordering::SeqCst);
						allow_exit.store(true, Ordering::SeqCst);
                        if let Some(ref mut b) = *backend.lock().unwrap() {
							if let Err(e) = b.terminate() {
								warn!("Failed to terminate backend process: {:?}", e);
							}
						}
                        return;
                    }

                    let should_allow = allow_exit.load(Ordering::SeqCst);
                    debug!("ExitRequested event: allow_exit={}", should_allow);

                    // Only exit if explicitly allowed (e.g., via tray menu Quit)
                    if !should_allow {
                        api.prevent_exit();
                        debug!("Minimizing main window to tray");
                        minimize_main_window_to_tray(&app_handle, TrayMinimizeMode::Hide);
                        return;
                    }

                    debug!("allow_exit is TRUE, proceeding with app shutdown");
                    info!("App exit allowed, shutting down backend...");
                    if let Some(ref mut b) = *backend.lock().unwrap() {
                        if let Err(e) = b.terminate() {
                            warn!("Failed to terminate backend process: {:?}", e);
                        }
                    }
                }
                #[cfg(target_os = "macos")]
                tauri::RunEvent::Reopen { .. } => {
                    restore_main_window_from_any_thread(
                        app_handle.clone(),
                        port,
                        recreating_main_window_for_run.clone(),
                    );
                }
                tauri::RunEvent::WindowEvent {
                    label,
                    event: tauri::WindowEvent::CloseRequested { ref api, .. },
                    ..
                } => {
                    debug!("Window {} close requested", label);

                    if label == "splash" && !setup_completed.load(Ordering::SeqCst) {
						info!("Splash closed during setup; exiting without environment rebuild");
						setup_cancel_requested.store(true, Ordering::SeqCst);
						allow_exit.store(true, Ordering::SeqCst);
						app_handle.exit(0);
                        return;
                    }

                    if label == "splash" && !allow_exit.load(Ordering::SeqCst) {
                        api.prevent_close();
                        allow_exit.store(true, Ordering::SeqCst);
                        app_handle.exit(0);
                        return;
                    }

                    // Windows: destroy main window to release WebView resources.
                    #[cfg(windows)]
                    {
                        if label == "main" && !allow_exit.load(Ordering::SeqCst) {
                            api.prevent_close();
							minimize_main_window_to_tray(&app_handle, TrayMinimizeMode::Destroy);
                            return;
                        }
                    }

                    // macOS: switch to Accessory policy so the app does not terminate
                    // when no Regular windows are visible.
                    #[cfg(target_os = "macos")]
                    {
                        if label == "main" && !allow_exit.load(Ordering::SeqCst) {
                            api.prevent_close();
                            minimize_main_window_to_tray(&app_handle, TrayMinimizeMode::Hide);
                            return;
                        }
                    }

                    // Linux: just hide to tray
                    #[cfg(target_os = "linux")]
                    {
                        if label == "main" && !allow_exit.load(Ordering::SeqCst) {
                            api.prevent_close();
                            minimize_main_window_to_tray(&app_handle, TrayMinimizeMode::Hide);
                            return;
                        }
                    }
                }

                _ => {}
            };
        });
    Ok(())
}

fn initialize_logging() -> Result<WorkerGuard> {
    let log_dir = Path::new("log");
    let log_filename = today_launcher_log_filename();
    truncate_log_file(log_dir, &log_filename)?;
    let file_appender = tracing_appender::rolling::never(log_dir, log_filename);
    let (non_blocking_file, guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking_file)
        .with_ansi(false)
        .with_target(false)
        .with_filter(tracing::level_filters::LevelFilter::DEBUG);
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing::level_filters::LevelFilter::DEBUG);

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .init();

    Ok(guard)
}

fn truncate_log_file(log_dir: &Path, filename: &str) -> Result<()> {
    fs::create_dir_all(log_dir)?;
    let path = log_dir.join(filename);
    fs::File::create(&path)
        .with_context(|| format!("truncate launcher log file {}", path.display()))?;
    Ok(())
}

#[tauri::command]
fn save_as(app_handle: tauri::AppHandle, filename: &str, data: &str) {
    match BASE64_STANDARD.decode(data) {
        Ok(decoded_data) => app_handle
            .dialog()
            .file()
            .set_file_name(filename)
            .save_file(move |path| {
                let result: Result<()> = (move || {
                    let file_path = path
                        .as_ref()
                        .and_then(FilePath::as_path)
                        .ok_or_else(|| anyhow!("Invalid file path {:?}", &path))?;
                    fs::write(file_path, &decoded_data)?;
                    info!("Saved file to {:?}", file_path);
                    Ok(())
                })();
                if let Err(e) = result {
                    error!("Failed to save file: {:?}", e);
                }
            }),
        Err(e) => {
            error!("Failed to decode file content: {:?}", e);
        }
    }
}

#[tauri::command]
fn download_today_gui_log(app_handle: tauri::AppHandle) -> std::result::Result<String, String> {
    download_log_file(app_handle, today_gui_log_filename(), "GUI")
}

#[tauri::command]
fn download_today_launcher_log(
    app_handle: tauri::AppHandle,
) -> std::result::Result<String, String> {
    download_log_file(app_handle, today_launcher_log_filename(), "launcher")
}

fn download_log_file(
    app_handle: tauri::AppHandle,
    filename: String,
    log_name: &str,
) -> std::result::Result<String, String> {
    let log_name = log_name.to_owned();
    let source_path = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .join("log")
        .join(&filename);
    let data = fs::read(&source_path).map_err(|e| {
        t!(
            "errors.read_log_file",
            path = source_path.to_string_lossy().to_string(),
            error = e.to_string()
        )
    })?;

    app_handle
        .dialog()
        .file()
        .set_file_name(&filename)
        .save_file(move |path| {
            let log_name_for_save = log_name.clone();
            let result: Result<()> = (move || {
                let file_path = path
                    .as_ref()
                    .and_then(FilePath::as_path)
                    .ok_or_else(|| anyhow!("Invalid file path {:?}", &path))?;
                fs::write(file_path, &data)?;
                info!("Saved {} log to {:?}", log_name_for_save, file_path);
                Ok(())
            })();
            if let Err(e) = result {
                error!("Failed to save {} log: {:?}", log_name, e);
            }
        });

    Ok(filename)
}

fn today_gui_log_filename() -> String {
    format!("{}_gui.txt", Local::now().format("%Y-%m-%d"))
}

fn today_launcher_log_filename() -> String {
    format!("{}_launcher.txt", Local::now().format("%Y-%m-%d"))
}

#[tauri::command]
fn window_hide(app_handle: tauri::AppHandle) -> tauri::Result<()> {
    minimize_main_window_to_tray(&app_handle, TrayMinimizeMode::Hide);
    Ok(())
}

#[tauri::command]
fn window_minimize(window: WebviewWindow) -> tauri::Result<()> {
    window.minimize()
}

#[tauri::command]
fn window_toggle_maximize(window: WebviewWindow) -> tauri::Result<bool> {
    if window.is_maximized()? {
        window.unmaximize()?;
        Ok(false)
    } else {
        window.maximize()?;
        Ok(true)
    }
}

#[tauri::command]
fn window_close(window: WebviewWindow) -> tauri::Result<()> {
    window.close()
}

#[tauri::command]
fn window_is_maximized(window: WebviewWindow) -> tauri::Result<bool> {
    window.is_maximized()
}

#[tauri::command]
async fn retry_backend_connection(
    window: WebviewWindow,
    port: u16,
) -> std::result::Result<bool, String> {
    // 等待与换发免密令牌均含阻塞调用，统一放在阻塞线程中执行。
    let target_url = tauri::async_runtime::spawn_blocking(move || {
        if wait_for_backend_connection(port, BACKEND_NAVIGATION_TIMEOUT).is_err() {
            return None;
        }
        Some(webui_navigate_url(port))
    })
    .await
    .map_err(|e| {
        error!("Backend retry task failed: {e:?}");
        e.to_string()
    })?;

    let Some(target_url) = target_url else {
        return Ok(false);
    };

    let url = Url::parse(&target_url).map_err(|e| e.to_string())?;
    window.navigate(url).map_err(|e| {
        error!("Failed to navigate to reconnected backend: {e:?}");
        e.to_string()
    })?;
    Ok(true)
}

fn page_load_injector(webview: WebviewWindow, payload: PageLoadPayload<'_>) {
    if payload.event() == PageLoadEvent::Finished {
        info!(
            "Injecting saveFile function to loaded page: {}",
            redacted_url_log(payload.url())
        );
        let injected_js = r#"
if (!window.alas_launcher_injected) {
    window.alas_launcher_injected = true;
    (function () {
        // Prevent going back
        history.pushState(null, document.title, location.href);
        window.addEventListener('popstate', event => {
            history.pushState(null, document.title, location.href);
        });
        // Disable right-click menu
        window.addEventListener('contextmenu', event => {
            event.preventDefault();
        }, { capture: true });
        // Overwrite original saveAs function
        window.saveAs = function (blob, filename) {
            const reader = new FileReader();
            reader.onload = async () => {
                const data = reader.result.split(',')[1];
                console.log(data);
                const tauriInvoke =
                    (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
                    || (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);
                if (typeof tauriInvoke === 'function') {
                    tauriInvoke('save_as', { filename, data });
                }
            };
            reader.readAsDataURL(blob);
        };
__ALAS_TITLEBAR_SCRIPT__
    })();
}
"#
        .replace(
            "__ALAS_TITLEBAR_SCRIPT__",
            &main_window_titlebar_injection_script(),
        );
        if let Err(e) = webview.eval(&injected_js) {
            error!("Failed to inject JS to webview: {:?}", e);
        }
    }
}

fn initialize_splash(splash: &WebviewWindow, show_window: bool) {
    match Url::parse(SPLASH_URL) {
        Ok(url) => {
            if let Err(e) = splash.navigate(url) {
                error!("Failed to navigate splash page: {:?}", e);
            }
            if !wait_for_splash_ready(splash, Duration::from_secs(2)) {
                warn!("Timed out waiting for splash page readiness; showing splash anyway");
            }
            if show_window {
                if let Err(e) = splash.show() {
                    error!("Failed to show splash window: {:?}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to parse splash URL: {:?}", e);
        }
    }
}

fn wait_for_splash_ready(splash: &WebviewWindow, timeout: Duration) -> bool {
    let started_at = Instant::now();
    while started_at.elapsed() < timeout {
        if splash
            .eval(
                r#"
                if (!window.__ALAS_SPLASH_READY) {
                    throw new Error("splash page is not ready");
                }
                "#,
            )
            .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn update_splash(splash: &WebviewWindow, update: &SplashUpdate) {
    let payload = to_string(update).unwrap();
    let script = format!("window.__ALAS_SPLASH_UPDATE && window.__ALAS_SPLASH_UPDATE({payload});");
    if let Err(e) = splash.eval(&script) {
        error!("Failed to update splash page: {:?}", e);
    }
}

fn backend_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/")
}

fn splash_response() -> tauri::http::Response<Vec<u8>> {
    let video_bg_b64 = BASE64_STANDARD.encode(SPLASH_BG_VIDEO);
    let mi_sans_font_b64 = BASE64_STANDARD.encode(MI_SANS_FONT);
    tauri::http::Response::builder()
        .header(
            tauri::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )
        .body(splash_redesigned_shell_html(&video_bg_b64, &mi_sans_font_b64).into_bytes())
        .unwrap()
}

fn check_backend_connection(port: u16) -> Result<()> {
    let address: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    TcpStream::connect_timeout(&address, BACKEND_CONNECT_TIMEOUT)
        .map(|_| ())
        .map_err(|e| anyhow!("Unable to connect to local backend at {address}: {e}"))
}

fn wait_for_backend_connection(port: u16, timeout: Duration) -> Result<()> {
    let started_at = Instant::now();
    let mut last_error = None;
    while started_at.elapsed() < timeout {
        match check_backend_connection(port) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_error = Some(e);
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!(t!("errors.backend_timeout"))))
}

fn navigate_backend_or_error(window: &WebviewWindow, port: u16) -> Result<bool> {
    match wait_for_backend_connection(port, BACKEND_NAVIGATION_TIMEOUT) {
        Ok(()) => {
            let url = webui_navigate_url(port);
            window.navigate(Url::parse(&url)?)?;
            Ok(true)
        }
        Err(e) => {
            warn!("Backend connection check failed before navigation: {:?}", e);
            navigate_to_backend_error(window, port, &e.to_string())?;
            Ok(false)
        }
    }
}

fn navigate_to_backend_error(window: &WebviewWindow, port: u16, error_detail: &str) -> Result<()> {
    let url = backend_error_url(port, error_detail)?;
    window.navigate(url)?;
    Ok(())
}

fn backend_error_url(port: u16, error_detail: &str) -> Result<Url> {
    let port = port.to_string();
    Ok(Url::parse_with_params(
        BACKEND_ERROR_URL_BASE,
        [("port", port.as_str()), ("detail", error_detail)],
    )?)
}

fn backend_error_response(
    request: tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    let (port, detail) = backend_error_request_params(request.uri().to_string().as_str());
    let html = backend_error_html(port, &detail);

    tauri::http::Response::builder()
        .header(
            tauri::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )
        .body(html.into_bytes())
        .unwrap()
}

fn backend_error_request_params(uri: &str) -> (u16, String) {
    let mut port = 22267;
    let mut detail = t!("error_page.unable_connect").to_string();

    if let Ok(url) = Url::parse(uri) {
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "port" => {
                    if let Ok(parsed_port) = value.parse::<u16>() {
                        port = parsed_port;
                    }
                }
                "detail" => detail = value.into_owned(),
                _ => {}
            }
        }
    }

    (port, detail)
}

fn handle_backend_navigation(app: tauri::AppHandle, port: u16, url: &Url) -> bool {
    if !is_backend_url(url, port) {
        return true;
    }

    match check_backend_connection(port) {
        Ok(()) => true,
        Err(e) => {
            let blocked_url = redacted_url_log(url);
            warn!(
                "Blocked navigation to unreachable backend {}: {:?}",
                blocked_url, e
            );
            let error_detail = e.to_string();
            thread::spawn(move || {
                if let Some(window) = app.get_webview_window("main") {
                    if let Err(e) = navigate_to_backend_error(&window, port, &error_detail) {
                        error!("Failed to show backend error page: {:?}", e);
                    }
                }
            });
            false
        }
    }
}

fn is_backend_url(url: &Url, port: u16) -> bool {
    matches!(url.scheme(), "http" | "https")
        && matches!(url.host_str(), Some("127.0.0.1") | Some("localhost"))
        && url.port_or_known_default() == Some(port)
}

fn escape_html(input: impl AsRef<str>) -> String {
    input
        .as_ref()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn backend_error_html(port: u16, error_detail: &str) -> String {
    let backend_url_json = to_string(&backend_url(port)).unwrap();
    let error_detail_json = to_string(error_detail).unwrap();
    let mi_sans_font_b64 = BASE64_STANDARD.encode(MI_SANS_FONT);
    let splash_video_b64 = BASE64_STANDARD.encode(SPLASH_BG_VIDEO);
    let titlebar_script = main_window_titlebar_injection_script();
    let i18n = serde_json::json!({
        "title": t!("error_page.title"),
        "heading": t!("error_page.heading"),
        "description": t!("error_page.description"),
        "address": t!("error_page.address"),
        "errorLabel": t!("error_page.error_label"),
        "retry": t!("error_page.retry"),
        "downloadGuiLog": t!("error_page.download_gui_log"),
        "downloadLauncherLog": t!("error_page.download_launcher_log"),
        "reconnecting": t!("error_page.reconnecting"),
        "stillFailed": t!("error_page.still_failed"),
        "retryFailed": t!("error_page.retry_failed"),
        "preparing": t!("error_page.preparing"),
        "saved": t!("error_page.saved"),
        "downloadFailed": t!("error_page.download_failed"),
    });
    let i18n_json = to_string(&i18n).unwrap();

    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  @font-face {{
    font-family: "MiSans";
    src: url(data:font/ttf;base64,{mi_sans_font_b64}) format("truetype");
    font-weight: 100 900;
    font-style: normal;
    font-display: swap;
  }}
  :root {{
    color-scheme: light;
    --bg: #f4f6f8;
    --surface: #ffffff;
    --surface-soft: #f8fafb;
    --line: #e5e9ee;
    --text: #17212b;
    --muted: #687582;
    --accent: #176b67;
    --accent-hover: #105854;
    --accent-soft: #e8f4f2;
    --danger: #b64545;
    --danger-soft: #fff1f0;
  }}
  * {{
    box-sizing: border-box;
  }}
  html, body {{
    width: 100%;
    min-height: 100%;
    margin: 0;
    font-family: "MiSans", sans-serif;
    font-weight: 420;
    font-synthesis: none;
    color: var(--text);
    background: #dfe7ea;
  }}
  body {{
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 72px 44px 44px;
    position: relative;
    isolation: isolate;
    overflow: hidden;
    background: transparent;
    animation: page-in 420ms cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .error-background-video {{
    position: fixed;
    inset: 0;
    z-index: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    opacity: 0.9;
    pointer-events: none;
  }}
  .error-background-scrim {{
    position: fixed;
    inset: 0;
    z-index: 1;
    background: rgba(244, 247, 248, 0.36);
    pointer-events: none;
  }}
  .panel {{
    position: relative;
    z-index: 2;
    display: grid;
    grid-template-columns: 190px minmax(0, 1fr);
    width: min(820px, 100%);
    min-height: 390px;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: rgba(255, 255, 255, 0.76);
    backdrop-filter: blur(22px) saturate(1.08);
    box-shadow: 0 20px 48px rgba(23, 33, 43, 0.11), 0 2px 6px rgba(23, 33, 43, 0.04);
    animation: panel-in 520ms cubic-bezier(0.22, 1, 0.36, 1) 70ms both;
  }}
  .signal {{
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--accent);
    color: #fff;
  }}
  .signal::before, .signal::after {{
    content: "";
    position: absolute;
    border: 1px solid rgba(255, 255, 255, 0.17);
    border-radius: 50%;
    opacity: 0;
    animation: signal-expand 3.2s ease-out infinite;
  }}
  .signal::before {{ width: 76px; height: 76px; }}
  .signal::after {{ width: 76px; height: 76px; animation-delay: 1.6s; }}
  .signal-core {{
    position: relative;
    z-index: 1;
    width: 76px;
    height: 76px;
    display: grid;
    place-items: center;
    border: 1px solid rgba(255, 255, 255, 0.45);
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.12);
    animation: core-breathe 2.8s ease-in-out infinite;
  }}
  .signal-core svg {{
    width: 36px;
    height: 36px;
    fill: none;
    stroke: currentColor;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke-width: 1.7;
  }}
  .content {{
    display: flex;
    flex-direction: column;
    min-width: 0;
    padding: 38px 42px 32px;
    animation: content-in 500ms cubic-bezier(0.22, 1, 0.36, 1) 140ms both;
  }}
  .eyebrow {{
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    font-size: 11px;
    font-weight: 620;
    letter-spacing: 1.2px;
    text-transform: uppercase;
  }}
  .eyebrow::before {{
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--danger);
    box-shadow: 0 0 0 4px var(--danger-soft);
    animation: status-pulse 2s ease-in-out infinite;
  }}
  h1 {{
    max-width: 470px;
    margin: 16px 0 0;
    font-size: 30px;
    font-weight: 680;
    letter-spacing: -0.3px;
    line-height: 1.18;
  }}
  .lead {{
    max-width: 510px;
    margin: 12px 0 0;
    color: var(--muted);
    font-size: 14px;
    font-weight: 430;
    line-height: 1.65;
  }}
  .details {{
    margin: 24px 0 0;
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
    background: var(--surface-soft);
  }}
  .row {{
    display: grid;
    grid-template-columns: 70px minmax(0, 1fr);
    gap: 14px;
    padding: 10px 13px;
    border-top: 1px solid var(--line);
    font-size: 12px;
    font-weight: 460;
    line-height: 1.5;
  }}
  .row:first-child {{ border-top: 0; }}
  .label {{ color: var(--muted); }}
  .value {{
    min-width: 0;
    overflow-wrap: anywhere;
    color: var(--text);
    font-family: inherit;
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }}
  .actions {{
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
    margin-top: auto;
    padding-top: 24px;
  }}
  button {{
    min-height: 36px;
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 0 13px;
    font: inherit;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 140ms ease, border-color 140ms ease, color 140ms ease, opacity 140ms ease;
    will-change: transform;
  }}
  button:hover {{ transform: translateY(-1px); }}
  button:active {{ transform: translateY(0); }}
  .action-button {{
    color: #fff;
    background: var(--accent);
  }}
  .action-button:hover {{ background: var(--accent-hover); }}
  .secondary-button {{
    color: var(--accent);
    border-color: #c5dfdc;
    background: var(--accent-soft);
  }}
  .secondary-button:hover {{ background: #dcefeb; border-color: #a8d2cd; }}
  button:disabled {{ cursor: default; opacity: 0.55; }}
  button:disabled:hover {{ transform: none; }}
  .status {{
    flex: 1 1 100%;
    min-height: 18px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 460;
  }}
  .footer {{
    margin-top: 16px;
    color: #9aa5ae;
    font-size: 11px;
    font-weight: 430;
  }}
  @media (max-width: 680px) {{
    body {{ padding: 62px 18px 24px; align-items: flex-start; }}
    .panel {{ grid-template-columns: 1fr; min-height: 0; }}
    .signal {{ min-height: 120px; }}
    .signal::before {{ width: 76px; height: 76px; }}
    .signal::after {{ width: 76px; height: 76px; }}
    .content {{ padding: 28px 24px 24px; }}
    h1 {{ font-size: 25px; }}
    .actions {{ margin-top: 22px; }}
    button {{ flex: 1 1 auto; }}
  }}
  @media (max-width: 420px) {{
    .row {{ grid-template-columns: 1fr; gap: 3px; }}
    button {{ width: 100%; }}
  }}
  @keyframes page-in {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
  @keyframes panel-in {{ from {{ opacity: 0; transform: translateY(12px) scale(0.985); }} to {{ opacity: 1; transform: translateY(0) scale(1); }} }}
  @keyframes content-in {{ from {{ opacity: 0; transform: translateX(10px); }} to {{ opacity: 1; transform: translateX(0); }} }}
  @keyframes signal-expand {{ 0% {{ opacity: 0.72; transform: scale(0.72); }} 68% {{ opacity: 0.12; }} 100% {{ opacity: 0; transform: scale(2.8); }} }}
  @keyframes core-breathe {{ 0%, 100% {{ transform: scale(1); }} 50% {{ transform: scale(1.045); }} }}
  @keyframes status-pulse {{ 0%, 100% {{ opacity: 0.62; }} 50% {{ opacity: 1; }} }}
  @media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{ animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; }}
  }}
</style>
</head>
<body>
  <video class="error-background-video" autoplay muted loop playsinline preload="auto" aria-hidden="true">
    <source src="data:video/mp4;base64,{splash_video_b64}" type="video/mp4">
  </video>
  <div class="error-background-scrim" aria-hidden="true"></div>
  <main class="panel">
    <div class="signal" aria-hidden="true">
      <div class="signal-core">
        <svg viewBox="0 0 24 24"><path d="M12 8v4m0 4h.01"/><path d="M10.3 3.9 2.8 17a2 2 0 0 0 1.7 3h15a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
      </div>
    </div>
    <div class="content">
      <div class="eyebrow">{error_label}</div>
      <h1>{heading}</h1>
      <p class="lead">{description}</p>
      <section class="details" aria-label="{connection_info}">
        <div class="row">
          <div class="label">{address}</div>
          <div id="backend-url" class="value"></div>
        </div>
        <div class="row">
          <div class="label">{error_label}</div>
          <div id="error-detail" class="value"></div>
        </div>
      </section>
      <div class="actions">
        <button id="retry-button" class="action-button" type="button">{retry}</button>
        <button id="gui-log-button" class="secondary-button" type="button">{download_gui_log}</button>
        <button id="launcher-log-button" class="secondary-button" type="button">{download_launcher_log}</button>
        <span id="retry-status" class="status"></span>
      </div>
      <div class="footer">AzurPilot · {connection_info}</div>
    </div>
  </main>
  <script>
    (function () {{
{titlebar_script}
    }})();

    const i18n = {i18n_json};
    const backendUrl = {backend_url_json};
    const errorDetail = {error_detail_json};
    const port = {port};
    const retryButton = document.getElementById('retry-button');
    const guiLogButton = document.getElementById('gui-log-button');
    const launcherLogButton = document.getElementById('launcher-log-button');
    const retryStatus = document.getElementById('retry-status');
    const invoke =
      (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
      || (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);

    document.getElementById('backend-url').textContent = backendUrl;
    document.getElementById('error-detail').textContent = errorDetail;

    retryButton.addEventListener('click', async () => {{
      retryButton.disabled = true;
      retryStatus.textContent = i18n.reconnecting;
      try {{
        if (typeof invoke !== 'function') {{
          throw new Error('Tauri invoke is unavailable');
        }}
        const connected = await invoke('retry_backend_connection', {{ port }});
        if (!connected) {{
          retryStatus.textContent = i18n.stillFailed;
          retryButton.disabled = false;
        }}
      }} catch (error) {{
        retryStatus.textContent = i18n.retryFailed + (error && error.message ? error.message : error);
        retryButton.disabled = false;
      }}
    }});

    async function downloadLog(button, command, label) {{
      button.disabled = true;
      retryStatus.textContent = i18n.preparing.replace('%{{label}}', label);
      try {{
        if (typeof invoke !== 'function') {{
          throw new Error('Tauri invoke is unavailable');
        }}
        const filename = await invoke(command);
        retryStatus.textContent = i18n.saved.replace('%{{filename}}', filename);
      }} catch (error) {{
        retryStatus.textContent = i18n.downloadFailed.replace('%{{label}}', label) + (error && error.message ? error.message : error);
      }} finally {{
        button.disabled = false;
      }}
    }}

    guiLogButton.addEventListener('click', () => {{
      downloadLog(guiLogButton, 'download_today_gui_log', '{gui_log_label}');
    }});

    launcherLogButton.addEventListener('click', () => {{
      downloadLog(launcherLogButton, 'download_today_launcher_log', '{launcher_log_label}');
    }});

    // 每秒尝试自动刷新（重试连接）
    setInterval(() => {{
      if (!retryButton.disabled) {{
        retryButton.click();
      }}
    }}, 1000);
  </script>
</body>
</html>"#,
        title = t!("error_page.title"),
        heading = t!("error_page.heading"),
        description = t!("error_page.description"),
        address = t!("error_page.address"),
        error_label = t!("error_page.error_label"),
        retry = t!("error_page.retry"),
        download_gui_log = t!("error_page.download_gui_log"),
        download_launcher_log = t!("error_page.download_launcher_log"),
        gui_log_label = t!("error_page.download_gui_log"),
        launcher_log_label = t!("error_page.download_launcher_log"),
        connection_info = t!("error_page.connection_info"),
    )
}

fn splash_redesigned_shell_html(video_bg_b64: &str, mi_sans_font_b64: &str) -> String {
    let i18n = serde_json::json!({
        "defaultTip": t!("tips.17"),
        "loading": t!("splash.loading_badge"),
        "webuiInit": t!("splash.webui_init"),
        "starting": t!("splash.starting"),
        "errorBadge": t!("splash.error_badge"),
        "initStopped": t!("splash.init_stopped"),
        "progressMetaReady": t!("splash.progress_meta_ready"),
        "preparingLog": t!("splash.preparing_log"),
        "logSavedPrefix": t!("splash.log_saved_prefix"),
        "logFailed": t!("splash.log_failed"),
    });
    let i18n_json = to_string(&i18n).unwrap();

    r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  @font-face {
    font-family: "MiSans";
    src: url(data:font/ttf;base64,$MI_SANS_FONT) format("truetype");
    font-weight: 100 900;
    font-style: normal;
    font-display: swap;
  }
  :root {
    --primary-color: #4facfe;
    --secondary-color: #00f2fe;
    --text-main: #ffffff;
    --text-sub: rgba(255, 255, 255, 0.76);
    --text-muted: rgba(255, 255, 255, 0.52);
    --surface-soft: rgba(255, 255, 255, 0.16);
    --surface-border: rgba(255, 255, 255, 0.15);
    --danger: #ff5f57;
    --warning: #ffbd2e;
  }
  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    user-select: none;
  }
  html,
  body {
    width: 100%;
    height: 100%;
    overflow: hidden;
    background: #111827;
  }
  body {
    font-family: "MiSans", sans-serif;
    font-weight: 420;
    font-synthesis: none;
    color: var(--text-main);
  }
  button {
    font: inherit;
  }
  .launcher-window {
    position: relative;
    width: 100%;
    height: 100%;
    overflow: hidden;
    border-radius: 0;
    background: #111827;
    box-shadow: none;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .splash-background-video {
    position: absolute;
    inset: 0;
    z-index: 0;
    width: 100%;
    height: 100%;
    object-fit: cover;
    pointer-events: none;
  }
  .launcher-window::before {
    content: "";
    position: absolute;
    inset: 0;
    z-index: 1;
    background:
      linear-gradient(to bottom, rgba(0, 0, 0, 0.05) 0%, rgba(0, 0, 0, 0.03) 42%, rgba(0, 0, 0, 0.28) 100%),
      linear-gradient(115deg, rgba(12, 30, 72, 0.10), rgba(255, 126, 117, 0.05));
    pointer-events: none;
  }
  .top-bar {
    position: relative;
    z-index: 2;
    display: flex;
    justify-content: space-between;
    align-items: center;
    min-height: 56px;
    padding: 10px 18px;
    touch-action: none;
    app-region: drag;
    -webkit-app-region: drag;
  }
  .brand-zone {
    display: flex;
    align-items: center;
    min-width: 0;
    gap: 10px;
  }
  .app-title {
    color: var(--text-main);
    font-size: 18px;
    font-weight: 610;
    letter-spacing: 0;
    text-shadow: 0 2px 6px rgba(0, 0, 0, 0.22);
  }
  .app-version {
    color: var(--text-sub);
    font-size: 12px;
    font-weight: 460;
    line-height: 1;
    background: rgba(255, 255, 255, 0.14);
    border: 1px solid rgba(255, 255, 255, 0.11);
    padding: 4px 9px;
    border-radius: 999px;
    backdrop-filter: blur(8px);
  }
  .top-right {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .status-badge {
    max-width: 260px;
    min-height: 32px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    border-radius: 999px;
    padding: 6px 13px;
    color: #394451;
    background: rgba(250, 250, 247, 0.78);
    border: 1px solid rgba(255, 255, 255, 0.92);
    backdrop-filter: blur(16px) saturate(1.2);
    box-shadow: 0 4px 14px rgba(61, 79, 97, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.36);
    font-size: 12px;
    font-weight: 460;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .status-badge::before {
    content: "";
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--secondary-color);
    box-shadow: 0 0 12px rgba(0, 242, 254, 0.7);
    flex: 0 0 auto;
  }
  .window-controls {
    display: flex;
    align-items: center;
    gap: 2px;
    min-height: 36px;
    padding: 3px 4px;
    border: 1px solid rgba(255, 255, 255, 0.92);
    border-radius: 18px;
    background: rgba(250, 250, 247, 0.78);
    box-shadow: 0 4px 14px rgba(61, 79, 97, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.36);
    backdrop-filter: blur(16px) saturate(1.2);
    flex: 0 0 auto;
    app-region: no-drag;
    -webkit-app-region: no-drag;
  }
  .window-controls * {
    app-region: no-drag;
    -webkit-app-region: no-drag;
  }
  .win-btn {
    width: 28px;
    height: 28px;
    border: 0;
    border-radius: 12px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    color: #727b86;
    background: transparent;
    transition: transform 140ms cubic-bezier(.23, 1, .32, 1), background-color 140ms ease, color 140ms ease;
  }
  .win-btn:hover {
    color: #202832;
    background: rgba(255, 255, 255, 0.72);
  }
  .win-btn:active {
    transform: scale(0.96);
  }
  .win-btn svg {
    width: 11px;
    height: 11px;
    stroke: currentColor;
    stroke-width: 1.35;
    stroke-linecap: round;
    opacity: 1;
  }
  .win-btn.minimize {
    color: #727b86;
  }
  .win-btn.close {
    color: #e64f58;
  }
  .win-btn.close:hover {
    color: #b5202e;
    background: rgba(244, 91, 91, 0.15);
  }
  .main-content {
    position: relative;
    z-index: 2;
    padding: 0 40px 35px;
  }
  .update-status {
    margin-bottom: 25px;
    max-width: min(650px, 100%);
  }
  .title-group {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }
  .spinner {
    width: 22px;
    height: 22px;
    border: 2.5px solid rgba(255, 255, 255, 0.24);
    border-top-color: var(--text-main);
    border-radius: 50%;
    animation: spin 0.9s linear infinite;
    flex: 0 0 auto;
  }
  .err-dot {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #ffffff;
    color: #c73532;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 800;
    box-shadow: 0 5px 16px rgba(0, 0, 0, 0.2);
    flex: 0 0 auto;
  }
  .main-action-text {
    min-width: 0;
    color: var(--text-main);
    font-size: 24px;
    line-height: 1.2;
    font-weight: 620;
    letter-spacing: 0;
    text-shadow: 0 2px 10px rgba(0, 0, 0, 0.32);
  }
  .sub-action-text {
    color: var(--text-sub);
    font-size: 12px;
    font-weight: 480;
    letter-spacing: 1.2px;
    line-height: 1.45;
    margin: 0;
    max-width: min(650px, 100%);
    max-height: 54px;
    overflow: hidden;
    text-shadow: 0 1px 5px rgba(0, 0, 0, 0.28);
    white-space: pre-line;
  }
  .progress-container {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 12px;
    margin-bottom: 15px;
  }
  .progress-bar-bg {
    grid-column: 1;
    grid-row: 1;
    width: 100%;
    height: 5px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.2);
    overflow: hidden;
    box-shadow: inset 0 1px 1px rgba(0, 0, 0, 0.12);
    backdrop-filter: blur(8px);
  }
  .progress-bar-fill {
    width: 4%;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, #4facfe, #43d7f5);
    box-shadow: 0 0 10px rgba(67, 215, 245, 0.38);
    position: relative;
    overflow: hidden;
    transition: width 0.35s cubic-bezier(.23, 1, .32, 1), background-color 0.2s ease;
  }
  .progress-bar-fill::after {
    display: none;
  }
  .progress-bar-fill-error {
    background: linear-gradient(90deg, #ff5f57, #ffbd2e);
    box-shadow: 0 0 14px rgba(255, 95, 87, 0.46);
  }
  .progress-bar-fill-error::after {
    display: none;
  }
  .progress-percentage {
    grid-column: 2;
    grid-row: 1;
    min-width: 34px;
    color: var(--text-main);
    font-size: 12px;
    font-weight: 560;
    text-align: right;
    font-variant-numeric: tabular-nums;
    text-shadow: 0 1px 5px rgba(0, 0, 0, 0.28);
  }
  .uv-progress-container {
    display: none;
    margin-top: -3px;
    margin-bottom: 15px;
  }
  .uv-progress-container.is-visible {
    display: block;
  }
  .uv-progress-header {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 6px;
    color: var(--text-sub);
    font-size: 11px;
    font-variant-numeric: tabular-nums;
  }
  .uv-progress-detail {
    flex: 1 1 auto;
    min-width: 0;
    overflow: hidden;
    text-align: right;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .uv-progress-bar-bg {
    width: 100%;
    height: 4px;
    overflow: hidden;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.14);
  }
  .uv-progress-bar-fill {
    position: relative;
    width: 2%;
    height: 100%;
    overflow: hidden;
    border-radius: inherit;
    background: #55cda0;
    box-shadow: 0 0 8px rgba(85, 205, 160, 0.34);
    transition: width 0.4s cubic-bezier(.23, 1, .32, 1);
  }
  .uv-progress-bar-fill::after {
    display: none;
  }
  .footer-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    min-height: 28px;
    font-size: 12px;
  }
  .tip-text {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    max-width: 520px;
    color: var(--text-sub);
    background: rgba(15, 23, 42, 0.26);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 12px;
    padding: 7px 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-weight: 460;
    backdrop-filter: blur(12px) saturate(1.1);
  }
  .tip-text::before {
    content: "✦";
    color: var(--primary-color);
    font-size: 12px;
    line-height: 1;
    text-shadow: 0 0 10px rgba(79, 172, 254, 0.55);
    flex: 0 0 auto;
  }
  .footer-right {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
    flex: 0 0 auto;
  }
  .notice-text {
    color: var(--text-muted);
    white-space: nowrap;
    font-weight: 450;
  }
  .splash-actions {
    display: none;
  }
  .splash-actions-err {
    display: block;
  }
  .splash-log-button {
    min-height: 34px;
    border: 1px solid rgba(255, 255, 255, 0.78);
    border-radius: 12px;
    padding: 0 14px;
    color: #394451;
    background: rgba(250, 250, 247, 0.78);
    box-shadow: 0 4px 14px rgba(61, 79, 97, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.36);
    backdrop-filter: blur(14px) saturate(1.15);
    cursor: pointer;
    font-size: 12px;
    font-weight: 560;
    transition: transform 140ms cubic-bezier(.23, 1, .32, 1), background-color 140ms ease;
  }
  .splash-log-button:hover {
    background: rgba(255, 255, 255, 0.9);
  }
  .splash-log-button:active {
    transform: scale(0.97);
  }
  .splash-log-button:disabled {
    cursor: default;
    opacity: 0.65;
  }
  body.error-state .status-badge {
    background: rgba(255, 255, 255, 0.18);
    animation: none;
  }
  body.error-state .status-badge::before {
    background: #ff5f57;
    box-shadow: 0 0 12px rgba(255, 95, 87, 0.76);
  }
  body.error-state .tip-text {
    border-color: rgba(255, 189, 46, 0.42);
  }
  body.error-state .tip-text::before {
    color: #ffbd2e;
  }
  @media (max-width: 720px) {
    .top-bar {
      padding: 10px 16px;
    }
    .status-badge {
      max-width: 180px;
    }
    .main-content {
      padding: 0 28px 28px;
    }
    .main-action-text {
      font-size: 22px;
    }
  }
  @media (max-width: 560px), (max-height: 340px) {
    .top-right {
      gap: 12px;
    }
    .status-badge {
      display: none;
    }
    .footer-info {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }
    .footer-right {
      width: 100%;
      justify-content: space-between;
    }
    .tip-text {
      max-width: 100%;
    }
  }
  @media (max-height: 340px) {
    .main-content {
      padding-bottom: 24px;
    }
    .update-status {
      margin-bottom: 18px;
    }
    .sub-action-text {
      max-height: 36px;
    }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
</head>
<body>
  <div class="launcher-window">
    <video class="splash-background-video" autoplay muted loop playsinline preload="auto" aria-hidden="true">
      <source src="data:video/mp4;base64,$VIDEO_BG" type="video/mp4">
    </video>
    <div id="splash-drag-region" class="top-bar" data-tauri-drag-region>
      <div class="brand-zone">
        <span class="app-title">AzurPilot</span>
        <span class="app-version">v$LAUNCHER_VERSION</span>
      </div>
      <div class="top-right">
        <div id="badge" class="status-badge">
          <span id="badge-text">$I18N_INITIALIZING</span>
        </div>
        <div class="window-controls">
          <button id="window-minimize" class="win-btn minimize" type="button" aria-label="$I18N_MINIMIZE" title="$I18N_MINIMIZE">
            <svg viewBox="0 0 8 8" aria-hidden="true"><line x1="2" y1="4" x2="6" y2="4"></line></svg>
          </button>
          <button id="window-close" class="win-btn close" type="button" aria-label="$I18N_CLOSE" title="$I18N_CLOSE">
            <svg viewBox="0 0 8 8" aria-hidden="true"><line x1="2" y1="2" x2="6" y2="6"></line><line x1="6" y1="2" x2="2" y2="6"></line></svg>
          </button>
        </div>
      </div>
    </div>

    <div class="main-content">
      <div class="update-status">
        <div class="title-group">
          <div id="spinner" class="spinner"></div>
          <div id="error-dot" class="err-dot" style="display:none;">!</div>
          <h1 id="title" class="main-action-text">$I18N_STARTING</h1>
        </div>
        <p id="detail" class="sub-action-text">$I18N_WEBUI_INIT</p>
      </div>

      <div class="progress-container">
        <div id="progress-pct" class="progress-percentage">4%</div>
        <div class="progress-bar-bg">
          <div id="progress-fill" class="progress-bar-fill" style="width: 4%;"></div>
        </div>
      </div>

      <div id="uv-progress-container" class="uv-progress-container" aria-hidden="true">
        <div class="uv-progress-header">
          <span id="uv-progress-detail" class="uv-progress-detail"></span>
          <span id="uv-progress-pct">0%</span>
        </div>
        <div class="uv-progress-bar-bg">
          <div id="uv-progress-fill" class="uv-progress-bar-fill" style="width: 2%;"></div>
        </div>
      </div>

      <div class="footer-info">
        <div id="tip-text" class="tip-text">$I18N_DEFAULT_TIP</div>
        <div class="footer-right">
          <div id="progress-meta" class="notice-text">$I18N_PROGRESS_META</div>
          <div id="splash-actions" class="splash-actions">
            <button id="splash-log-button" class="splash-log-button" type="button">$I18N_DOWNLOAD_LOG</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const i18n = $I18N_JSON;
    const defaultTip = i18n.defaultTip;
    const invoke =
      (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
      || (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);
    const webviewDraggableRegionsEnabled = $NATIVE_TOUCH_DRAG;

    window.addEventListener('contextmenu', event => {
      event.preventDefault();
    }, { capture: true });

    function splitSubtitle(value) {
      const text = String(value || '').trim();
      if (!text) {
        return { status: i18n.loading, tip: defaultTip };
      }
      const match = text.match(/^(.*?)\s*\|\s*Tips[:：]\s*(.*)$/);
      if (!match) {
        return { status: text, tip: defaultTip };
      }
      return {
        status: match[1].trim() || i18n.loading,
        tip: match[2].trim() || defaultTip,
      };
    }

    function normalizeDetail(value) {
      const text = String(value || '').trim();
      return text || i18n.webuiInit;
    }

    window.__ALAS_SPLASH_UPDATE = function (payload) {
      const badge = document.getElementById('badge');
      const badgeText = document.getElementById('badge-text');
      const spinner = document.getElementById('spinner');
      const errorDot = document.getElementById('error-dot');
      const progressFill = document.getElementById('progress-fill');
      const progressPct = document.getElementById('progress-pct');
      const uvProgressContainer = document.getElementById('uv-progress-container');
      const uvProgressFill = document.getElementById('uv-progress-fill');
      const uvProgressPct = document.getElementById('uv-progress-pct');
      const uvProgressDetail = document.getElementById('uv-progress-detail');
      const progressMeta = document.getElementById('progress-meta');
      const splashActions = document.getElementById('splash-actions');
      const subtitle = splitSubtitle(payload.subtitle);

      badgeText.textContent = payload.is_error ? i18n.errorBadge : subtitle.status;
      document.getElementById('tip-text').textContent = subtitle.tip;
      document.getElementById('title').textContent = payload.title || i18n.starting;
      document.getElementById('detail').textContent = normalizeDetail(payload.detail);
      progressMeta.textContent = payload.is_error
        ? i18n.initStopped
        : i18n.progressMetaReady;

      const progress = Math.max(0, Math.min(100, Number(payload.progress || 0)));
      progressFill.style.width = progress + '%';
      progressPct.textContent = progress + '%';

      const uvState = payload.uv_progress;
      const hasUvProgress = !payload.is_error
        && uvState
        && Number.isFinite(Number(uvState.progress));
      uvProgressContainer.classList.toggle('is-visible', Boolean(hasUvProgress));
      uvProgressContainer.setAttribute('aria-hidden', String(!hasUvProgress));
      if (hasUvProgress) {
        const uvProgress = Math.max(0, Math.min(99, Number(uvState.progress)));
        uvProgressFill.style.width = uvProgress + '%';
        uvProgressPct.textContent = uvProgress + '%';
        uvProgressDetail.textContent = String(uvState.detail || '');
      }

      if (payload.is_error) {
        document.body.classList.add('error-state');
        badge.className = 'status-badge status-badge-err';
        spinner.style.display = 'none';
        errorDot.style.display = 'flex';
        progressFill.className = 'progress-bar-fill progress-bar-fill-error';
        splashActions.className = 'splash-actions splash-actions-err';
      } else {
        document.body.classList.remove('error-state');
        badge.className = 'status-badge';
        spinner.style.display = 'block';
        errorDot.style.display = 'none';
        progressFill.className = 'progress-bar-fill';
        splashActions.className = 'splash-actions';
      }
    };

    document.getElementById('window-minimize').addEventListener('click', event => {
      event.stopPropagation();
      if (typeof invoke === 'function') {
        invoke('window_minimize').catch(error => {
          console.error('Failed to minimize splash window', error);
        });
      }
    });

    document.getElementById('window-close').addEventListener('click', event => {
      event.stopPropagation();
      if (typeof invoke === 'function') {
        invoke('window_close').catch(error => {
          console.error('Failed to close splash window', error);
        });
      }
    });

    document.getElementById('splash-log-button').addEventListener('click', async () => {
      const button = document.getElementById('splash-log-button');
      const progressMeta = document.getElementById('progress-meta');
      button.disabled = true;
      progressMeta.textContent = i18n.preparingLog;
      try {
        if (typeof invoke !== 'function') {
          throw new Error('Tauri invoke is unavailable');
        }
        const filename = await invoke('download_today_launcher_log');
        progressMeta.textContent = i18n.logSavedPrefix + filename;
      } catch (error) {
        progressMeta.textContent = i18n.logFailed + (error && error.message ? error.message : error);
      } finally {
        button.disabled = false;
      }
    });

    window.__ALAS_SPLASH_READY = true;
  </script>
</body>
</html>"#
    .replace("$VIDEO_BG", video_bg_b64)
    .replace("$MI_SANS_FONT", mi_sans_font_b64)
    .replace("$LAUNCHER_VERSION", env!("CARGO_PKG_VERSION"))
    .replace("$I18N_JSON", &i18n_json)
    .replace("$NATIVE_TOUCH_DRAG", if cfg!(windows) { "true" } else { "false" })
    .replace("$I18N_INITIALIZING", &escape_html(t!("splash.initializing")))
    .replace("$I18N_MINIMIZE", &escape_html(t!("titlebar.minimize")))
    .replace("$I18N_CLOSE", &escape_html(t!("titlebar.close")))
    .replace("$I18N_STARTING", &escape_html(t!("splash.starting")))
    .replace("$I18N_WEBUI_INIT", &escape_html(t!("splash.webui_init")))
    .replace("$I18N_DEFAULT_TIP", &escape_html(t!("tips.17")))
    .replace("$I18N_PROGRESS_META", &escape_html(t!("splash.progress_meta_ready")))
    .replace("$I18N_DOWNLOAD_LOG", &escape_html(t!("splash.download_log")))
}

fn create_main_window(app: &tauri::AppHandle, port: u16) -> Result<WebviewWindow> {
    let main_config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == "main")
        .ok_or_else(|| anyhow!("Main window config not found"))?;

    let app_for_navigation = app.clone();
    let main_window = tauri::WebviewWindowBuilder::from_config(app, main_config)?
        .on_navigation(move |url| handle_backend_navigation(app_for_navigation.clone(), port, url))
        .on_page_load(page_load_injector)
		.general_autofill_enabled(false)
        .build()?;
    main_window.set_resizable(true)?;

    // Windows/Linux: remove native decorations for the main window as well.
    // Splash is configured as borderless in tauri.conf.json.
    #[cfg(not(target_os = "macos"))]
    {
        main_window.set_decorations(false)?;
    }

    Ok(main_window)
}

fn reveal_window(window: &WebviewWindow) -> tauri::Result<()> {
    if window.is_minimized()? {
        window.unminimize()?;
    }
    window.show()?;
    window.set_focus()?;
    Ok(())
}

#[derive(Copy, Clone, PartialEq)]
enum TrayMinimizeMode {Hide,Destroy}
fn minimize_main_window_to_tray(app: &tauri::AppHandle, mode: TrayMinimizeMode) {
    #[cfg(windows)]
    {
        if let Some(window) = app.get_webview_window("main") {
			if mode == TrayMinimizeMode::Destroy {
                info!("Destroying main window to release WebView resources while trayed");
                if let Err(e) = window.destroy() {
                    warn!("Failed to destroy main window for tray mode: {:?}", e);
                }
            } else {
                info!("Hiding main window (preserving page state) while trayed");
                if let Err(e) = window.hide() {
                    warn!("Failed to hide main window: {:?}", e);
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
    }

    #[cfg(target_os = "macos")]
    {
        set_macos_activation_policy(app, false);
    }
}

fn restore_main_window_from_any_thread(
    app: tauri::AppHandle,
    port: u16,
    recreating_main_window: Arc<AtomicBool>,
) {
    let app_for_restore = app.clone();
    if let Err(e) = app.run_on_main_thread(move || {
        restore_main_window_from_tray(&app_for_restore, port, recreating_main_window);
    }) {
        warn!("Failed to schedule main window restore: {:?}", e);
    }
}

fn restore_main_window_from_tray(
    app: &tauri::AppHandle,
    port: u16,
    recreating_main_window: Arc<AtomicBool>,
) {
    if let Some(window) = app.get_webview_window("main") {
        #[cfg(target_os = "macos")]
        set_macos_activation_policy(app, true);
        let _ = reveal_window(&window);
        return;
    }

    if recreating_main_window
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        debug!("Main window recreation already in progress");
        return;
    }

    let app_handle = app.clone();
    thread::spawn(move || {
        #[cfg(target_os = "macos")]
        set_macos_activation_policy(&app_handle, true);

        let result = (|| -> Result<()> {
            let window = create_main_window(&app_handle, port)?;
            navigate_backend_or_error(&window, port)?;
            reveal_window(&window)?;
            Ok(())
        })();

        recreating_main_window.store(false, Ordering::SeqCst);

        if let Err(e) = result {
            error!("Failed to recreate main window from tray: {:?}", e);
        }
    });
}

fn toggle_main_window_visibility(
    app: &tauri::AppHandle,
    port: u16,
    recreating_main_window: Arc<AtomicBool>,
) {
    if let Some(window) = app.get_webview_window("main") {
        let is_visible = window.is_visible().unwrap_or(false);
        let is_minimized = window.is_minimized().unwrap_or(false);
        if is_visible && !is_minimized {
            minimize_main_window_to_tray(app, TrayMinimizeMode::Hide);
        } else {
            restore_main_window_from_tray(app, port, recreating_main_window);
        }
    } else {
        restore_main_window_from_tray(app, port, recreating_main_window);
    }
}

fn main_window_titlebar_injection_script() -> String {
    #[cfg(target_os = "macos")]
    {
        String::new()
    }
    #[cfg(not(target_os = "macos"))]
    {
        let i18n = serde_json::json!({
            "hideLabel": t!("titlebar.minimize_to_tray"),
            "minimizeLabel": t!("titlebar.minimize_window"),
            "minimizeTitle": t!("titlebar.minimize"),
            "maximizeLabel": t!("titlebar.maximize_restore_window"),
            "maximizeTitle": t!("titlebar.maximize"),
            "closeLabel": t!("titlebar.close_window"),
            "closeTitle": t!("titlebar.close"),
            "restoreTitle": t!("titlebar.restore"),
            "maximizeActionTitle": t!("titlebar.maximize_action"),
            "restoreLabel": t!("titlebar.restore_window"),
            "maximizeLabelText": t!("titlebar.maximize_window"),
        });
        let i18n_json = serde_json::to_string(&i18n).unwrap();
        let mut s = String::with_capacity(4096);
        s.push_str("const i18n = ");
        s.push_str(&i18n_json);
        s.push_str(r#";
        const invoke =
            (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)
            || (window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke);
        if (typeof invoke !== 'function') {
            return;
        }
        const ensureTitlebar = () => {
            if (!document.body || document.getElementById('alas-launcher-titlebar')) {
                return;
            }
            if (!document.getElementById('alas-launcher-titlebar-style')) {
                const style = document.createElement('style');
                style.id = 'alas-launcher-titlebar-style';
                style.textContent = ':root{--alas-titlebar-height:37px}#alas-launcher-titlebar{position:fixed;top:0;left:0;right:0;height:var(--alas-titlebar-height);z-index:2147483647;user-select:none;pointer-events:none;background:transparent}#alas-launcher-titlebar *{box-sizing:border-box}.alas-titlebar-drag-segment{position:absolute;top:0;bottom:0;pointer-events:auto;background:transparent;touch-action:none;app-region:drag;-webkit-app-region:drag}.header-icon,.header-icon *{app-region:no-drag;-webkit-app-region:no-drag}.header-icon{display:flex;align-items:center;gap:0;position:absolute;top:0;right:0;height:37px;margin:0;padding:0;pointer-events:auto;background:transparent;border:none;box-shadow:none}.icon{width:36px;height:37px;margin:0;padding:0;border:none;background:transparent;cursor:pointer;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;transition:color 140ms ease,filter 140ms ease,transform 100ms ease}.icon:active{transform:scale(.92)}.icon svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round}.icon-hide{color:#a855f7}.icon-hide:hover{color:#7e22ce;filter:drop-shadow(0 0 5px #a855f7)}.icon-minimize{color:#0284c7}.icon-minimize:hover{color:#0369a1;filter:drop-shadow(0 0 5px #0284c7)}.icon-maximize{color:#10b981}.icon-maximize:hover{color:#047857;filter:drop-shadow(0 0 5px #10b981)}.icon-close{color:#ef4444}.icon-close:hover{color:#b91c1c;filter:drop-shadow(0 0 5px #ef4444)}';
                document.head.appendChild(style);
            }
            const titlebar = document.createElement('div');
            titlebar.id = 'alas-launcher-titlebar';
            titlebar.innerHTML = '<div class="alas-titlebar-drag-segment" data-tauri-drag-region style="left:110px;width:50px"></div><div class="alas-titlebar-drag-segment" data-tauri-drag-region style="left:380px;right:144px"></div><div class="header-icon"><button type="button" class="icon icon-hide" data-action="hide" aria-label="'+i18n.hideLabel+'" title="'+i18n.hideLabel+'"><svg viewBox="0 0 10 10"><line x1="2.5" y1="2.5" x2="7.5" y2="7.5"/><polyline points="4,7.5 7.5,7.5 7.5,4"/></svg></button><button type="button" class="icon icon-minimize" data-action="minimize" aria-label="'+i18n.minimizeLabel+'" title="'+i18n.minimizeTitle+'"><svg viewBox="0 0 10 10"><line x1="1.5" y1="5" x2="8.5" y2="5"/></svg></button><button type="button" class="icon icon-maximize" data-action="maximize" aria-label="'+i18n.maximizeLabel+'" title="'+i18n.maximizeTitle+'"><svg viewBox="0 0 10 10" class="svg-restore" style="display:none"><path d="M3.5 1.5h5v5"/><rect x="1.5" y="3.5" width="5" height="5"/></svg><svg viewBox="0 0 10 10" class="svg-maximize"><rect x="1.5" y="1.5" width="7" height="7"/></svg></button><button type="button" class="icon icon-close" data-action="close" aria-label="'+i18n.closeLabel+'" title="'+i18n.closeTitle+'"><svg viewBox="0 0 10 10"><line x1="2" y1="2" x2="8" y2="8"/><line x1="8" y1="2" x2="2" y2="8"/></svg></button></div>';
            document.body.dataset.alasCustomTitlebar = 'true';
            document.body.prepend(titlebar);
            const maximizeButton = titlebar.querySelector('[data-action="maximize"]');

            const syncMaximizeState = async () => {
                if (!maximizeButton) return;
                try {
                    const maximized = await invoke('window_is_maximized');
                    maximizeButton.dataset.maximized = maximized ? 'true' : 'false';
                    maximizeButton.title = maximized ? i18n.restoreTitle : i18n.maximizeActionTitle;
                    maximizeButton.setAttribute('aria-label', maximized ? i18n.restoreLabel : i18n.maximizeLabelText);
                    maximizeButton.querySelector('.svg-maximize').style.display = maximized ? 'none' : '';
                    maximizeButton.querySelector('.svg-restore').style.display = maximized ? '' : 'none';
                } catch (e) {
                    console.error('Failed to sync maximize state', e);
                }
            };
            titlebar.querySelectorAll('button[data-action]').forEach(button => {
                button.addEventListener('click', async event => {
                    event.stopPropagation();
                    try {
                        switch (button.dataset.action) {
                            case 'hide': await invoke('window_hide'); break;
                            case 'minimize': await invoke('window_minimize'); break;
                            case 'maximize': await invoke('window_toggle_maximize'); await syncMaximizeState(); break;
                            case 'close': await invoke('window_close'); break;
                        }
                    } catch (error) {
                        console.error('Failed to handle ' + button.dataset.action + ' window action', error);
                    }
                });
            });
            window.addEventListener('resize', () => { void syncMaximizeState(); });
            void syncMaximizeState();
        };
        ensureTitlebar();
        if (!document.body) {
            window.addEventListener('DOMContentLoaded', ensureTitlebar, { once: true });
        }
        "#);
        s
    }
}

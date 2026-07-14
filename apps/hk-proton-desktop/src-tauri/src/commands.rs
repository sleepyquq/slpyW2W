use std::sync::{Arc, Mutex};

use tauri::State;

use crate::{
    dto::{AppStatusDto, CommandErrorDto, NodeDelayReportDto, UiMode, UiProfileRole},
    error::{ServiceError, ServiceResult},
    service::DesktopService,
};

type CommandResult = Result<AppStatusDto, CommandErrorDto>;
pub type SharedDesktopService = Arc<Mutex<DesktopService>>;

/// 文件校验、进程启动、controller 等待和清理都可能耗时数秒。
/// 所有服务调用统一进入阻塞线程池，避免占住 Tauri 窗口事件线程导致“未响应”。
async fn run_service_command<T, F>(
    service: State<'_, SharedDesktopService>,
    operation: F,
) -> Result<T, CommandErrorDto>
where
    T: Send + 'static,
    F: FnOnce(&mut DesktopService) -> ServiceResult<T> + Send + 'static,
{
    let service = Arc::clone(service.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let mut service = service
            .lock()
            .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
        operation(&mut service).map_err(CommandErrorDto::from)
    })
    .await
    .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?
}

#[tauri::command]
pub async fn get_app_status(service: State<'_, SharedDesktopService>) -> CommandResult {
    run_service_command(service, DesktopService::get_app_status).await
}

#[tauri::command]
pub async fn activate_pyxis_member(
    member: String,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    #[cfg(feature = "pyxis")]
    {
        return run_service_command(service, move |service| {
            service.activate_pyxis_member(member)
        })
        .await;
    }
    #[cfg(not(feature = "pyxis"))]
    {
        let _ = (member, service);
        Err(CommandErrorDto::from(ServiceError::InvalidSelection))
    }
}

#[tauri::command]
pub async fn import_config_files(
    role: UiProfileRole,
    paths: Vec<std::path::PathBuf>,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    run_service_command(service, move |service| {
        service.import_config_files(role, paths)
    })
    .await
}

#[tauri::command]
pub async fn delete_profile(
    role: UiProfileRole,
    profile_id: String,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    run_service_command(service, move |service| {
        service.delete_profile(role, profile_id)
    })
    .await
}

#[tauri::command]
pub async fn update_selection(
    mode: UiMode,
    selected_first_hop: String,
    selected_proton: Option<String>,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    run_service_command(service, move |service| {
        service.update_selection(mode, selected_first_hop, selected_proton)
    })
    .await
}

#[tauri::command]
pub async fn validate_current(service: State<'_, SharedDesktopService>) -> CommandResult {
    run_service_command(service, DesktopService::validate_current).await
}

#[tauri::command]
pub async fn connect(service: State<'_, SharedDesktopService>) -> CommandResult {
    run_service_command(service, DesktopService::connect).await
}

#[tauri::command]
pub async fn disconnect(service: State<'_, SharedDesktopService>) -> CommandResult {
    run_service_command(service, DesktopService::disconnect).await
}

#[tauri::command]
pub async fn poll_status(service: State<'_, SharedDesktopService>) -> CommandResult {
    run_service_command(service, DesktopService::poll_status).await
}

#[tauri::command]
pub async fn measure_node_delays(
    service: State<'_, SharedDesktopService>,
) -> Result<NodeDelayReportDto, CommandErrorDto> {
    run_service_command(service, DesktopService::measure_node_delays).await
}

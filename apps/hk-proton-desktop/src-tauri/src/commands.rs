use std::sync::{Arc, Mutex};

use tauri::State;

use crate::{
    dto::{AppStatusDto, CommandErrorDto, NodeDelayReportDto, UiMode, UiProfileRole},
    error::ServiceError,
    service::DesktopService,
};

type CommandResult = Result<AppStatusDto, CommandErrorDto>;
pub type SharedDesktopService = Arc<Mutex<DesktopService>>;

#[tauri::command]
pub fn get_app_status(service: State<'_, SharedDesktopService>) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.get_app_status().map_err(Into::into)
}

#[tauri::command]
pub fn import_config_files(
    role: UiProfileRole,
    paths: Vec<std::path::PathBuf>,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.import_config_files(role, paths).map_err(Into::into)
}

#[tauri::command]
pub fn delete_profile(
    role: UiProfileRole,
    profile_id: String,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.delete_profile(role, profile_id).map_err(Into::into)
}

#[tauri::command]
pub fn update_selection(
    mode: UiMode,
    selected_first_hop: String,
    selected_proton: Option<String>,
    service: State<'_, SharedDesktopService>,
) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service
        .update_selection(mode, selected_first_hop, selected_proton)
        .map_err(Into::into)
}

#[tauri::command]
pub fn validate_current(service: State<'_, SharedDesktopService>) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.validate_current().map_err(Into::into)
}

#[tauri::command]
pub fn connect(service: State<'_, SharedDesktopService>) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.connect().map_err(Into::into)
}

#[tauri::command]
pub fn disconnect(service: State<'_, SharedDesktopService>) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.disconnect().map_err(Into::into)
}

#[tauri::command]
pub fn poll_status(service: State<'_, SharedDesktopService>) -> CommandResult {
    let mut service = service
        .lock()
        .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
    service.poll_status().map_err(Into::into)
}

#[tauri::command]
pub async fn measure_node_delays(
    service: State<'_, SharedDesktopService>,
) -> Result<NodeDelayReportDto, CommandErrorDto> {
    let service = Arc::clone(service.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let mut service = service
            .lock()
            .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?;
        service.measure_node_delays().map_err(Into::into)
    })
    .await
    .map_err(|_| CommandErrorDto::from(ServiceError::Internal))?
}

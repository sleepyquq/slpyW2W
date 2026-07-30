use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_updater::{Error as UpdaterError, Update, UpdaterExt};

/// 返回给前端的更新信息不包含下载地址和签名，避免把发布实现细节暴露到界面层。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub version: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub configured: bool,
    pub update: Option<UpdateInfo>,
}

fn info(update: &Update) -> UpdateInfo {
    UpdateInfo {
        current_version: update.current_version.clone(),
        version: update.version.clone(),
        notes: update.body.clone(),
    }
}

fn update_error(error: UpdaterError) -> String {
    // IPC 不返回端点、下载地址或签名等细节，只给出稳定的用户提示。
    match error {
        UpdaterError::EmptyEndpoints => "更新服务尚未配置。".to_string(),
        _ => "更新服务暂时不可用。".to_string(),
    }
}

#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<UpdateCheckResult, String> {
    let updater = match app.updater_builder().build() {
        Ok(updater) => updater,
        Err(UpdaterError::EmptyEndpoints) => {
            return Ok(UpdateCheckResult {
                configured: false,
                update: None,
            });
        }
        Err(error) => return Err(update_error(error)),
    };

    let update = updater.check().await.map_err(update_error)?;
    Ok(UpdateCheckResult {
        configured: true,
        update: update.as_ref().map(info),
    })
}

#[tauri::command]
pub async fn install_latest_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = match app.updater_builder().build() {
        Ok(updater) => updater,
        Err(error) => return Err(update_error(error)),
    };
    let Some(update) = updater.check().await.map_err(update_error)? else {
        return Ok(None);
    };

    let update_info = info(&update);
    // Windows 安装器会在安装前自动退出当前程序；下载过程中的进度不写入日志，
    // 避免将发布服务器信息带入用户日志。
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(update_error)?;

    Ok(Some(update_info))
}

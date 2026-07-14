use std::{
    fs::{File, OpenOptions},
    mem::size_of,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    ptr::null,
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Storage::FileSystem::FILE_SHARE_READ,
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::CREATE_NO_WINDOW,
    },
};

use crate::{
    CoreExit, CoreLaunchSpec, ManagerError, OfflineLaunchPlan, ProcessDriver, Result,
    TrustedMihomoExecutable, process::sealed::Sealed,
};

/// 会改变 Mihomo 启动语义或执行外部命令的环境变量一律不继承。
const REMOVED_MIHOMO_ENVIRONMENT: &[&str] = &[
    "CLASH_HOME_DIR",
    "CLASH_CONFIG_FILE",
    "CLASH_CONFIG_STRING",
    "CLASH_AGE_SECRET_KEY",
    "CLASH_OVERRIDE_EXTERNAL_UI_DIR",
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS",
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX",
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE",
    "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK",
    "CLASH_OVERRIDE_SECRET",
    "CLASH_POST_UP",
    "CLASH_POST_DOWN",
    "SAFE_PATHS",
    "SKIP_SAFE_PATH_CHECK",
];
const STATIC_VALIDATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Windows 下受控的 Mihomo 子进程 driver。
///
/// 它不查询或接管任何现有 PID；所有停止操作都只针对 `Command::spawn` 返回并由
/// `WindowsMihomoHandle` 持有的 `Child`。stdout/stderr 直接丢弃，避免运行时配置或
/// 上游凭据进入应用日志。
#[derive(Default)]
pub struct WindowsMihomoDriver {
    _private: (),
}

impl WindowsMihomoDriver {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct WindowsMihomoHandle {
    child: Child,
    // 进程属于这个 kill-on-close Job；GUI 崩溃时 Windows 会关闭句柄并清理成员进程。
    _job: OwnedJob,
    // 保持只读、禁止写入/删除共享的句柄，阻止运行期间替换已固定 SHA 的文件。
    _executable_guard: File,
    _config_guard: File,
    finished: bool,
}

impl Drop for WindowsMihomoHandle {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(_)) => self.finished = true,
            Ok(None) => {
                // Drop 无法报告错误；尽力终止且只操作这个自有 Child handle。
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.finished = true;
            }
            Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.finished = true;
            }
        }
    }
}

impl Sealed for WindowsMihomoDriver {}

impl ProcessDriver for WindowsMihomoDriver {
    type Handle = WindowsMihomoHandle;

    fn spawn(&mut self, spec: &CoreLaunchSpec) -> Result<Self::Handle> {
        // 先取得禁止写入/删除共享的只读句柄，再重新校验路径和 SHA，缩小 TOCTOU 窗口。
        let executable_guard = open_immutable_guard(spec.executable())?;
        let config_guard = open_immutable_guard(spec.config_file())?;
        spec.validate_for_spawn()?;

        let job = OwnedJob::new_kill_on_close()?;
        let mut command = build_live_command(spec);
        let mut child = command.spawn().map_err(|_| ManagerError::Process)?;
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(WindowsMihomoHandle {
            child,
            _job: job,
            _executable_guard: executable_guard,
            _config_guard: config_guard,
            finished: false,
        })
    }

    fn pid(&self, handle: &Self::Handle) -> u32 {
        handle.child.id()
    }

    fn try_wait(&mut self, handle: &mut Self::Handle) -> Result<Option<CoreExit>> {
        let status = handle.child.try_wait().map_err(|_| ManagerError::Process)?;
        Ok(status.map(|status| {
            handle.finished = true;
            CoreExit {
                code: status.code(),
            }
        }))
    }

    fn stop_owned(&mut self, handle: &mut Self::Handle) -> Result<CoreExit> {
        if let Some(status) = handle.child.try_wait().map_err(|_| ManagerError::Process)? {
            handle.finished = true;
            return Ok(CoreExit {
                code: status.code(),
            });
        }

        handle.child.kill().map_err(|_| ManagerError::Process)?;
        let status = handle.child.wait().map_err(|_| ManagerError::Process)?;
        handle.finished = true;
        Ok(CoreExit {
            code: status.code(),
        })
    }
}

/// 使用固定的 `-t -d <home> -f <config>` 合同调用已钉住版本的 Mihomo 做静态校验。
///
/// 该函数不会开启 live session；配置和可执行文件在运行前后都由只读句柄固定，输出被
/// 丢弃，只有明确的退出码 0 才视为通过。
pub fn validate_mihomo_config(
    trusted_executable: &TrustedMihomoExecutable,
    private_data_root: impl Into<PathBuf>,
    runtime_home: impl Into<PathBuf>,
    config_file: impl Into<PathBuf>,
    plan: &OfflineLaunchPlan,
) -> Result<()> {
    let spec = CoreLaunchSpec::static_validation(
        trusted_executable,
        private_data_root,
        runtime_home,
        config_file,
        plan,
    )?;
    run_static_validation(&spec)
}

/// 在 generation 提交前，对调用层持有的候选 YAML 做受控 Mihomo 静态校验。
///
/// 候选内存值、声明哈希、落地文件和网络投影必须一致。该函数与已提交 generation 无关，
/// 且只会用固定 `-t -d <home> -f <config>` 参数启动已钉住的 Mihomo；不会创建 live session。
pub fn validate_candidate_mihomo_config(
    trusted_executable: &TrustedMihomoExecutable,
    private_data_root: impl Into<PathBuf>,
    runtime_home: impl Into<PathBuf>,
    config_file: impl Into<PathBuf>,
    candidate_yaml: &hk_proton_core::SecretValue,
    expected_candidate_sha256: &str,
    expected_projection: &crate::NetworkEffectProjection,
) -> Result<()> {
    let spec = CoreLaunchSpec::candidate_static_validation(
        trusted_executable,
        private_data_root,
        runtime_home,
        config_file,
        candidate_yaml,
        expected_candidate_sha256,
        expected_projection,
    )?;
    run_static_validation(&spec)
}

fn run_static_validation(spec: &CoreLaunchSpec) -> Result<()> {
    let _executable_guard = open_immutable_guard(spec.executable())?;
    let _config_guard = open_immutable_guard(spec.config_file())?;
    spec.validate_for_static_validation()?;

    let job = OwnedJob::new_kill_on_close()?;
    let mut command = build_validation_command(spec);
    let mut child = command.spawn().map_err(|_| ManagerError::Process)?;
    if let Err(error) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let deadline = Instant::now() + STATIC_VALIDATION_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| ManagerError::Process)? {
            return require_successful_validation_exit(status.code());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ManagerError::MihomoConfigValidationFailed);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn require_successful_validation_exit(code: Option<i32>) -> Result<()> {
    (code == Some(0))
        .then_some(())
        .ok_or(ManagerError::MihomoConfigValidationFailed)
}

struct OwnedJob(HANDLE);

// SAFETY: Windows 内核 HANDLE 可在线程间传递；所有权仍唯一并只由 Drop 关闭一次。
unsafe impl Send for OwnedJob {}

impl OwnedJob {
    fn new_kill_on_close() -> Result<Self> {
        // SAFETY: 传入空安全属性和空名称，创建当前进程私有的 Job Object。
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(ManagerError::Process);
        }
        let job = Self(handle);
        let limits = kill_on_job_close_limits();
        // SAFETY: `limits` 的类型、长度和信息类严格匹配，且 `job` 在调用期间有效。
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(ManagerError::Process);
        }
        Ok(job)
    }

    fn assign(&self, child: &Child) -> Result<()> {
        // SAFETY: 两个句柄在调用期间都有效；Child 仍由 Rust 所有，Job 只建立成员关系。
        let assigned = unsafe {
            AssignProcessToJobObject(self.0, child.as_raw_handle().cast::<std::ffi::c_void>())
        };
        if assigned == 0 {
            return Err(ManagerError::Process);
        }
        Ok(())
    }
}

impl Drop for OwnedJob {
    fn drop(&mut self) {
        // SAFETY: 构造函数已排除空句柄，句柄只由这个所有者关闭一次。
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn kill_on_job_close_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits
}

fn open_immutable_guard(path: &std::path::Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(ManagerError::from)
}

fn build_live_command(spec: &CoreLaunchSpec) -> Command {
    build_command(spec, spec.command_arguments())
}

fn build_validation_command(spec: &CoreLaunchSpec) -> Command {
    build_command(spec, spec.validation_arguments())
}

fn build_command<const N: usize>(
    spec: &CoreLaunchSpec,
    arguments: [std::ffi::OsString; N],
) -> Command {
    let mut command = Command::new(spec.executable());
    command
        .args(arguments)
        .current_dir(spec.runtime_home())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    for variable in REMOVED_MIHOMO_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::*;
    use crate::{LiveLaunchAuthorization, process::LaunchMode};

    #[test]
    fn command_contract_has_only_fixed_home_and_config_arguments() {
        let spec = CoreLaunchSpec {
            executable: PathBuf::from(r"C:\ProgramData\HK-Proton\mihomo.exe"),
            expected_executable_sha256: "0".repeat(64),
            private_data_root: PathBuf::from(r"C:\ProgramData\HK-Proton"),
            runtime_home: PathBuf::from(r"C:\ProgramData\HK-Proton\runtime"),
            config_file: PathBuf::from(r"C:\ProgramData\HK-Proton\runtime\config.yaml"),
            expected_config_sha256: "1".repeat(64),
            mode: LaunchMode::Live(LiveLaunchAuthorization {
                preflight: crate::LivePreflightApproval {
                    revision: 1,
                    runtime_plaintext_sha256: "1".repeat(64),
                    network_effects: crate::NetworkEffectProjection {
                        tun_enabled: false,
                        allow_lan: false,
                        bind_address: "127.0.0.1".to_owned(),
                        mode: "rule".to_owned(),
                        mixed_port: 17890,
                        external_controller: "127.0.0.1:19090".parse().unwrap(),
                        dns_enabled: true,
                        dns_listener: "127.0.0.1:1053".parse().unwrap(),
                    },
                },
                tun_authorized: false,
            }),
        };

        let command = build_live_command(&spec);
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                OsString::from("-d"),
                spec.runtime_home().as_os_str().to_owned(),
                OsString::from("-f"),
                spec.config_file().as_os_str().to_owned(),
            ]
        );
        let removed = command
            .get_envs()
            .filter_map(|(name, value)| value.is_none().then_some(name))
            .collect::<Vec<_>>();
        assert!(REMOVED_MIHOMO_ENVIRONMENT.iter().all(|expected| {
            removed
                .iter()
                .any(|actual| actual.eq_ignore_ascii_case(expected))
        }));

        let validation = build_validation_command(&spec);
        assert_eq!(
            validation
                .get_args()
                .map(OsString::from)
                .collect::<Vec<_>>(),
            vec![
                OsString::from("-t"),
                OsString::from("-d"),
                spec.runtime_home().as_os_str().to_owned(),
                OsString::from("-f"),
                spec.config_file().as_os_str().to_owned(),
            ]
        );
        let validation_removed = validation
            .get_envs()
            .filter_map(|(name, value)| value.is_none().then_some(name))
            .collect::<Vec<_>>();
        assert!(REMOVED_MIHOMO_ENVIRONMENT.iter().all(|expected| {
            validation_removed
                .iter()
                .any(|actual| actual.eq_ignore_ascii_case(expected))
        }));
    }

    #[test]
    fn job_contract_is_kill_on_close_and_handle_is_sendable() {
        fn assert_send<T: Send>() {}

        let limits = kill_on_job_close_limits();
        assert_eq!(
            limits.BasicLimitInformation.LimitFlags,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        );
        assert_send::<WindowsMihomoHandle>();
    }

    #[test]
    fn static_validation_accepts_only_an_explicit_zero_exit_code() {
        assert!(require_successful_validation_exit(Some(0)).is_ok());
        assert!(matches!(
            require_successful_validation_exit(Some(1)),
            Err(ManagerError::MihomoConfigValidationFailed)
        ));
        assert!(matches!(
            require_successful_validation_exit(None),
            Err(ManagerError::MihomoConfigValidationFailed)
        ));
    }
}

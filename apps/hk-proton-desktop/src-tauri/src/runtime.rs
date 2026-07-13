use hk_proton_core::SecretValue;

use crate::dto::{BlockerDto, RuntimeStateDto};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeView {
    pub state: RuntimeStateDto,
    pub can_connect: bool,
    pub blocker: Option<BlockerDto>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDelayTarget {
    pub profile_id: String,
    pub proxy_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDelayMeasurement {
    pub profile_id: String,
    pub delay_ms: Option<u32>,
}

/// Tauri 服务与未来 live manager 之间唯一的运行时接缝。
///
/// 当前实现有意 fail closed；替换实现后，只有这里可以采集冲突快照、启动自有进程或轮询 API。
pub trait RuntimeBackend: Send {
    fn is_active(&self) -> bool;
    /// 在状态提交前校验候选运行配置；实现不得启动 live session。
    fn validate_candidate(&mut self, yaml: &SecretValue) -> Result<(), ()>;
    fn connect(&mut self, revision: u64) -> RuntimeView;
    fn disconnect(&mut self) -> RuntimeView;
    fn poll(&mut self) -> RuntimeView;
    fn configuration_changed(&mut self) -> RuntimeView;
    /// 测量节点延迟；未连接实现只能启动关闭 TUN、仅监听 loopback 的自有临时探测会话。
    fn measure_delays(
        &mut self,
        _targets: &[NodeDelayTarget],
    ) -> Result<Vec<NodeDelayMeasurement>, ()> {
        Err(())
    }
}

#[cfg(test)]
pub struct FailClosedRuntime {
    view: RuntimeView,
}

#[cfg(test)]
impl FailClosedRuntime {
    pub fn new() -> Self {
        Self {
            view: disconnected_view("配置已就绪。"),
        }
    }

    pub fn reset_after_config_change(&mut self) {
        self.view = disconnected_view("配置已保存并通过离线验证。");
    }
}

#[cfg(test)]
impl RuntimeBackend for FailClosedRuntime {
    fn is_active(&self) -> bool {
        false
    }

    fn validate_candidate(&mut self, yaml: &SecretValue) -> Result<(), ()> {
        hk_proton_core::validate_rendered_profile(yaml.expose_secret())
            .map(|_| ())
            .map_err(|_| ())
    }

    fn connect(&mut self, _revision: u64) -> RuntimeView {
        // 未接入 live 冲突快照与自有进程会话前，不得把“有配置”误当成“可以启动”。
        self.view = RuntimeView {
            state: RuntimeStateDto::Blocked,
            can_connect: false,
            blocker: Some(BlockerDto::LivePreflightRequired),
            message: "连接前检查尚未完成，未启动连接。".to_owned(),
        };
        self.view.clone()
    }

    fn disconnect(&mut self) -> RuntimeView {
        self.view = disconnected_view("当前没有由 slpyW2W 启动的连接。");
        self.view.clone()
    }

    fn poll(&mut self) -> RuntimeView {
        self.view.clone()
    }

    fn configuration_changed(&mut self) -> RuntimeView {
        self.reset_after_config_change();
        self.view.clone()
    }

    fn measure_delays(
        &mut self,
        targets: &[NodeDelayTarget],
    ) -> Result<Vec<NodeDelayMeasurement>, ()> {
        Ok(targets
            .iter()
            .map(|target| NodeDelayMeasurement {
                profile_id: target.profile_id.clone(),
                delay_ms: Some(42),
            })
            .collect())
    }
}

#[cfg(test)]
fn disconnected_view(message: &str) -> RuntimeView {
    RuntimeView {
        state: RuntimeStateDto::Disconnected,
        can_connect: false,
        blocker: Some(BlockerDto::LivePreflightRequired),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_runtime_never_claims_it_can_connect() {
        let mut runtime = FailClosedRuntime::new();
        let blocked = runtime.connect(3);
        assert_eq!(blocked.state, RuntimeStateDto::Blocked);
        assert!(!blocked.can_connect);
        assert_eq!(blocked.blocker, Some(BlockerDto::LivePreflightRequired));

        let stopped = runtime.disconnect();
        assert_eq!(stopped.state, RuntimeStateDto::Disconnected);
        assert!(!stopped.can_connect);
    }
}

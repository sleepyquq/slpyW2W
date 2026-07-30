import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check } from "@phosphor-icons/react/Check";
import { DotsThreeVertical } from "@phosphor-icons/react/DotsThreeVertical";
import { Lightning } from "@phosphor-icons/react/Lightning";
import { Trash } from "@phosphor-icons/react/Trash";
import { UploadSimple } from "@phosphor-icons/react/UploadSimple";
import { useAppController } from "./useAppController.js";

const CONNECTED_STATES = new Set(["connected", "running", "manual-verification-required"]);
const BUSY_STATES = new Set(["starting", "connecting", "stopping", "disconnecting"]);

function selectedName(profiles, selectedId, fallback = "未导入") {
  return profiles.find((profile) => profile.id === selectedId)?.name ?? fallback;
}

function delayView(delays, profileId, testing) {
  if (testing) return { label: "测速中", tone: "testing" };
  if (!Object.prototype.hasOwnProperty.call(delays, profileId)) {
    return { label: "—", tone: "empty" };
  }
  const delay = delays[profileId];
  if (!Number.isFinite(delay)) return { label: "超时", tone: "timeout" };
  if (delay <= 120) return { label: `${delay} ms`, tone: "fast" };
  if (delay <= 250) return { label: `${delay} ms`, tone: "medium" };
  return { label: `${delay} ms`, tone: "slow" };
}

function connectionView(status, pendingAction) {
  if (pendingAction === "connect" || ["starting", "connecting"].includes(status.runtimeState)) {
    return { label: "连接中", connected: false, transitioning: true };
  }
  if (pendingAction === "disconnect" || ["stopping", "disconnecting"].includes(status.runtimeState)) {
    return { label: "断开中", connected: true, transitioning: true };
  }
  if (CONNECTED_STATES.has(status.runtimeState)) {
    return { label: "已连接", connected: true, transitioning: false };
  }
  return { label: "连接", connected: false, transitioning: false };
}

function useDismissableLayer(open, onClose, floatingRef = null) {
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event) => {
      if (
        !ref.current?.contains(event.target)
        && !floatingRef?.current?.contains(event.target)
      ) {
        onClose();
      }
    };
    const onKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [floatingRef, open, onClose]);

  return ref;
}

function ConnectionControl({ view, disabled, onConnect, onDisconnect }) {
  return (
    <section className="connection-panel" aria-label="连接控制">
      <div className={`connection-orbit${view.connected ? " is-connected" : ""}`}>
        {view.connected ? (
          <span className="ripple-layer" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
        ) : null}
        <button
          className="connection-circle"
          type="button"
          disabled={disabled}
          aria-label={view.connected && !view.transitioning ? "断开连接" : view.label}
          onClick={view.connected ? onDisconnect : onConnect}
        >
          <span className="circle-default-label">{view.label}</span>
          {view.connected && !view.transitioning ? (
            <span className="circle-hover-label">断开连接</span>
          ) : null}
        </button>
      </div>
    </section>
  );
}

function ModeBar({ mode, disabled, canEnterForward, testing, onRequestMode, onTest }) {
  return (
    <div className="mode-bar">
      <div className={`mode-switch${mode === "double" ? " is-double" : ""}`} aria-label="连接模式">
        <button
          className={mode === "single" ? "is-selected" : ""}
          type="button"
          disabled={disabled}
          aria-pressed={mode === "single"}
          onClick={() => onRequestMode("single")}
        >
          直连
        </button>
        <button
          className={mode === "double" ? "is-selected" : ""}
          type="button"
          disabled={disabled || !canEnterForward}
          aria-pressed={mode === "double"}
          onClick={() => onRequestMode("double")}
        >
          转发
        </button>
      </div>
      <button
        className={`speed-test-button${testing ? " is-testing" : ""}`}
        type="button"
        disabled={testing}
        aria-label="测试节点延迟"
        title="测试节点延迟"
        onClick={onTest}
      >
        <Lightning aria-hidden="true" size={20} weight={testing ? "fill" : "regular"} />
      </button>
    </div>
  );
}

function NodeSelector({ label, profiles, value, delays, testingIds, disabled, selectionDisabled, onSelect }) {
  const [open, setOpen] = useState(false);
  const [floatingStyle, setFloatingStyle] = useState(null);
  const triggerRef = useRef(null);
  const optionsRef = useRef(null);
  const sortedProfiles = useMemo(
    () =>
      [...profiles].sort((left, right) =>
        left.name.localeCompare(right.name, "en", { numeric: true, sensitivity: "base" }),
      ),
    [profiles],
  );
  const close = useCallback(() => {
    setOpen(false);
    setFloatingStyle(null);
  }, []);
  const rootRef = useDismissableLayer(open, close, optionsRef);
  const currentName = selectedName(profiles, value);
  const currentDelay = value ? delayView(delays, value, testingIds.has(value)) : null;

  useLayoutEffect(() => {
    if (!open) return undefined;

    const placeOptions = () => {
      const trigger = triggerRef.current;
      if (!trigger) return;
      const rect = trigger.getBoundingClientRect();
      const configTop = trigger.closest(".config-list")?.getBoundingClientRect().top ?? rect.top;
      const viewportPadding = 12;
      const gap = 6;
      const width = Math.min(390, window.innerWidth - viewportPadding * 2);
      const left = Math.min(
        Math.max(rect.left - 12, viewportPadding),
        window.innerWidth - width - viewportPadding,
      );
      const availableBelow = Math.max(0, window.innerHeight - rect.bottom - viewportPadding);
      const availableAbove = Math.max(0, rect.top - configTop - gap);
      const openBelow = availableBelow >= availableAbove;
      const maxHeight = Math.max(1, Math.min(220, openBelow ? availableBelow : availableAbove));
      setFloatingStyle({
        top: openBelow ? rect.bottom + gap : rect.top - gap - maxHeight,
        left,
        width,
        maxHeight,
      });
    };

    placeOptions();
    window.addEventListener("resize", placeOptions);
    return () => window.removeEventListener("resize", placeOptions);
  }, [open]);

  return (
    <div className="node-selector" ref={rootRef}>
      <span className="config-label">{label}</span>
      <button
        className="node-selector-trigger"
        type="button"
        role="combobox"
        aria-label={`${label}选择`}
        aria-expanded={open}
        aria-controls={`${label}-options`}
        disabled={disabled || profiles.length === 0}
        ref={triggerRef}
        onClick={() => {
          if (open) {
            close();
          } else {
            setFloatingStyle(null);
            setOpen(true);
          }
        }}
      >
        <span>{currentName}</span>
        <span className={`selected-delay${currentDelay ? ` is-${currentDelay.tone}` : ""}`}>
          {currentDelay?.label === "—" ? "" : currentDelay?.label}
        </span>
      </button>
      {open && floatingStyle ? createPortal(
        <div
          className="node-options"
          id={`${label}-options`}
          role="listbox"
          aria-label={label}
          ref={optionsRef}
          style={floatingStyle}
        >
          {sortedProfiles.map((profile) => {
            const delay = delayView(delays, profile.id, testingIds.has(profile.id));
            return (
              <button
                className={profile.id === value ? "is-selected" : ""}
                type="button"
                role="option"
                aria-selected={profile.id === value}
                key={profile.id}
                disabled={!profile.enabled || selectionDisabled}
                onClick={() => {
                  close();
                  onSelect(profile.id);
                }}
              >
                <Check aria-hidden="true" size={15} weight="bold" />
                <span className="node-option-name">{profile.name}</span>
                <span className={`node-delay is-${delay.tone}`}>{delay.label}</span>
              </button>
            );
          })}
        </div>,
        document.body,
      ) : null}
    </div>
  );
}

function NodeActions({ label, role, value, name, menuDisabled, actionDisabled, onImport, onDelete }) {
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const rootRef = useDismissableLayer(open, close);

  return (
    <div className="node-actions" ref={rootRef}>
      <button
        className="node-menu-trigger"
        type="button"
        aria-label={`${label}操作`}
        aria-expanded={open}
        disabled={menuDisabled}
        onClick={() => setOpen((current) => !current)}
      >
        <DotsThreeVertical aria-hidden="true" size={22} weight="bold" />
      </button>
      {open ? (
        <div className="node-action-menu" role="menu">
          <button
            type="button"
            role="menuitem"
            disabled={actionDisabled}
            onClick={() => {
              close();
              onImport(role);
            }}
          >
            <UploadSimple aria-hidden="true" size={17} />
            导入
          </button>
          <button
            className="is-destructive"
            type="button"
            role="menuitem"
            disabled={!value || actionDisabled}
            onClick={() => {
              close();
              onDelete({ role, id: value, name });
            }}
          >
            <Trash aria-hidden="true" size={17} />
            删除
          </button>
        </div>
      ) : null}
    </div>
  );
}

function ConfigRow(props) {
  return (
    <div className="config-row">
      <NodeSelector
        label={props.label}
        profiles={props.profiles}
        value={props.value}
        delays={props.delays}
        testingIds={props.testingIds}
        disabled={props.browseDisabled}
        selectionDisabled={props.disabled}
        onSelect={props.onSelect}
      />
      <NodeActions
        label={props.label}
        role={props.role}
        value={props.value}
        name={selectedName(props.profiles, props.value)}
        menuDisabled={props.browseDisabled}
        actionDisabled={props.disabled}
        onImport={props.onImport}
        onDelete={props.onDelete}
      />
    </div>
  );
}

function ConfirmDialog({ title, message, confirmLabel = "确定", destructive = false, onCancel, onConfirm }) {
  const ref = useRef(null);

  useEffect(() => {
    ref.current?.showModal();
  }, []);

  return (
    <dialog className="confirm-dialog" ref={ref} onCancel={onCancel}>
      <h2>{title}</h2>
      <p>{message}</p>
      <div>
        <button type="button" onClick={onCancel}>取消</button>
        <button className={destructive ? "is-destructive" : "is-primary"} type="button" onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

export function App() {
  const controller = useAppController();
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [requestedMode, setRequestedMode] = useState(null);
  const view = connectionView(controller.status, controller.pendingAction);
  const active = view.connected || BUSY_STATES.has(controller.status.runtimeState);
  const operationPending = Boolean(controller.pendingAction);
  const testingIds = useMemo(
    () => new Set(controller.testingDelayIds),
    [controller.testingDelayIds],
  );
  const nodeControlsDisabled = controller.loading || operationPending || controller.testingDelays || active;
  const nodeBrowseDisabled = controller.loading;
  const generalControlsDisabled = controller.loading || operationPending || controller.testingDelays;
  const firstHop = selectedName(controller.status.firstHops, controller.status.selectedFirstHop);
  const proton = selectedName(controller.status.protonNodes, controller.status.selectedProton);
  const feedback = controller.feedback?.message ?? controller.pollError;
  const canToggleConnection = view.connected
    ? !controller.loading && !operationPending && !controller.testingDelays
    : controller.status.configured
      && controller.status.canConnect
      && !operationPending
      && !controller.testingDelays;

  const confirmDelete = async () => {
    const target = deleteTarget;
    setDeleteTarget(null);
    if (target) await controller.deleteProfile(target.role, target.id);
  };

  const applyModeChange = async (mode) => {
    if (mode === "double" && controller.status.protonNodes.length === 0) {
      // 后端不会保存缺少出口节点的转发状态；先完成导入，再原子切换模式。
      if (view.connected && !(await controller.disconnect())) return false;
      if (!(await controller.importConfigs("proton"))) return false;
    }
    return controller.switchMode(mode);
  };

  const confirmModeChange = async () => {
    const mode = requestedMode;
    setRequestedMode(null);
    if (mode) await applyModeChange(mode);
  };

  const requestMode = (mode) => {
    if (mode === controller.status.mode) return;
    if (view.connected) {
      setRequestedMode(mode);
      return;
    }
    void applyModeChange(mode);
  };

  return (
    <main className="app-shell">
      <ConnectionControl
        view={view}
        disabled={!canToggleConnection}
        onConnect={controller.connect}
        onDisconnect={controller.disconnect}
      />

      <ModeBar
        mode={controller.status.mode}
        disabled={generalControlsDisabled}
        canEnterForward={controller.status.firstHops.length > 0}
        testing={controller.testingDelays}
        onRequestMode={requestMode}
        onTest={controller.testDelays}
      />

      <section
        className={`config-list${controller.status.mode === "double" ? " has-exit" : ""}`}
        aria-label="节点配置"
      >
        <ConfigRow
          label="转发节点"
          role="first-hop"
          profiles={controller.status.firstHops}
          value={controller.status.selectedFirstHop}
          delays={controller.delays}
          testingIds={testingIds}
          disabled={nodeControlsDisabled}
          browseDisabled={nodeBrowseDisabled}
          onSelect={(selectedFirstHop) => controller.updateSelection({ selectedFirstHop })}
          onImport={controller.importConfigs}
          onDelete={setDeleteTarget}
        />
        <div
          className={`exit-node-slot${controller.status.mode === "double" ? " is-visible" : ""}`}
          aria-hidden={controller.status.mode !== "double"}
        >
          <ConfigRow
            label="出口节点"
            role="proton"
            profiles={controller.status.protonNodes}
            value={controller.status.selectedProton}
            delays={controller.delays}
            testingIds={testingIds}
            disabled={nodeControlsDisabled || controller.status.mode !== "double"}
            browseDisabled={nodeBrowseDisabled || controller.status.mode !== "double"}
            onSelect={(selectedProton) => controller.updateSelection({ selectedProton })}
            onImport={controller.importConfigs}
            onDelete={setDeleteTarget}
          />
        </div>
      </section>

      <p
        className={`feedback${feedback ? " is-visible" : ""}${controller.feedback ? ` is-${controller.feedback.kind}` : ""}`}
        role="status"
      >
        {feedback ?? "状态正常"}
      </p>

      <footer className="route-line">
        <span key={controller.status.mode}>
          {controller.status.mode === "double" ? `${firstHop} → ${proton}` : firstHop}
        </span>
        {controller.desktopRuntime ? (
          <button
            className="update-button"
            type="button"
            disabled={active || operationPending || controller.testingDelays || controller.updateBusy}
            onClick={controller.updateInfo ? controller.installUpdate : controller.checkForUpdate}
          >
            {controller.updateBusy
              ? "检查中…"
              : controller.updateInfo
                ? `安装 ${controller.updateInfo.version}`
                : "检查更新"}
          </button>
        ) : null}
      </footer>

      {deleteTarget ? (
        <ConfirmDialog
          title="删除配置？"
          message={deleteTarget.name}
          confirmLabel="删除"
          destructive
          onCancel={() => setDeleteTarget(null)}
          onConfirm={confirmDelete}
        />
      ) : null}
      {requestedMode ? (
        <ConfirmDialog
          title="切换连接模式"
          message="切换模式会中断连接，确定要继续吗？"
          onCancel={() => setRequestedMode(null)}
          onConfirm={confirmModeChange}
        />
      ) : null}
    </main>
  );
}

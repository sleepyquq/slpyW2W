import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check } from "@phosphor-icons/react/Check";
import { CaretDown } from "@phosphor-icons/react/CaretDown";
import { DotsThreeVertical } from "@phosphor-icons/react/DotsThreeVertical";
import { Trash } from "@phosphor-icons/react/Trash";
import { UploadSimple } from "@phosphor-icons/react/UploadSimple";
import { useAppController } from "./useAppController.js";

const CONNECTED_STATES = new Set(["connected", "running", "manual-verification-required"]);
const BUSY_STATES = new Set(["starting", "connecting", "stopping", "disconnecting"]);
const PYXIS_BUILD = import.meta.env.VITE_PYXIS_BUILD === "true";

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

function ModeBar({ mode, disabled, hasExitNode, onRequestMode }) {
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
          disabled={disabled || !hasExitNode}
          aria-pressed={mode === "double"}
          onClick={() => onRequestMode("double")}
        >
          转发
        </button>
      </div>
    </div>
  );
}

function teamNodeRank(name) {
  if (name === "香港") return 0;
  if (name === "香港2") return 1;
  const match = /^(台湾|新加坡)([CYZ]?)([123])$/.exec(name);
  if (!match) return Number.MAX_SAFE_INTEGER;
  const regionRank = match[1] === "台湾" ? 10 : 100;
  const ownerRank = { "": 0, C: 0, Y: 10, Z: 20 }[match[2]] ?? 30;
  return regionRank + ownerRank + Number(match[3]);
}

function TeamNodeBar({
  profiles,
  value,
  delays,
  testingIds,
  browseDisabled,
  selectionDisabled,
  onSelect,
}) {
  return (
    <section className="team-node-bar" aria-label="节点选择">
      <NodeSelector
        label="节点"
        profiles={profiles}
        value={value}
        delays={delays}
        testingIds={testingIds}
        disabled={browseDisabled}
        selectionDisabled={selectionDisabled}
        preserveOrder
        team
        onSelect={onSelect}
      />
    </section>
  );
}

function NodeSelector({
  label,
  profiles,
  value,
  delays,
  testingIds,
  disabled,
  selectionDisabled,
  onSelect,
  preserveOrder = false,
  team = false,
}) {
  const [open, setOpen] = useState(false);
  const [floatingStyle, setFloatingStyle] = useState(null);
  const triggerRef = useRef(null);
  const optionsRef = useRef(null);
  const sortedProfiles = useMemo(
    () =>
      preserveOrder
        ? profiles
        : [...profiles].sort((left, right) =>
          left.name.localeCompare(right.name, "en", { numeric: true, sensitivity: "base" }),
        ),
    [preserveOrder, profiles],
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
      const viewportPadding = 12;
      const gap = 6;
      const width = team
        ? rect.width
        : Math.min(390, window.innerWidth - viewportPadding * 2);
      const left = Math.min(
        Math.max(team ? rect.left : rect.left - 12, viewportPadding),
        window.innerWidth - width - viewportPadding,
      );
      const availableBelow = Math.max(0, window.innerHeight - rect.bottom - viewportPadding);
      const availableAbove = Math.max(0, rect.top - viewportPadding - gap);
      const openBelow = team || availableBelow >= availableAbove;
      const maxOptionsHeight = team ? 136 : 220;
      const maxHeight = Math.max(1, Math.min(maxOptionsHeight, openBelow ? availableBelow : availableAbove));
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
  }, [open, team]);

  return (
    <div className={`node-selector${team ? " is-team" : ""}`} ref={rootRef}>
      {!team ? <span className="config-label">{label}</span> : null}
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
        <span className="node-selection-meta">
          <span className={`selected-delay${currentDelay ? ` is-${currentDelay.tone}` : ""}`}>
            {currentDelay?.label === "—" ? "" : currentDelay?.label}
          </span>
          <CaretDown aria-hidden="true" size={15} weight="bold" />
        </span>
      </button>
      {open && floatingStyle ? createPortal(
        <div
          className={`node-options${team ? " is-team" : ""}`}
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
      {!PYXIS_BUILD ? (
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
      ) : null}
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

function MemberDialog({ open, required, busy, error, onImport, onClose }) {
  const ref = useRef(null);

  useEffect(() => {
    if (open && !ref.current?.open) ref.current?.showModal();
    if (!open && ref.current?.open) ref.current?.close();
  }, [open]);

  return (
    <dialog
      className="member-dialog"
      ref={ref}
      onCancel={(event) => {
        if (required) event.preventDefault();
        else onClose();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy) void onImport();
        }}
      >
        <h2>{required ? "导入个人配置" : "更新个人配置"}</h2>
        <p>请选择管理员发给你的 .hkproton 文件。</p>
        <span className={`member-error${error ? " is-visible" : ""}`} role="alert">
          {error ?? ""}
        </span>
        <div className={`member-dialog-actions${required ? "" : " is-optional"}`}>
          {!required ? (
            <button className="is-secondary" type="button" disabled={busy} onClick={onClose}>
              取消
            </button>
          ) : null}
          <button type="submit" disabled={busy}>
            {busy ? "正在导入" : "选择文件"}
          </button>
        </div>
      </form>
    </dialog>
  );
}

export function App() {
  const controller = useAppController();
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [requestedMode, setRequestedMode] = useState(null);
  const [requestedTeamNode, setRequestedTeamNode] = useState(null);
  const [memberPackageDialogOpen, setMemberPackageDialogOpen] = useState(false);
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
  const teamBrowseDisabled = controller.loading
    || operationPending
    || BUSY_STATES.has(controller.status.runtimeState);
  const teamSelectionDisabled = teamBrowseDisabled || controller.testingDelays;
  const firstHop = selectedName(controller.status.firstHops, controller.status.selectedFirstHop);
  const proton = selectedName(controller.status.protonNodes, controller.status.selectedProton);
  const teamProfiles = useMemo(() => {
    const first = [...controller.status.firstHops]
      .filter((profile) => profile.enabled)
      .map((profile) => ({ ...profile }))
      .sort((left, right) => teamNodeRank(left.name) - teamNodeRank(right.name));
    const exits = [...controller.status.protonNodes]
      .filter((profile) => profile.enabled)
      .sort((left, right) =>
      teamNodeRank(left.name) - teamNodeRank(right.name)
        || left.name.localeCompare(right.name, "zh-Hans-CN", { numeric: true }),
      );
    return [...first, ...exits];
  }, [controller.status.firstHops, controller.status.protonNodes]);
  const selectedTeamNode = controller.status.mode === "single"
    ? controller.status.selectedFirstHop
    : controller.status.selectedProton;
  const feedback = controller.feedback?.message ?? controller.pollError;
  const canToggleConnection = view.connected
    ? !controller.loading && !operationPending && !controller.testingDelays
    : controller.status.configured
      && controller.status.canConnect
      && !operationPending
      && !controller.testingDelays
      && (!PYXIS_BUILD || !controller.memberRequired);

  const confirmDelete = async () => {
    const target = deleteTarget;
    setDeleteTarget(null);
    if (target) await controller.deleteProfile(target.role, target.id);
  };

  const confirmModeChange = async () => {
    const mode = requestedMode;
    setRequestedMode(null);
    if (mode) await controller.switchMode(mode);
  };

  const requestMode = (mode) => {
    if (mode === controller.status.mode) return;
    if (view.connected) {
      setRequestedMode(mode);
      return;
    }
    void controller.switchMode(mode);
  };

  const applyTeamNode = async (profileId) => {
    const isHongKong = controller.status.firstHops.some((profile) => profile.id === profileId);
    if (isHongKong) {
      return controller.updateSelection({
        mode: "single",
        selectedFirstHop: profileId,
      });
    }
    const vlessHongKong = controller.status.firstHops.find((profile) => profile.name === "香港");
    if (!vlessHongKong) return false;
    return controller.updateSelection({
      mode: "double",
      selectedFirstHop: vlessHongKong.id,
      selectedProton: profileId,
    });
  };

  const requestTeamNode = (profileId) => {
    if (profileId === selectedTeamNode) return;
    if (view.connected) {
      setRequestedTeamNode(profileId);
      return;
    }
    void applyTeamNode(profileId);
  };

  const confirmTeamNodeChange = async () => {
    const profileId = requestedTeamNode;
    setRequestedTeamNode(null);
    if (!profileId) return;
    if (view.connected && !(await controller.disconnect())) return;
    await applyTeamNode(profileId);
  };

  const importMemberPackage = async () => {
    if (await controller.importMemberPackage()) {
      setMemberPackageDialogOpen(false);
    }
  };

  return (
    <main className={`app-shell${PYXIS_BUILD ? " is-pyxis-team" : ""}`}>
      <ConnectionControl
        view={view}
        disabled={!canToggleConnection}
        onConnect={controller.connect}
        onDisconnect={controller.disconnect}
      />

      {PYXIS_BUILD ? (
        <TeamNodeBar
          profiles={teamProfiles}
          value={selectedTeamNode}
          delays={controller.delays}
          testingIds={testingIds}
          browseDisabled={teamBrowseDisabled}
          selectionDisabled={teamSelectionDisabled}
          onSelect={requestTeamNode}
        />
      ) : (
        <>
          <ModeBar
            mode={controller.status.mode}
            disabled={generalControlsDisabled}
            hasExitNode={controller.status.protonNodes.length > 0}
            onRequestMode={requestMode}
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
        </>
      )}

      <p
        className={`feedback${feedback ? " is-visible" : ""}${controller.feedback ? ` is-${controller.feedback.kind}` : ""}`}
        role="status"
      >
        {feedback ?? "状态正常"}
      </p>

      {!PYXIS_BUILD ? (
        <footer className="route-line">
          <span key={controller.status.mode}>
            {controller.status.mode === "double" ? `${firstHop} → ${proton}` : firstHop}
          </span>
        </footer>
      ) : null}

      {PYXIS_BUILD && controller.pyxisMember ? (
        <footer className="pyxis-member-signature">
          <span>Pyxis - {controller.pyxisMember}</span>
          <button
            type="button"
            disabled={controller.loading || active || operationPending || controller.testingDelays}
            onClick={() => setMemberPackageDialogOpen(true)}
          >
            更新配置
          </button>
        </footer>
      ) : null}

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
      {requestedTeamNode ? (
        <ConfirmDialog
          title="切换节点"
          message="切换节点会中断连接，确定要继续吗？"
          onCancel={() => setRequestedTeamNode(null)}
          onConfirm={confirmTeamNodeChange}
        />
      ) : null}
      {PYXIS_BUILD && (controller.memberRequired || memberPackageDialogOpen) ? (
        <MemberDialog
          open={controller.memberRequired || memberPackageDialogOpen}
          required={controller.memberRequired}
          busy={controller.pendingAction === "member"}
          error={controller.memberError}
          onImport={importMemberPackage}
          onClose={() => setMemberPackageDialogOpen(false)}
        />
      ) : null}
    </main>
  );
}

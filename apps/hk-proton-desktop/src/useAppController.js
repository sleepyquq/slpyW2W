import { useCallback, useEffect, useRef, useState } from "react";
import {
  connectApp,
  activatePyxisMember,
  disconnectApp,
  getAppStatus,
  importConfigFiles,
  deleteConfig,
  isDesktopRuntime,
  isStatusPayload,
  normalizeAppStatus,
  pollAppStatus,
  measureNodeDelays,
  toUserMessage,
  updateAppSelection,
  validateCurrent,
} from "./appBridge.js";

const INITIAL_STATUS = normalizeAppStatus(null);
const PYXIS_BUILD = import.meta.env.VITE_PYXIS_BUILD === "true";
const MEMBER_STORAGE_KEY = "slpyw2w.pyxis.member.v1";

function storedPyxisMember() {
  if (!PYXIS_BUILD || typeof window === "undefined") return "";
  return window.localStorage.getItem(MEMBER_STORAGE_KEY)?.trim().toLowerCase() ?? "";
}

export function useAppController() {
  const [status, setStatus] = useState(INITIAL_STATUS);
  const [loading, setLoading] = useState(true);
  const [pendingAction, setPendingAction] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [pollError, setPollError] = useState(null);
  const [delays, setDelays] = useState({});
  const [testingDelayIds, setTestingDelayIds] = useState([]);
  const [pyxisMember, setPyxisMember] = useState(storedPyxisMember);
  const [memberRequired, setMemberRequired] = useState(() => PYXIS_BUILD && !storedPyxisMember());
  const [memberError, setMemberError] = useState(null);
  const [desktopRuntime] = useState(() => isDesktopRuntime());
  const statusRef = useRef(INITIAL_STATUS);
  const revisionRef = useRef(INITIAL_STATUS.revision);
  const operationActiveRef = useRef(false);
  const speedTestActiveRef = useRef(false);
  const pollActiveRef = useRef(false);
  const mountedRef = useRef(true);

  const commitStatus = useCallback((rawStatus) => {
    const nextStatus = normalizeAppStatus(rawStatus);
    if (revisionRef.current !== nextStatus.revision) {
      revisionRef.current = nextStatus.revision;
      setDelays({});
    }
    statusRef.current = nextStatus;
    if (mountedRef.current) {
      setStatus(nextStatus);
    }
    return nextStatus;
  }, []);

  const resolveStatus = useCallback(
    async (result) => {
      const rawStatus = isStatusPayload(result) ? result : await pollAppStatus();
      return commitStatus(rawStatus);
    },
    [commitStatus],
  );

  const perform = useCallback(
    async ({ action, task, successMessage = null, fallbackMessage, optimistic = null }) => {
      if (operationActiveRef.current) {
        return false;
      }

      const previousStatus = statusRef.current;
      operationActiveRef.current = true;
      setPendingAction(action);
      setFeedback(null);
      setPollError(null);
      if (optimistic) {
        commitStatus({ ...previousStatus, ...optimistic });
      }

      try {
        const result = await task();
        if (result?.cancelled) {
          return false;
        }
        await resolveStatus(result);
        if (successMessage && mountedRef.current) {
          setFeedback({ kind: "success", message: successMessage });
        }
        return true;
      } catch (error) {
        if (optimistic) {
          commitStatus(previousStatus);
        }
        if (mountedRef.current) {
          setFeedback({ kind: "error", message: toUserMessage(error, fallbackMessage) });
        }
        return false;
      } finally {
        operationActiveRef.current = false;
        if (mountedRef.current) {
          setPendingAction(null);
        }
      }
    },
    [commitStatus, resolveStatus],
  );

  useEffect(() => {
    mountedRef.current = true;
    let cancelled = false;

    const load = async () => {
      try {
        let rawStatus;
        if (PYXIS_BUILD && pyxisMember) {
          try {
            rawStatus = await activatePyxisMember(pyxisMember);
          } catch {
            window.localStorage.removeItem(MEMBER_STORAGE_KEY);
            setPyxisMember("");
            setMemberRequired(true);
            setMemberError("没有找到对应的团队配置，请检查名字。");
            rawStatus = await getAppStatus();
          }
        } else {
          rawStatus = await getAppStatus();
        }
        if (!cancelled) {
          commitStatus(rawStatus);
        }
      } catch (error) {
        if (!cancelled) {
          setFeedback({
            kind: "error",
            message: toUserMessage(error, "无法读取应用状态，请重试。"),
          });
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    const poll = async () => {
      if (
        cancelled ||
        document.visibilityState === "hidden" ||
        operationActiveRef.current ||
        speedTestActiveRef.current ||
        pollActiveRef.current
      ) {
        return;
      }
      pollActiveRef.current = true;
      try {
        const rawStatus = await pollAppStatus();
        if (!cancelled) {
          commitStatus(rawStatus);
          setPollError(null);
        }
      } catch (error) {
        if (!cancelled) {
          setPollError(toUserMessage(error, "状态更新失败，请稍后重试。"));
        }
      } finally {
        pollActiveRef.current = false;
      }
    };

    void load();
    const timer = desktopRuntime ? window.setInterval(poll, 1500) : null;

    return () => {
      cancelled = true;
      mountedRef.current = false;
      if (timer !== null) {
        window.clearInterval(timer);
      }
    };
  }, [commitStatus, desktopRuntime]);

  const activateMember = useCallback(async (value) => {
    if (!PYXIS_BUILD || operationActiveRef.current) return false;
    const member = String(value ?? "").trim().toLowerCase();
    operationActiveRef.current = true;
    setPendingAction("member");
    setMemberError(null);
    try {
      const result = await activatePyxisMember(member);
      commitStatus(result);
      window.localStorage.setItem(MEMBER_STORAGE_KEY, member);
      setPyxisMember(member);
      setMemberRequired(false);
      setDelays({});
      return true;
    } catch {
      setMemberError("没有找到对应的团队配置，请检查名字。");
      return false;
    } finally {
      operationActiveRef.current = false;
      if (mountedRef.current) setPendingAction(null);
    }
  }, [commitStatus]);

  const updateSelection = useCallback(
    async (changes) => {
      const current = statusRef.current;
      const selection = {
        mode: changes.mode ?? current.mode,
        selectedFirstHop: changes.selectedFirstHop ?? current.selectedFirstHop,
        selectedProton: changes.selectedProton ?? current.selectedProton,
      };
      const changed = await perform({
        action: "selection",
        task: () => updateAppSelection(selection),
        fallbackMessage: "无法保存选择，请重试。",
        optimistic: selection,
      });
      if (changed) setDelays({});
      return changed;
    },
    [perform],
  );

  const importConfigs = useCallback(
    async (role) => {
      const imported = await perform({
        action: "import",
        task: () => importConfigFiles(role),
        successMessage: "配置已导入。",
        fallbackMessage: "导入失败，请检查配置后重试。",
      });
      if (imported) setDelays({});
      return imported;
    },
    [perform],
  );

  const deleteProfile = useCallback(
    async (role, profileId) => {
      const deleted = await perform({
        action: "delete",
        task: () => deleteConfig(role, profileId),
        successMessage: "配置已删除。",
        fallbackMessage: "无法删除配置。",
      });
      if (deleted) setDelays({});
      return deleted;
    },
    [perform],
  );

  const connect = useCallback(
    () =>
      perform({
        action: "connect",
        task: async () => {
          await validateCurrent();
          return connectApp();
        },
        fallbackMessage: "连接失败，请检查配置后重试。",
      }),
    [perform],
  );

  const disconnect = useCallback(
    () =>
      perform({
        action: "disconnect",
        task: disconnectApp,
        fallbackMessage: "断开失败，请重试。",
      }),
    [perform],
  );

  const switchMode = useCallback(
    (mode) => {
      const current = statusRef.current;
      const connected = ["connected", "running", "manual-verification-required"].includes(
        current.runtimeState,
      );
      return perform({
        action: "mode",
        task: async () => {
          if (connected) {
            await disconnectApp();
          }
          return updateAppSelection({
            mode,
            selectedFirstHop: current.selectedFirstHop,
            selectedProton: current.selectedProton,
          });
        },
        fallbackMessage: "无法切换连接模式。",
        optimistic: connected ? null : { mode },
      });
    },
    [perform],
  );

  const testDelays = useCallback(async () => {
    if (operationActiveRef.current || speedTestActiveRef.current) return false;
    const current = statusRef.current;
    const targets = PYXIS_BUILD || current.mode === "double"
      ? [...current.firstHops, ...current.protonNodes]
      : current.firstHops;
    speedTestActiveRef.current = true;
    setTestingDelayIds(targets.filter((item) => item.enabled).map((item) => item.id));
    setFeedback(null);
    setPollError(null);
    try {
      const report = await measureNodeDelays();
      const next = Object.fromEntries(targets.map((item) => [item.id, null]));
      for (const item of Array.isArray(report?.results) ? report.results : []) {
        if (!item || typeof item.id !== "string") continue;
        next[item.id] = Number.isFinite(item.delayMs)
          ? Math.max(1, Math.round(item.delayMs))
          : null;
      }
      const timeoutCount = Object.values(next).filter((value) => value === null).length;
      if (mountedRef.current) {
        setDelays(next);
        setFeedback({
          kind: timeoutCount > 0 ? "warning" : "success",
          message: timeoutCount > 0
            ? `测速完成，${timeoutCount} 个节点超时。`
            : "节点延迟已更新。",
        });
      }
      return true;
    } catch (error) {
      if (mountedRef.current) {
        setFeedback({ kind: "error", message: toUserMessage(error, "测速失败，请稍后重试。") });
      }
      return false;
    } finally {
      speedTestActiveRef.current = false;
      if (mountedRef.current) setTestingDelayIds([]);
    }
  }, []);

  return {
    status,
    loading,
    pendingAction,
    feedback,
    pollError,
    delays,
    testingDelayIds,
    testingDelays: testingDelayIds.length > 0,
    desktopRuntime,
    pyxisMember,
    memberRequired,
    memberError,
    activateMember,
    updateSelection,
    importConfigs,
    deleteProfile,
    switchMode,
    testDelays,
    connect,
    disconnect,
    clearFeedback: () => setFeedback(null),
  };
}

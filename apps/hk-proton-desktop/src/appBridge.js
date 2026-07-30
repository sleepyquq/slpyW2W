import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

const EMPTY_STATUS = {
  configured: false,
  revision: 0,
  mode: "single",
  firstHops: [],
  protonNodes: [],
  selectedFirstHop: null,
  selectedProton: null,
  runtimeState: "unconfigured",
  canConnect: false,
  blocker: null,
  message: null,
};

let demoStatus = {
  ...EMPTY_STATUS,
  configured: true,
  mode: "double",
  firstHops: [
    { id: "demo-zurich", name: "Zurich Relay", enabled: true },
    { id: "demo-hk", name: "香港 WireGuard", enabled: true },
  ],
  protonNodes: [
    { id: "demo-proton-jp-1", name: "Proton JP-1", enabled: true },
    { id: "demo-proton-jp-2", name: "Proton JP-2", enabled: true },
    { id: "demo-proton-kr-1", name: "Proton KR-1", enabled: true },
    { id: "demo-proton-kr-2", name: "Proton KR-2", enabled: true },
    { id: "demo-proton-sg-1", name: "Proton SG-1", enabled: true },
    { id: "demo-proton-sg-2", name: "Proton SG-2", enabled: true },
    { id: "demo-proton-us-1", name: "Proton US-1", enabled: true },
  ],
  selectedFirstHop: "demo-hk",
  selectedProton: "demo-proton-jp-1",
  runtimeState: "disconnected",
  canConnect: true,
};

function cloneStatus(status) {
  return {
    ...status,
    firstHops: status.firstHops.map((profile) => ({ ...profile })),
    protonNodes: status.protonNodes.map((profile) => ({ ...profile })),
  };
}

function normalizeProfiles(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((profile, index) => {
    if (!profile || typeof profile !== "object") return [];
    const id = profile.id ?? profile.profileId ?? profile.profile_id;
    if (id === undefined || id === null || String(id).trim() === "") return [];
    const name = profile.name ?? profile.displayName ?? profile.display_name ?? `配置 ${index + 1}`;
    return [{ id: String(id), name: String(name), enabled: profile.enabled !== false }];
  });
}

function normalizeRuntimeState(value) {
  return String(value ?? "unconfigured")
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .replaceAll("_", "-")
    .toLowerCase();
}

export function normalizeAppStatus(value) {
  const raw = value && typeof value === "object" ? value : EMPTY_STATUS;
  const revisionValue = Number(raw.revision ?? 0);
  return {
    configured: Boolean(raw.configured),
    revision: Number.isFinite(revisionValue) ? revisionValue : 0,
    mode: raw.mode === "double" || raw.mode === "double-hop" ? "double" : "single",
    firstHops: normalizeProfiles(raw.firstHops ?? raw.first_hops),
    protonNodes: normalizeProfiles(raw.protonNodes ?? raw.proton_nodes),
    selectedFirstHop: raw.selectedFirstHop ?? raw.selected_first_hop ?? null,
    selectedProton: raw.selectedProton ?? raw.selected_proton ?? null,
    runtimeState: normalizeRuntimeState(raw.runtimeState ?? raw.runtime_state),
    canConnect: Boolean(raw.canConnect ?? raw.can_connect),
    blocker: raw.blocker ?? null,
    message: typeof raw.message === "string" && raw.message.trim() ? raw.message.trim() : null,
  };
}

export function isStatusPayload(value) {
  return Boolean(value && typeof value === "object" && ("configured" in value || "runtimeState" in value));
}

export function isDesktopRuntime() {
  return typeof window !== "undefined" && Boolean(window.__TAURI_INTERNALS__);
}

export async function getAppStatus() {
  return isDesktopRuntime() ? invoke("get_app_status") : cloneStatus(demoStatus);
}

export async function activatePyxisMember(member) {
  if (isDesktopRuntime()) return invoke("activate_pyxis_member", { member });
  const normalized = String(member ?? "").trim().toLowerCase();
  const allowed = new Set(["cheyuxuan", "yanggengbo", "zhenjiabao", "zuoanna", "zhouwantong"]);
  if (!allowed.has(normalized)) throw { message: "未找到对应的团队配置。" };
  const owners = normalized === "zhenjiabao" ? ["C", "Y", "Z"] : [""];
  const protonNodes = owners.flatMap((owner) => [
    ...[1, 2, 3].map((index) => ({
      id: `demo-${normalized}-tw-${owner || "self"}-${index}`,
      name: `台湾${owner}${index}`,
      enabled: true,
    })),
    ...[1, 2, 3].map((index) => ({
      id: `demo-${normalized}-sg-${owner || "self"}-${index}`,
      name: `新加坡${owner}${index}`,
      enabled: true,
    })),
  ]);
  const firstHops = [
    { id: `demo-${normalized}-hk-vless`, name: "香港", enabled: true },
    ...(normalized === "zhouwantong"
      ? []
      : [{ id: `demo-${normalized}-hk-wireguard`, name: "香港2", enabled: true }]),
  ];
  demoStatus = {
    ...demoStatus,
    configured: true,
    mode: "single",
    firstHops,
    protonNodes,
    selectedFirstHop: firstHops[0]?.id ?? null,
    selectedProton: protonNodes[0]?.id ?? null,
    runtimeState: "disconnected",
    canConnect: true,
    revision: demoStatus.revision + 1,
  };
  return cloneStatus(demoStatus);
}

export async function pollAppStatus() {
  return isDesktopRuntime() ? invoke("poll_status") : cloneStatus(demoStatus);
}

export async function updateAppSelection(selection) {
  if (isDesktopRuntime()) return invoke("update_selection", selection);
  demoStatus = { ...demoStatus, ...selection };
  return cloneStatus(demoStatus);
}

export async function importConfigFiles(role) {
  if (!isDesktopRuntime()) {
    const key = role === "first-hop" ? "firstHops" : "protonNodes";
    const selectionKey = role === "first-hop" ? "selectedFirstHop" : "selectedProton";
    const index = demoStatus[key].length + 1;
    const profile = {
      id: `demo-${role}-${index}`,
      name: role === "first-hop" ? `转发节点 ${index}` : `Proton JP-${index}`,
      enabled: true,
    };
    demoStatus = { ...demoStatus, [key]: [...demoStatus[key], profile], [selectionKey]: profile.id };
    return cloneStatus(demoStatus);
  }
  const selected = await open({
    multiple: true,
    directory: false,
    filters: [{ name: "WireGuard / VLESS 配置", extensions: ["conf", "txt", "yaml", "yml"] }],
  });
  if (!selected) return { cancelled: true };
  const paths = Array.isArray(selected) ? selected : [selected];
  return invoke("import_config_files", { role, paths });
}

export async function deleteConfig(role, profileId) {
  if (isDesktopRuntime()) return invoke("delete_profile", { role, profileId });
  const key = role === "first-hop" ? "firstHops" : "protonNodes";
  const selectionKey = role === "first-hop" ? "selectedFirstHop" : "selectedProton";
  const next = demoStatus[key].filter((profile) => profile.id !== profileId);
  if (role === "first-hop" && next.length === 0) {
    throw { message: "请先导入另一个第一跳配置。" };
  }
  demoStatus = { ...demoStatus, [key]: next, [selectionKey]: next[0]?.id ?? null };
  if (role === "proton" && next.length === 0) demoStatus.mode = "single";
  return cloneStatus(demoStatus);
}

export async function validateCurrent() {
  return isDesktopRuntime() ? invoke("validate_current") : cloneStatus(demoStatus);
}

export async function connectApp() {
  if (isDesktopRuntime()) return invoke("connect");
  demoStatus = { ...demoStatus, runtimeState: "connected" };
  return cloneStatus(demoStatus);
}

export async function disconnectApp() {
  if (isDesktopRuntime()) return invoke("disconnect");
  demoStatus = { ...demoStatus, runtimeState: "disconnected" };
  return cloneStatus(demoStatus);
}

export async function measureNodeDelays() {
  if (isDesktopRuntime()) return invoke("measure_node_delays");
  await new Promise((resolve) => window.setTimeout(resolve, 900));
  const demoDelays = {
    "demo-zurich": 48,
    "demo-hk": 184,
    "demo-proton-jp-1": 96,
    "demo-proton-jp-2": 112,
    "demo-proton-kr-1": 138,
    "demo-proton-kr-2": null,
    "demo-proton-sg-1": 188,
    "demo-proton-sg-2": 224,
    "demo-proton-us-1": 326,
  };
  const selectedIds = [
    demoStatus.selectedFirstHop,
    demoStatus.mode === "double" ? demoStatus.selectedProton : null,
  ].filter(Boolean);
  return {
    results: selectedIds.map((id) => ({
      id,
      delayMs: demoDelays[id] ?? null,
    })),
  };
}

export function toUserMessage(error, fallback = "操作失败，请重试。") {
  const source = typeof error === "string" ? error : typeof error?.message === "string" ? error.message : "";
  const message = source.replace(/\s+/g, " ").trim();
  if (/未配置|not configured/i.test(message)) return "请先导入配置。";
  if (/其他代理|冲突|conflict|networkactivation|\bTUN\b/i.test(message)) return "请关闭其他软件的 TUN 后重试。";
  if (/权限|permission|access denied/i.test(message)) return "请确认应用权限后重试。";
  if (/域名.*解析|DNS/i.test(message)) return "成员配置已找到，但当前 DNS 无法解析线路服务器。";
  if (/配置.*无效|validation|invalid state|invalid config/i.test(message)) return "当前配置无法使用，请重新导入。";
  const looksSafe = message.length > 0 && message.length <= 96 && /[\u3400-\u9fff]/.test(message)
    && !/[\\/]|https?:|mihomo|dpapi|hmac|yaml|endpoint|stack trace/i.test(message);
  return looksSafe ? message : fallback;
}

/* SPDX-License-Identifier: MIT */
/*
 * YukiZygisk - WebUI control and telemetry adapter.
 * Derived from KOWX712/ksu-webui-demo and Kagami's static WebUI.
 * License: MIT
 * Authors: KOWX712 and Anatdx
 */

import { exec, hasKernelSU } from "./assets/kernelsu.js";

export const PATHS = {
  MODULE: "/data/adb/modules/yukizygisk",
  CONTROL: "/data/adb/modules/yukizygisk/bin/yzctl",
  CONFIG: "/data/adb/yukizygisk/yzconfig.json",
};

export const DEFAULT_CONFIG = {
  yukilinker: true,
  anonymous_memory: true,
  denylist_mode: 0,
  dmesg_log: false,
  crash_protection: false,
};

export const DEFAULT_STATUS = {
  available: false,
  kernel_alive: false,
  abi: "arm64-v8a",
  root_impl: "unknown",
  root_mask: 0,
  ksu_redirect: false,
  root_policy_source: "kernel",
  root_policy_cache_ready: false,
  count: 0,
  safe_mode: false,
  zygote_crashes: 0,
  safe_mode_zygote: "zygote",
  yukilinker: true,
  anonymous_memory: true,
  denylist_mode: 0,
  dmesg_log: false,
  crash_protection: false,
  recent: [],
  zygotes: [],
  zygote_monitor: [],
  modules: [],
  native_modules: [],
  native_injections: [],
  suspended_modules: [],
  error: "",
};

const params = new URLSearchParams(globalThis.location?.search || "");
const runtimeMode = params.get("mock") === "1" || !hasKernelSU() ? "mock" : "live";

export function getRuntimeMode() {
  return runtimeMode;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function output(result) {
  return String(result?.stdout || result?.stderr || "").trim();
}

function shellEscape(value) {
  return String(value ?? "").replace(/'/g, "'\\''");
}

function normalizeConfig(value = {}) {
  const mode = Number(value.denylist_mode);
  return {
    yukilinker: value.yukilinker !== false,
    anonymous_memory: value.anonymous_memory !== false,
    denylist_mode: [0, 1, 2].includes(mode) ? mode : 0,
    dmesg_log: value.dmesg_log === true,
    crash_protection: value.crash_protection === true,
  };
}

function normalizeStatus(value = {}) {
  const hasZygoteMonitor = Object.prototype.hasOwnProperty.call(value, "zygote_monitor");
  const status = {
    ...clone(DEFAULT_STATUS),
    ...value,
    available: value.kernel_alive === true,
  };
  for (const key of ["recent", "zygotes", "zygote_monitor", "modules", "native_modules", "native_injections", "suspended_modules"]) {
    if (!Array.isArray(status[key]))
      status[key] = [];
  }
  if (!hasZygoteMonitor)
    status.zygote_monitor = status.zygotes.map((item) => ({ ...item, state: "injected" }));
  return status;
}

function parseModuleProp(text) {
  const meta = {
    id: "yukizygisk",
    name: "YukiZygisk",
    version: "dev",
    versionCode: "",
    author: "Anatdx",
    description: "",
  };
  for (const line of String(text || "").split(/\r?\n/)) {
    const index = line.indexOf("=");
    if (index <= 0)
      continue;
    const key = line.slice(0, index).trim();
    if (key in meta)
      meta[key] = line.slice(index + 1).trim();
  }
  return meta;
}

async function writeConfig(config) {
  const normalized = normalizeConfig(config);
  const args = Object.entries(normalized).flatMap(([key, value]) => [key, String(value)]);
  const command = [PATHS.CONTROL, "config", "set", ...args]
    .map((value) => "'" + shellEscape(value) + "'").join(" ");
  const result = await exec(command);
  if (result.errno !== 0)
    throw new Error(output(result) || "failed to write yzconfig.json");
  return normalized;
}

const mockState = {
  config: {
    yukilinker: true,
    anonymous_memory: true,
    denylist_mode: 1,
    dmesg_log: false,
    crash_protection: false,
  },
  status: normalizeStatus({
    kernel_alive: true,
    abi: "arm64-v8a",
    root_impl: "kernelsu-redirect",
    root_mask: 3,
    ksu_redirect: true,
    root_policy_source: "userspace-ksu-api",
    root_policy_cache_ready: true,
    count: 184,
    denylist_mode: 1,
    recent: [10123, 10244, 10188, 10072],
    zygote_monitor: [
      { pid: 1771, name: "zygote", abi: "arm64-v8a", state: "injected" },
      { pid: 1772, name: "zygote_ocomp", abi: "arm64-v8a", state: "injected" },
    ],
    modules: ["zygisk_lsposed", "playintegrityfix"],
    native_modules: [
      { id: "zn_audit", target_type: "name", target: "logd", companion: false, state: "injected" },
      { id: "native_guard", target_type: "path", target: "/system/bin/keystore2", companion: true, state: "failed" },
    ],
    native_injections: [
      {
        pid: 611,
        process: "logd",
        module: "zn_audit",
        target_type: "name",
        target: "logd",
        abi: "arm64-v8a",
        companion: false,
        state: "injected",
      },
    ],
  }),
};

const mockApi = {
  async getStatus() {
    return clone(mockState.status);
  },
  async loadConfig() {
    return clone(mockState.config);
  },
  async saveConfig(config) {
    mockState.config = normalizeConfig(config);
    Object.assign(mockState.status, mockState.config);
    return clone(mockState.config);
  },
  async reload() {
    return true;
  },
  async getSystemInfo() {
    return {
      model: "Yuki Reference Device",
      android: "Android 16 (API 36)",
      kernel: "6.12.23-android16-gki",
      selinux: "Enforcing",
    };
  },
  async getModuleMeta() {
    return {
      id: "yukizygisk",
      name: "YukiZygisk",
      version: "v0.1.0-10009",
      versionCode: "10009",
      author: "Anatdx",
    };
  },
};

async function queryStatus() {
  const result = await exec(`'${shellEscape(PATHS.CONTROL)}' status --json`);
  const text = output(result);
  if (result.errno !== 0 || !text)
    return { status: null, error: text || "kernel status unavailable" };
  try {
    return { status: normalizeStatus(JSON.parse(text)), error: "" };
  } catch (error) {
    return { status: null, error: `invalid status JSON from yzctl: ${error.message}` };
  }
}

async function reloadRuntime() {
  const result = await exec(`'${shellEscape(PATHS.CONTROL)}' reload`);
  if (result.errno !== 0)
    throw new Error(output(result) || "kernel reload failed");
}

const realApi = {
  async getStatus() {
    const result = await queryStatus();
    return result.status || normalizeStatus({ error: result.error });
  },

  async loadConfig() {
    const result = await exec("'" + shellEscape(PATHS.CONTROL) + "' config get");
    if (result.errno !== 0 || !result.stdout.trim())
      return clone(DEFAULT_CONFIG);
    try {
      return normalizeConfig(JSON.parse(result.stdout));
    } catch (_error) {
      return clone(DEFAULT_CONFIG);
    }
  },

  async saveConfig(config) {
    const normalized = await writeConfig(config);
    return normalized;
  },

  async reload() {
    await reloadRuntime();
    return true;
  },

  async getSystemInfo() {
    const [model, release, sdk, kernel, selinux] = await Promise.all([
      exec("getprop ro.product.model"),
      exec("getprop ro.build.version.release"),
      exec("getprop ro.build.version.sdk"),
      exec("uname -r"),
      exec("getenforce 2>/dev/null || echo Unknown"),
    ]);
    const androidRelease = output(release) || "Unknown";
    const apiLevel = output(sdk);
    return {
      model: output(model) || "Unknown",
      android: apiLevel ? `Android ${androidRelease} (API ${apiLevel})` : `Android ${androidRelease}`,
      kernel: output(kernel) || "Unknown",
      selinux: output(selinux) || "Unknown",
    };
  },

  async getModuleMeta() {
    const result = await exec(`cat '${shellEscape(PATHS.MODULE)}/module.prop' 2>/dev/null`);
    return parseModuleProp(result.stdout);
  },
};

export const api = runtimeMode === "mock" ? mockApi : realApi;

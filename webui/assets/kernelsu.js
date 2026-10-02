/* SPDX-License-Identifier: MIT */
/*
 * YukiZygisk - WebUI X host bridge.
 *
 * Derived from KOWX712/ksu-webui-demo and Kagami's static WebUI bridge.
 *
 * License: MIT
 *
 * Authors: KOWX712 and Anatdx
 */

let callbackCounter = 0;

function uniqueName(prefix) {
  callbackCounter += 1;
  return `${prefix}_callback_${Date.now()}_${callbackCounter}`;
}

export function hasKernelSU() {
  return typeof globalThis.ksu !== "undefined";
}

export function exec(command, options = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    if (!hasKernelSU()) {
      resolve({ errno: 1, stdout: "", stderr: "ksu is not defined" });
      return;
    }

    const callbackName = uniqueName("exec");
    const timeout = setTimeout(() => {
      delete globalThis[callbackName];
      const error = new Error("The WebUI host did not respond in time");
      error.code = "ETIMEDOUT";
      reject(error);
    }, timeoutMs);
    globalThis[callbackName] = (errno, stdout, stderr) => {
      clearTimeout(timeout);
      delete globalThis[callbackName];
      resolve({ errno, stdout, stderr });
    };

    try {
      globalThis.ksu.exec(command, JSON.stringify(options), callbackName);
    } catch (error) {
      clearTimeout(timeout);
      delete globalThis[callbackName];
      reject(error);
    }
  });
}

export async function enableEdgeToEdge(enabled = true) {
  if (!hasKernelSU())
    return false;
  if (typeof globalThis.ksu.enableEdgeToEdge === "function") {
    globalThis.ksu.enableEdgeToEdge(enabled);
    return true;
  }
  if (typeof globalThis.ksu.enableInsets === "function") {
    globalThis.ksu.enableInsets(enabled);
    return true;
  }
  return false;
}

export function setFullScreen(enabled = true) {
  if (!hasKernelSU() || typeof globalThis.ksu.fullScreen !== "function")
    return false;
  globalThis.ksu.fullScreen(enabled);
  return true;
}

export function toast(message) {
  if (hasKernelSU() && typeof globalThis.ksu.toast === "function") {
    globalThis.ksu.toast(String(message));
    return;
  }
  console.log(`[toast] ${message}`);
}

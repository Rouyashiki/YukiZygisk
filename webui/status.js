/* SPDX-License-Identifier: MIT */
/*
 * YukiZygisk - WebUI runtime and policy status.
 * Derived from KOWX712/ksu-webui-demo and Kagami's static WebUI.
 * Authors: KOWX712 and Rouyashiki Developers
 */

export function configSavePhase(changes, lateLoadPending) {
  if ("fixed_sepolicy" in changes) return "savedPolicy";
  return lateLoadPending ? "savedPending" : "saved";
}

export function policyPresentation(policy) {
  if (!policy?.supported || (policy.error && !policy.requested))
    return { tone: "danger", label: "settings.policyUnavailable" };
  if (policy.error)
    return { tone: "danger", label: policy.error === -101 ? "settings.policyMountRejected" : "settings.policyRejected" };
  if (!policy.initialized || (policy.requested && !policy.active))
    return { tone: "warning", label: "settings.policyPending" };
  return { tone: "success", label: policy.active ? "settings.policyFixed" : "settings.policyTemporary" };
}

export function withPolicyRebootNotice(text, policy, t) {
  if (!policy?.reboot_required) return text;
  return t("settings.policyRebootRequired", "", { status: String(text).replace(/[.。]$/, "") });
}

export function policyModeText({ status: { policy }, config, configReady }, t) {
  const active = t(policyPresentation(policy).label);
  const preferred = configReady
    ? t(config.fixed_sepolicy ? "settings.policyFixed" : "settings.policyTemporary")
    : t("common.unknown");
  let status = t("settings.policyState", "", { active, preferred });
  if (policy?.supported && policy.error)
    status = t("settings.policyError", "", { status, error: policy.error });
  if (policy?.supported && policy.missing_av) {
    status = t("settings.policyDenied", "", {
      status,
      source: policy.missing_source || "?",
      target: policy.missing_target || "?",
      cls: policy.missing_class || "?",
      av: `0x${Number(policy.missing_av).toString(16)}`,
    });
  }
  return withPolicyRebootNotice(status, policy, t);
}

export function statusPresentation(status, ready, t) {
  const { policy } = status;
  const describe = (text) => withPolicyRebootNotice(text, policy, t);
  if (!ready) return { tone: "", icon: "loader-circle", title: t("common.loading"), description: "" };
  if (status.safe_mode) return { tone: "warning", icon: "shield-alert", title: t("status.safeMode"), description: describe(t("status.safeModeDesc")) };
  const online = status.available && status.kernel_alive;
  if (status.late_load && status.late_load_error)
    return { tone: "danger", icon: "circle-alert", title: t("status.lateLoad"), description: describe(status.late_load_error) };
  if (online && policy?.supported && (policy.error || !status.late_load_pending)) {
    const { tone, label } = policyPresentation(policy);
    if (tone !== "success") {
      let detail = t(label);
      if (policy.error) detail = t("settings.policyError", "", { status: detail, error: policy.error });
      if (status.late_load_pending) detail = t("status.lateLoadBlocked", "", { error: detail });
      return { tone, icon: "shield-alert", title: t("settings.fixedPolicy"), description: describe(detail) };
    }
  }
  if (status.late_load_pending) return { tone: "warning", icon: "circle-alert", title: t("status.lateLoad"), description: describe(t("status.lateLoadPending")) };
  if (online) return { tone: "success", icon: "shield-check", title: t("status.running"), description: describe(status.abi) };
  return { tone: "danger", icon: "circle-alert", title: t("status.unavailable"), description: describe(status.error || t("status.unavailableDesc")) };
}

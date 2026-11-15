export function zygiskRecords(status, moduleId) {
  return (status.runtime || []).filter((record) => record.kind === "zygote" &&
    record.module === moduleId && record.process_state !== "exited" &&
    (status.zygote_monitor || []).some((zygote) => zygote.pid > 0 &&
      zygote.generation > 0 && zygote.pid === record.pid &&
      zygote.generation === record.generation && zygote.abi === record.abi));
}

export function zygiskOutcome(status, moduleId) {
  let success = false, failure = false, complete = true;
  const records = zygiskRecords(status, moduleId);
  for (const record of records) {
    if (status.zygisk_module_outcomes === true &&
        typeof record.load_success_seen === "boolean" &&
        typeof record.load_failure_seen === "boolean") {
      success ||= record.load_success_seen;
      failure ||= record.load_failure_seen;
    } else {
      const value = record.injection_state || record.state;
      success ||= value === "injected";
      failure ||= value === "failed";
      complete = false;
    }
  }
  if (success && failure) return "partial";
  if (success) return "load_success";
  if (failure) return complete ? "load_failed" : "load_legacy_failure";
  return "unknown";
}

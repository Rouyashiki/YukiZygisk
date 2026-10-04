/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Live kernel and authenticated daemon health diagnostics.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */

#include "health.hpp"
#include "host.hpp"
#include "uapi/yukizygisk.h"
#include "userspace/zygisk/daemon_health_client.hpp"

namespace yzctl {
namespace {
namespace health = yukizygisk::health;
const char *availability_name(health::Availability value) {
  switch (value) {
  case health::Availability::Available:
    return "available";
  case health::Availability::Missing:
    return "missing";
  case health::Availability::Unresponsive:
    return "unresponsive";
  case health::Availability::Unsupported:
    return "unsupported";
  case health::Availability::IdentityError:
    return "identity_error";
  case health::Availability::Error:
    return "error";
  }
  return "error";
}

const char *reader_name(health::ReaderState state) {
  switch (state) {
  case health::ReaderState::Unsupported:
    return "unsupported";
  case health::ReaderState::Active:
    return "active";
  case health::ReaderState::Retrying:
    return "retrying";
  case health::ReaderState::Unknown:
    return "unknown";
  }
  return "unknown";
}

json::Value number(uint32_t value) { return {static_cast<double>(value)}; }

} // namespace

json::Value kernel_health(Host &host, uint32_t capabilities) {
  json::Value result = json::Value::object();
  result["supported"] = (capabilities & YZ_RUNTIME_CAP_HEALTH) != 0;
  if ((capabilities & YZ_RUNTIME_CAP_HEALTH) == 0) {
    result["state"] = "unsupported";
    return result;
  }
  yz_health_query_cmd query{};
  query.version = YZ_HEALTH_VERSION;
  query.size = sizeof(query);
  if (host.call(YZ_IOCTL_GET_HEALTH, &query) != 0) {
    const int error = errno;
    if (error == ENOTTY || error == EOPNOTSUPP)
      result["supported"] = false;
    result["state"] =
        error == ENOTTY || error == EOPNOTSUPP ? "unsupported" : "error";
    result["error"] = error;
    return result;
  }
  result["state"] = "available";
  result["sample_begin_boottime_ns"] =
      std::to_string(query.sample_begin_boottime);
  result["sample_end_boottime_ns"] = std::to_string(query.sample_end_boottime);
  auto &history = result["history"];
  history["epoch"] = std::to_string(query.history.epoch);
  history["oldest_sequence"] = std::to_string(query.history.oldest_sequence);
  history["newest_sequence"] = std::to_string(query.history.newest_sequence);
  history["coverage_generation"] =
      std::to_string(query.history.coverage_generation);
  history["count"] = number(query.history.count);
  history["observer_active"] = query.history.observer_active != 0;
  auto &policy = result["policy"];
  policy["enabled"] = query.policy.enabled != 0;
#define YZ_HEALTH_COUNT(field) policy[#field] = number(query.policy.field)
  YZ_HEALTH_COUNT(states_current);
  YZ_HEALTH_COUNT(states_peak);
  YZ_HEALTH_COUNT(preparing);
  YZ_HEALTH_COUNT(native_active);
  YZ_HEALTH_COUNT(module_groups_active);
  YZ_HEALTH_COUNT(holders_current);
  YZ_HEALTH_COUNT(holders_peak);
  YZ_HEALTH_COUNT(retired_current);
  YZ_HEALTH_COUNT(restore_inflight);
  YZ_HEALTH_COUNT(retry_waiting);
  YZ_HEALTH_COUNT(last_restore_kind);
#undef YZ_HEALTH_COUNT
#define YZ_HEALTH_TOTAL(field)                                                 \
  policy[#field] = std::to_string(query.policy.field)
  YZ_HEALTH_TOTAL(oldest_retired_boottime);
  YZ_HEALTH_TOTAL(last_restore_boottime);
  YZ_HEALTH_TOTAL(restore_attempts);
  YZ_HEALTH_TOTAL(restore_failures);
  YZ_HEALTH_TOTAL(restore_successes);
#undef YZ_HEALTH_TOTAL
  policy["last_restore_errno"] = query.policy.last_restore_errno;
  auto &cleanup = result["cleanup"];
  cleanup["queued_owners"] = number(query.cleanup.queued_owners);
  cleanup["inflight_owners"] = number(query.cleanup.inflight_owners);
  cleanup["queue_peak"] = number(query.cleanup.queue_peak);
  cleanup["reconcile_pending"] = query.cleanup.reconcile_pending != 0;
#define YZ_HEALTH_TOTAL(field)                                                 \
  cleanup[#field] = std::to_string(query.cleanup.field)
  YZ_HEALTH_TOTAL(queue_enqueued);
  YZ_HEALTH_TOTAL(queue_overflows);
  YZ_HEALTH_TOTAL(owner_cleanup_calls);
  YZ_HEALTH_TOTAL(owner_index_visits);
  YZ_HEALTH_TOTAL(watch_index_visits);
  YZ_HEALTH_TOTAL(fullscan_overflow);
  YZ_HEALTH_TOTAL(fullscan_enable);
  YZ_HEALTH_TOTAL(fullscan_missing_owner);
  YZ_HEALTH_TOTAL(fullscan_disable);
  YZ_HEALTH_TOTAL(fullscan_entries);
  YZ_HEALTH_TOTAL(alive_checks_publish);
  YZ_HEALTH_TOTAL(alive_checks_scan);
  YZ_HEALTH_TOTAL(exit_worker_runs);
  YZ_HEALTH_TOTAL(retry_worker_runs);
#undef YZ_HEALTH_TOTAL
  return result;
}

json::Value daemon_health(Host &host) {
  health::ViolaIdentityContext identity;
  identity.control_fd = host.native_handle();
  const auto replies = health::query_all(
      health::kQueryTimeoutMs, health::verify_viola_identity, &identity);
  json::Value result = json::Value::array();
  for (size_t index = 0; index < replies.size(); ++index) {
    const auto &reply = replies[index];
    json::Value item = json::Value::object();
    item["abi_id"] = number(static_cast<uint32_t>(index + 1));
    item["abi"] = index == 0 ? "armeabi-v7a" : "arm64-v8a";
    item["source"] = "live";
    item["state"] = availability_name(reply.availability);
    item["error"] = reply.error;
    if (reply.availability == health::Availability::Available) {
      const auto &snapshot = reply.snapshot;
      const char *backend = nullptr;
      if (reply.execution_backend == health::ExecutionBackend::Tango)
        backend = "tango";
      else
        backend = reply.execution_backend == health::ExecutionBackend::Native
                      ? "native"
                      : "unknown";
      item["execution_backend"] = backend;
      item["pid"] = number(snapshot.pid);
      item["start_ticks"] = std::to_string(snapshot.start_ticks);
      item["sampled_boottime_ns"] =
          std::to_string(snapshot.sampled_boottime_ns);
      item["ready"] = (snapshot.flags & health::Ready) != 0;
      item["history_available"] =
          (snapshot.flags & health::HistoryAvailable) != 0;
      item["persistence_pending"] =
          (snapshot.flags & health::PersistencePending) != 0;
      item["committed_valid"] = (snapshot.flags & health::CommittedValid) != 0;
      item["catalog_frozen"] = (snapshot.flags & health::CatalogFrozen) != 0;
      item["reboot_required"] = (snapshot.flags & health::RebootRequired) != 0;
      item["reader_state"] = reader_name(snapshot.reader_state);
      item["read_error"] = snapshot.read_error;
      item["save_error"] = snapshot.save_error;
      item["catalog_error"] = snapshot.catalog_error;
#define YZ_HEALTH_TOTAL(field) item[#field] = std::to_string(snapshot.field)
      YZ_HEALTH_TOTAL(consumed_epoch);
      YZ_HEALTH_TOTAL(consumed_cursor);
      YZ_HEALTH_TOTAL(newest_observed);
      YZ_HEALTH_TOTAL(committed_epoch);
      YZ_HEALTH_TOTAL(committed_cursor);
      YZ_HEALTH_TOTAL(read_retry_at_ns);
      YZ_HEALTH_TOTAL(read_failures);
      YZ_HEALTH_TOTAL(save_retry_at_ns);
      YZ_HEALTH_TOTAL(save_failures);
      YZ_HEALTH_TOTAL(last_saved_boottime_ns);
      YZ_HEALTH_TOTAL(last_read_boottime_ns);
      YZ_HEALTH_TOTAL(poll_returns);
      YZ_HEALTH_TOTAL(poll_timeouts);
      YZ_HEALTH_TOTAL(history_drains);
#undef YZ_HEALTH_TOTAL
      item["bound_sessions"] = number(snapshot.bound_sessions);
      item["unbound_sessions"] = number(snapshot.unbound_sessions);
      item["companions"] = number(snapshot.companions);
      item["starting_companions"] = number(snapshot.starting_companions);
      item["terminating_companions"] = number(snapshot.terminating_companions);
      item["catalog_sha256"] =
          std::string(snapshot.catalog_sha256, sizeof(snapshot.catalog_sha256));
    }
    result.push_back(item);
  }
  return result;
}

} // namespace yzctl

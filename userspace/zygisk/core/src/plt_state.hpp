#pragma once

#include <lsplt.hpp>

#include <algorithm>
#include <atomic>

namespace yukizygisk {

inline bool
published_failure(const std::vector<lsplt::RegistrationResult> &entries) {
  return std::any_of(entries.begin(), entries.end(), [](const auto &entry) {
    return entry.ever_published &&
           entry.status != lsplt::CommitStatus::Applied &&
           entry.status != lsplt::CommitStatus::NoChange;
  });
}

inline bool published_failure(const lsplt::CommitReport &report) {
  return published_failure(report.registrations);
}

inline bool published_failure(const lsplt::HookBatchReport &report) {
  return published_failure(report.results) ||
         published_failure(report.recoveries);
}

struct PltLifetime {
  static_assert(std::atomic<bool>::is_always_lock_free);
  std::atomic<bool> retain_core{false};

  template <typename Report> void observe(const Report &report) {
    if (published_failure(report))
      retain_core.store(true);
  }
};

inline PltLifetime plt_lifetime;

inline lsplt::CommitReport commit_plt(bool cached) {
  auto report =
      cached ? lsplt::CommitHookCachedDetailed() : lsplt::CommitHookDetailed();
  plt_lifetime.observe(report);
  return report;
}

inline lsplt::HookRequest restore_plt(dev_t dev, ino_t inode,
                                      std::string_view symbol, void *original,
                                      void *expected_current) {
  lsplt::HookRequest request{dev, inode, symbol, original};
  request.operation = lsplt::HookOperation::Restore;
  request.expected_current = expected_current;
  return request;
}

inline lsplt::HookBatchReport
apply_plt(bool cached, const std::vector<lsplt::HookRequest> &requests) {
  auto report = cached ? lsplt::ApplyHooksCachedDetailed(requests)
                       : lsplt::ApplyHooksDetailed(requests);
  plt_lifetime.observe(report);
  for (size_t i = 0; i < requests.size() && i < report.results.size(); ++i) {
    const auto &result = report.results[i];
    if (requests[i].operation == lsplt::HookOperation::Restore &&
        (result.error == lsplt::HookError::SlotConflict ||
         result.rollback_error == lsplt::HookError::SlotConflict))
      plt_lifetime.retain_core.store(true);
  }
  return report;
}

inline bool plt_request_succeeded(const lsplt::HookBatchReport &report,
                                  size_t index) {
  if (report.rollback_pending || index >= report.results.size())
    return false;
  const auto &result = report.results[index];
  return (result.status == lsplt::CommitStatus::Applied ||
          result.status == lsplt::CommitStatus::NoChange) &&
         !result.slots.empty() &&
         std::all_of(result.slots.begin(), result.slots.end(),
                     [&](const auto &slot) {
                       return slot.observed && slot.permissions_restored &&
                              slot.after ==
                                  reinterpret_cast<uintptr_t>(result.callback);
                     });
}

enum class ArtHookState {
  NotAttempted,
  Deferred,
  Installing,
  Installed,
  FailedClean,
  NeedsCleanup,
  Retired
};

struct ArtHookLifecycle {
  ArtHookState state = ArtHookState::NotAttempted;
  bool unhook_required = false;

  bool begin(bool early) {
    if (state != ArtHookState::NotAttempted &&
        (early || state != ArtHookState::Deferred))
      return false;
    state = ArtHookState::Installing;
    return true;
  }

  void reject_probe(bool early) {
    state = early ? ArtHookState::Deferred : ArtHookState::FailedClean;
  }

  template <typename Report>
  void finish(bool early, bool committed, bool installed, bool dirty,
              const Report &report) {
    unhook_required |= committed;
    if (installed)
      state = ArtHookState::Installed;
    else if (dirty || report.rollback_pending)
      state = ArtHookState::NeedsCleanup;
    else
      state = early && !published_failure(report) ? ArtHookState::Deferred
                                                  : ArtHookState::FailedClean;
  }

  bool needs_cleanup() const {
    return state == ArtHookState::Installed ||
           state == ArtHookState::NeedsCleanup;
  }

  bool finish_cleanup(bool success) {
    state = success ? ArtHookState::Retired : ArtHookState::NeedsCleanup;
    return success;
  }
};

inline const char *art_hook_state_name(ArtHookState state) {
  switch (state) {
  case ArtHookState::NotAttempted:
    return "not-attempted";
  case ArtHookState::Deferred:
    return "deferred";
  case ArtHookState::Installing:
    return "installing";
  case ArtHookState::Installed:
    return "installed";
  case ArtHookState::FailedClean:
    return "failed-clean";
  case ArtHookState::NeedsCleanup:
    return "needs-cleanup";
  case ArtHookState::Retired:
    return "retired";
  }
  return "unknown";
}

inline const char *hook_error_name(lsplt::HookError error) {
  switch (error) {
  case lsplt::HookError::None:
    return "none";
  case lsplt::HookError::MapUnavailable:
    return "map-unavailable";
  case lsplt::HookError::InvalidElf:
    return "invalid-elf";
  case lsplt::HookError::SymbolNotFound:
    return "symbol-not-found";
  case lsplt::HookError::InvalidSlot:
    return "invalid-slot";
  case lsplt::HookError::InconsistentOriginal:
    return "inconsistent-original";
  case lsplt::HookError::ProtectFailed:
    return "protect-failed";
  case lsplt::HookError::SlotConflict:
    return "slot-conflict";
  case lsplt::HookError::PendingRollback:
    return "pending-rollback";
  case lsplt::HookError::OriginalUnavailable:
    return "original-unavailable";
  case lsplt::HookError::InvalidRequest:
    return "invalid-request";
  }
  return "unknown";
}

} // namespace yukizygisk

#pragma once

#include <lsplt.hpp>

#include <algorithm>
#include <atomic>

namespace yukizygisk {

inline bool published_failure(const lsplt::CommitReport &report) {
  return std::any_of(report.registrations.begin(), report.registrations.end(),
                     [](const auto &entry) {
                       return entry.ever_published &&
                              entry.status != lsplt::CommitStatus::Applied &&
                              entry.status != lsplt::CommitStatus::NoChange;
                     });
}

struct PltLifetime {
  static_assert(std::atomic<bool>::is_always_lock_free);
  std::atomic<bool> retain_core{false};

  void observe(const lsplt::CommitReport &report) {
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

  void finish(bool early, bool committed, bool installed, bool dirty,
              const lsplt::CommitReport &report) {
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
  }
  return "unknown";
}

} // namespace yukizygisk

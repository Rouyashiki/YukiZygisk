#pragma once

#include "userspace/zygisk/fixed_policy.hpp"

#include <optional>
#include <set>

namespace yukizygisk::policy_rules {

inline constexpr char kHeader[] = "# YukiZygisk daemon ";
inline constexpr std::string_view kTemplate[] = {
#include "module_rules.inc"
};

// Older scan records used "1" for any nonempty file. Keep that conservative
// result for rule files whose contents cannot be safely read.
inline constexpr char kUnknownRules[] = "1";

inline bool comparable_rules(std::string_view text) {
  // Host parsers can start a new statement after a semicolon, even on a
  // comment line. Our generator emits one statement per line.
  return text != kUnknownRules && text.find(';') == text.npos;
}

inline std::optional<std::set<std::string_view>>
rule_statements(std::string_view text) {
  if (!comparable_rules(text))
    return std::nullopt;
  std::set<std::string_view> statements;
  bool declared = false;
  while (!text.empty()) {
    const auto end = text.find('\n');
    const auto line = crash::trim(text.substr(0, end));
    if (!line.empty() && line.front() != '#') {
      // The host applies each line immediately. Only the generated file type
      // needs to be declared before an attribute assignment or grant uses it.
      if (line == "type " YZ_FIXED_FILE_TYPE " file_type")
        declared = true;
      else if (!declared && line.find(" " YZ_FIXED_FILE_TYPE " ") != line.npos)
        return std::nullopt;
      statements.insert(line);
    }
    if (end == text.npos)
      break;
    text.remove_prefix(end + 1);
  }
  return statements;
}

inline bool keeps_all_rules(std::string_view before, std::string_view after) {
  if (before.empty())
    return true;
  if (before == after)
    return comparable_rules(before);
  const auto old_rules = rule_statements(before);
  const auto new_rules = rule_statements(after);
  return old_rules && new_rules &&
         std::includes(new_rules->begin(), new_rules->end(), old_rules->begin(),
                       old_rules->end());
}

inline void replace(std::string &line, std::string_view token,
                    const std::string &value) {
  auto pos = line.find(token);
  while (pos != std::string::npos) {
    line.replace(pos, token.size(), value);
    pos = line.find(token, pos + value.size());
  }
}

inline std::string render(const std::string &provider,
                          const std::string &daemon, bool memfd) {
  std::string text = kHeader + provider + " " + daemon + "\n";
  for (auto line : kTemplate) {
    if (!memfd && line.find(" memfd_file ") != line.npos)
      continue;
    std::string statement(line);
    replace(statement, "$daemon", daemon);
    text += statement + "\n";
  }
  return text;
}

enum class RuleMatch { Current, MemfdClassChanged, Mismatch };

inline RuleMatch compare_published_rules(const std::string &saved,
                                         const std::string &provider,
                                         const std::string &daemon,
                                         bool memfd) {
  const auto published = rule_statements(saved);
  if (published) {
    const auto matches = [&](bool present) {
      const auto expected = render(provider, daemon, present);
      return published == rule_statements(expected);
    };
    if (matches(memfd))
      return RuleMatch::Current;
    if (matches(!memfd))
      return RuleMatch::MemfdClassChanged;
  }
  return RuleMatch::Mismatch;
}

inline bool saved_identity(const std::string &saved, std::string *provider,
                           std::string *daemon) {
  constexpr size_t begin = sizeof(kHeader) - 1;
  const auto split = saved.find(' ', begin);
  const auto end = saved.find('\n');
  if (saved.compare(0, begin, kHeader) || split == saved.npos ||
      end == saved.npos || end <= split + 1)
    return false;
  *provider = saved.substr(begin, split - begin);
  *daemon = saved.substr(split + 1, end - split - 1);
  return (*provider == "ksu" || *provider == "apatch") &&
         fixed_policy::domain_name(*daemon) && *daemon != "self";
}

inline bool matches_config(const std::string &rules,
                           const json::Value &settings) {
  yz_fixed_policy_config config{};
  std::string provider, daemon;
  // Either memfd class layout may have been published before an OS update.
  return fixed_policy::encode(settings, &config) && config.enabled &&
         saved_identity(rules, &provider, &daemon) &&
         compare_published_rules(rules, provider, daemon, false) !=
             RuleMatch::Mismatch;
}

} // namespace yukizygisk::policy_rules

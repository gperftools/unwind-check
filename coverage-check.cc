/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#include "coverage-check.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

// Merges `ranges` into sorted, non-overlapping [start, end)
// spans. Merging (beyond just sorting) buys us little efficiency and
// deals with 0-sized FDEs we see sometimes.
std::vector<std::pair<uint64_t, uint64_t>> MergeRanges(std::vector<std::pair<uint64_t, uint64_t>> ranges) {
  absl::c_sort(ranges);
  std::vector<std::pair<uint64_t, uint64_t>> merged;
  for (const auto& r : ranges) {
    if (!merged.empty() && r.first <= merged.back().second) {
      merged.back().second = std::max(merged.back().second, r.second);
    } else {
      merged.push_back(r);
    }
  }
  return merged;
}

// Bytes of [start, end) that land in none of coverage ranges (sorted,
// non-overlapping, per MergeRanges).
uint64_t UncoveredBytes(uint64_t start, uint64_t end, const std::vector<std::pair<uint64_t, uint64_t>>& coverage) {
  auto it = absl::c_lower_bound(coverage, start,
                                [](const std::pair<uint64_t, uint64_t>& iv, uint64_t v) { return iv.second <= v; });
  uint64_t cursor = start;
  uint64_t uncovered = 0;
  for (; it != coverage.end() && it->first < end && cursor < end; ++it) {
    if (it->first > cursor) {
      uncovered += std::min(it->first, end) - cursor;
    }
    cursor = std::max(cursor, std::min(it->second, end));
  }
  if (cursor < end) {
    uncovered += end - cursor;
  }
  return uncovered;
}

}  // namespace

std::vector<FDEResult> CheckUncoveredSymbols(const ELFImage& image,
                                             const std::vector<std::pair<uint64_t, uint64_t>>& fde_ranges) {
  std::vector<std::pair<uint64_t, uint64_t>> coverage = MergeRanges(fde_ranges);
  std::vector<FDEResult> results;
  absl::flat_hash_set<uint64_t> flagged;
  for (const FuncSymbol& sym : image.func_symbols()) {
    if (sym.size == 0 || !flagged.insert(sym.vaddr).second) {
      continue;
    }
    // PLT stubs are linker-generated and already exempted from FDE
    // checking entirely; they routinely have no FDE of their own and
    // that is not a finding.
    if (!image.IsExecutable(sym.vaddr, sym.size) || image.InPLT(sym.vaddr, sym.size)) {
      continue;
    }
    uint64_t uncovered = UncoveredBytes(sym.vaddr, sym.vaddr + sym.size, coverage);
    if (uncovered == 0) {
      continue;
    }
    FDEResult r;
    r.pc_begin = sym.vaddr;
    r.pc_end = sym.vaddr + sym.size;
    r.verdict = Verdict::kReview;
    std::string message = uncovered == sym.size
                              ? "no FDE covers this symbol at all"
                              : absl::StrFormat("no FDE covers %d of its %d bytes", uncovered, sym.size);
    r.findings.push_back(Finding{Finding::Severity::kReview, sym.vaddr, std::move(message), 0});
    results.push_back(std::move(r));
  }
  return results;
}

}  // namespace unwind_analysis

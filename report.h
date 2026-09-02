/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#ifndef REPORT_H_
#define REPORT_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "absl/container/flat_hash_map.h"
#include "cfi-table.h"
#include "disasm.h"
#include "elf-image.h"
#include "fde-checker.h"
#include "symbolizer.h"

namespace unwind_analysis {

struct ReportOptions {
  bool show_blessed = false;  // also list blessed FDEs
  bool summary_only = false;  // just the histogram
  // Restrict the listing (not the trailing summary line) to just this
  // verdict category. Independent of each other: setting both lists the
  // union, i.e. everything but blessed (and blessed only if show_blessed
  // is also on).
  bool only_mismatch = false;  // list only kMismatch
  bool only_review = false;    // list only kReview / kReviewLight
};

// Optional: when given, each finding gets a few real instructions of
// context around it (disasm text paired with the declared CFI row)
// instead of the bare single "at: <insn>" line. `cfi_by_pc_begin` is
// keyed by FDEResult::pc_begin (== CFI::pc_begin). Leaving this out
// entirely -- the default -- costs nothing and keeps the old behavior.
struct ReportContext {
  const ELFImage* image = nullptr;
  Disassembler* disasm = nullptr;
  const absl::flat_hash_map<uint64_t, const CFI*>* cfi_by_pc_begin = nullptr;
};

struct Summary {
  size_t blessed = 0;
  // REVIEW-LIGHT: a REVIEW whose sole unresolved indirect jump was
  // recovered by guessing (see FDEChecker::CheckWithGuessing). Counted
  // separately from `review` -- it still exits non-zero, same as any
  // other review, but reads as "mostly understood" rather than "beyond
  // this version's heuristics".
  size_t review_light = 0;
  size_t review = 0;
  size_t mismatch = 0;

  size_t total() const {
    return blessed + review_light + review + mismatch;
  }
};

Summary Summarize(const std::vector<FDEResult>& results);

// Prints the per-FDE report and the trailing histogram to stdout.
// `symbolizer` is consulted for names and, when available, source lines.
void PrintReport(const std::vector<FDEResult>& results, Symbolizer* symbolizer, const ReportOptions& options,
                 const ReportContext* context = nullptr);

}  // namespace unwind_analysis

#endif  // REPORT_H_

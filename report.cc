/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "report.h"

#include <stdio.h>

#include <algorithm>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "diagnostics.h"

namespace unwind_analysis {

namespace {

std::string Location(Symbolizer* sym, uint64_t pc) {
  std::string source = sym->SourceLine(pc);
  if (source.empty()) {
    return absl::StrFormat("0x%x", pc);
  }
  return absl::StrFormat("0x%x (%s)", pc, source);
}

void PrintOne(const FDEResult& r, Symbolizer* sym, const ReportContext* ctx) {
  std::string name = sym->Name(r.pc_begin);
  if (name.empty()) {
    name = "<no symbol>";
  }
  absl::PrintF("%-8s %s  [0x%x - 0x%x)%s\n", absl::StrCat(r.verdict), name, r.pc_begin, r.pc_end,
               r.signal_frame ? "  (signal frame)" : "");

  // A window of real instructions plus their declared CFI row -- much
  // more diagnostic than the single "at:" line below -- if the caller
  // gave us enough to build one for this FDE.
  std::vector<ListedInsn> listing;
  if (ctx != nullptr && ctx->cfi_by_pc_begin != nullptr) {
    auto it = ctx->cfi_by_pc_begin->find(r.pc_begin);
    if (it != ctx->cfi_by_pc_begin->end()) {
      listing = ListInstructions(*ctx->image, ctx->disasm, *it->second);
    }
  }

  for (const Finding& f : r.findings) {
    if (f.pc == 0) {
      absl::PrintF("  %s\n", f.message);
      continue;
    }
    std::string repeats = f.repeats > 0 ? absl::StrFormat(" [and at %d more addresses]", f.repeats) : "";
    absl::PrintF("  %s: %s%s\n", Location(sym, f.pc), f.message, repeats);
    std::string window;
    if (!listing.empty() && AppendFindingContext(listing, f, DiagnosticsOptions{}, &window)) {
      absl::PrintF("%s", window);
    }
  }

  // Not a Finding -- these carry no severity of their own, they're just
  // what made a REVIEW-LIGHT verdict possible in the first place, kept
  // visible so a human can judge the guess rather than take it on faith.
  for (const GuessedJumpTable& gjt : r.guessed_jump_tables) {
    absl::PrintF("  %s: guessed %d switch-table entries (table at 0x%x), targets:\n", Location(sym, gjt.pc),
                 gjt.targets.size(), gjt.table_addr);
    for (uint64_t target : gjt.targets) {
      absl::PrintF("      -> %s\n", Location(sym, target));
    }
  }
}

}  // namespace

Summary Summarize(const std::vector<FDEResult>& results) {
  Summary s;
  for (const FDEResult& r : results) {
    switch (r.verdict) {
      case Verdict::kBlessed:
        s.blessed++;
        break;
      case Verdict::kReviewLight:
        s.review_light++;
        break;
      case Verdict::kReview:
        s.review++;
        break;
      case Verdict::kMismatch:
        s.mismatch++;
        break;
    }
  }
  return s;
}

void PrintReport(const std::vector<FDEResult>& results, Symbolizer* symbolizer, const ReportOptions& options,
                 const ReportContext* context) {
  if (!options.summary_only) {
    // Every address the report will mention, resolved in one addr2line
    // run rather than one per finding.
    std::vector<uint64_t> interesting;
    for (const FDEResult& r : results) {
      if (r.verdict == Verdict::kBlessed && !options.show_blessed) {
        continue;
      }
      interesting.push_back(r.pc_begin);
      for (const Finding& f : r.findings) {
        interesting.push_back(f.pc);
      }
      for (const GuessedJumpTable& gjt : r.guessed_jump_tables) {
        interesting.push_back(gjt.pc);
        interesting.insert(interesting.end(), gjt.targets.begin(), gjt.targets.end());
      }
    }
    symbolizer->Prepare(interesting);

    // Mismatches first: they are the findings that claim something is
    // actually wrong.
    std::vector<const FDEResult*> ordered;
    ordered.reserve(results.size());
    for (const FDEResult& r : results) {
      if (r.verdict == Verdict::kBlessed && !options.show_blessed) {
        continue;
      }
      ordered.push_back(&r);
    }
    std::stable_sort(ordered.begin(), ordered.end(), [](const FDEResult* a, const FDEResult* b) {
      return static_cast<int>(a->verdict) > static_cast<int>(b->verdict);
    });
    for (const FDEResult* r : ordered) {
      PrintOne(*r, symbolizer, context);
    }
    if (!ordered.empty()) {
      absl::PrintF("\n");
    }
  }

  Summary s = Summarize(results);
  absl::PrintF("%d FDEs: %d blessed, %d review-light, %d review, %d mismatch\n", s.total(), s.blessed, s.review_light,
               s.review, s.mismatch);
  if (!symbolizer->disabled_reason().empty()) {
    absl::PrintF("(source lines unavailable: %s)\n", symbolizer->disabled_reason());
  }
}

}  // namespace unwind_analysis

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "report.h"

#include <stdio.h>

#include <algorithm>
#include <string>

#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

std::string Location(Symbolizer* sym, uint64_t pc) {
  std::string source = sym->SourceLine(pc);
  if (source.empty()) {
    return absl::StrFormat("0x%x", pc);
  }
  return absl::StrFormat("0x%x (%s)", pc, source);
}

void PrintOne(const FDEResult& r, Symbolizer* sym) {
  std::string name = sym->Name(r.pc_begin);
  if (name.empty()) {
    name = "<no symbol>";
  }
  absl::PrintF("%-8s %s  [0x%x - 0x%x)%s\n", VerdictName(r.verdict), name, r.pc_begin, r.pc_end,
               r.signal_frame ? "  (signal frame)" : "");
  for (const Finding& f : r.findings) {
    if (f.pc == 0 && f.insn_text.empty()) {
      absl::PrintF("  %s\n", f.message);
      continue;
    }
    std::string repeats = f.repeats > 0 ? absl::StrFormat(" [and at %d more addresses]", f.repeats) : "";
    absl::PrintF("  %s: %s%s\n", Location(sym, f.pc), f.message, repeats);
    if (!f.insn_text.empty()) {
      absl::PrintF("      at: %s\n", f.insn_text);
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

void PrintReport(const std::vector<FDEResult>& results, Symbolizer* symbolizer, const ReportOptions& options) {
  if (!options.summary_only) {
    // Every address the report will mention, resolved in one addr2line
    // run rather than one per finding.
    std::vector<uint64_t> interesting;
    for (const FDEResult& r : results) {
      if (r.verdict == Verdict::kBlessed && !options.verbose) {
        continue;
      }
      interesting.push_back(r.pc_begin);
      for (const Finding& f : r.findings) {
        interesting.push_back(f.pc);
      }
    }
    symbolizer->Prepare(interesting);

    // Mismatches first: they are the findings that claim something is
    // actually wrong.
    std::vector<const FDEResult*> ordered;
    ordered.reserve(results.size());
    for (const FDEResult& r : results) {
      if (r.verdict == Verdict::kBlessed && !options.verbose) {
        continue;
      }
      ordered.push_back(&r);
    }
    std::stable_sort(ordered.begin(), ordered.end(), [](const FDEResult* a, const FDEResult* b) {
      return static_cast<int>(a->verdict) > static_cast<int>(b->verdict);
    });
    for (const FDEResult* r : ordered) {
      PrintOne(*r, symbolizer);
    }
    if (!ordered.empty()) {
      absl::PrintF("\n");
    }
  }

  Summary s = Summarize(results);
  absl::PrintF("%d FDEs: %d blessed, %d review, %d mismatch\n", s.total(), s.blessed, s.review, s.mismatch);
  if (!symbolizer->disabled_reason().empty()) {
    absl::PrintF("(source lines unavailable: %s)\n", symbolizer->disabled_reason());
  }
}

}  // namespace unwind_analysis

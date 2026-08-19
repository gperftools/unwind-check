/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef REPORT_H_
#define REPORT_H_

#include <stddef.h>

#include <vector>

#include "fde-checker.h"
#include "symbolizer.h"

namespace unwind_analysis {

struct ReportOptions {
  bool verbose = false;       // also list blessed FDEs
  bool summary_only = false;  // just the histogram
};

struct Summary {
  size_t blessed = 0;
  size_t review = 0;
  size_t mismatch = 0;

  size_t total() const {
    return blessed + review + mismatch;
  }
};

Summary Summarize(const std::vector<FdeResult>& results);

// Prints the per-FDE report and the trailing histogram to stdout.
// `symbolizer` is consulted for names and, when available, source lines.
void PrintReport(const std::vector<FdeResult>& results, Symbolizer* symbolizer, const ReportOptions& options);

}  // namespace unwind_analysis

#endif  // REPORT_H_

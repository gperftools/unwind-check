/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef FDE_CHECKER_H_
#define FDE_CHECKER_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "abs-state.h"
#include "cfi-table.h"
#include "disasm.h"
#include "elf-image.h"

namespace unwind_analysis {

enum class Verdict {
  kBlessed,   // every instruction's declared CFI matched what the code does
  kReview,    // nothing looked wrong, but something was beyond our heuristics
  kMismatch,  // the CFI contradicts the code
};

const char* VerdictName(Verdict v);

struct Finding {
  enum class Severity { kReview, kMismatch };

  Severity severity = Severity::kReview;
  uint64_t pc = 0;
  std::string message;
  std::string insn_text;
  // How many further instructions produced this same message. Reports
  // would be unreadable otherwise: one unverifiable CFA rule easily
  // covers a hundred instructions.
  int repeats = 0;
};

struct FdeResult {
  uint64_t fde_addr = 0;
  uint64_t pc_begin = 0;
  uint64_t pc_end = 0;
  bool signal_frame = false;
  Verdict verdict = Verdict::kBlessed;
  std::vector<Finding> findings;
  size_t instructions_checked = 0;
};

class FdeChecker {
 public:
  struct Options {
    // Also require that callee-saved registers with no explicit rule
    // still hold their entry value. Off by default: hand-written
    // assembly breaks this constantly and it drowns the report.
    bool check_unmentioned_callee_saved = false;
    // Report bytes inside the FDE that the control-flow walk never
    // reached. Usually exception landing pads or jump-table targets.
    bool report_coverage_gaps = true;
    size_t max_findings_per_fde = 8;
    size_t max_iterations = 200000;
  };

  FdeChecker(const ElfImage& image, Disassembler& disasm, const Options& options)
      : image_(image), disasm_(disasm), options_(options) {
  }

  // `at_function_entry` says a function symbol starts exactly at
  // cfi.pc_begin. When it does, the FDE's first row must describe the
  // canonical x86-64 entry state, and we say so if it does not. When it
  // does not -- a cold fragment, a PLT stub -- there is nothing to
  // compare the first row against and we take it as given.
  FdeResult Check(const FdeCfi& cfi, bool at_function_entry) const;

 private:
  const ElfImage& image_;
  Disassembler& disasm_;
  Options options_;
};

}  // namespace unwind_analysis

#endif  // FDE_CHECKER_H_

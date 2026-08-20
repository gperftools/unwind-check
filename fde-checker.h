/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef FDE_CHECKER_H_
#define FDE_CHECKER_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <utility>
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

struct FDEResult {
  uint64_t fde_addr = 0;
  uint64_t pc_begin = 0;
  uint64_t pc_end = 0;
  bool signal_frame = false;
  Verdict verdict = Verdict::kBlessed;
  std::vector<Finding> findings;
  size_t instructions_checked = 0;
};

class FDEChecker {
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

  // `all_cfis` is every known checkable FDE, sorted by pc_begin. It backs
  // two things: validating that a resolved switch-table entry lands inside
  // *some* FDE (initial-switch-tables-plan.md §3.3) -- not necessarily this
  // one, since a shared, ICF'd throw block can be reached from a table
  // 1.2 MB away in a different FDE (§5) -- and looking up the declared CFI
  // row at a jump target outside this FDE's own range, so a tail call or a
  // switch-table dispatch into another FDE (typically a `.cold` fragment)
  // can be checked against what that FDE actually declares instead of
  // guessed at via the tail-call ABI convention. Leaving it empty simply
  // means neither lookup ever succeeds, which is safe -- it just costs the
  // precision these features exist to recover, and any jump whose target
  // has no entry here (PLT stubs included, since the caller excludes them)
  // falls back to the ABI-based check.
  FDEChecker(const ELFImage& image, Disassembler* disasm, const Options& options,
             std::vector<std::pair<std::pair<uint64_t, uint64_t>, const CFI*>> all_cfis = {})
      : image_(image), disasm_(disasm), options_(options), cfi_index_(std::move(all_cfis)) {
  }

  // `at_function_entry` says a function symbol starts exactly at
  // cfi.pc_begin. When it does, the FDE's first row must describe the
  // canonical x86-64 entry state, and we say so if it does not. When it
  // does not -- a cold fragment, a PLT stub -- there is nothing to
  // compare the first row against and we take it as given.
  FDEResult Check(const CFI& cfi, bool at_function_entry) const;

 private:
  // Reads and validates the switch table at `table_addr` with `entries`
  // int32 entries, all-or-nothing per initial-switch-tables-plan.md §3.3:
  // any entry failing any check discards the whole table. Returns the
  // resolved absolute targets, or nullopt.
  std::optional<std::vector<uint64_t>> ResolveJumpTable(uint64_t table_addr, uint64_t entries) const;
  bool LandsInsideSomeFDE(uint64_t addr) const;
  // The checkable FDE covering `pc`, or nullptr if none does.
  const CFI* CFIContaining(uint64_t pc) const;

  const ELFImage& image_;
  Disassembler* const disasm_;
  Options options_;
  std::vector<std::pair<std::pair<uint64_t, uint64_t>, const CFI*>> cfi_index_;
};

}  // namespace unwind_analysis

#endif  // FDE_CHECKER_H_

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
  kBlessed,      // every instruction's declared CFI matched what the code does
  kReviewLight,  // a REVIEW that guessing fully recovered from -- see below
  kReview,       // nothing looked wrong, but something was beyond our heuristics
  kMismatch,     // the CFI contradicts the code
};

template <typename Sink>
void AbslStringify(Sink& sink, Verdict v) {
  switch (v) {
    case Verdict::kBlessed:
      sink.Append("BLESSED");
      return;
    case Verdict::kReviewLight:
      sink.Append("REVIEW-LIGHT");
      return;
    case Verdict::kReview:
      sink.Append("REVIEW");
      return;
    case Verdict::kMismatch:
      sink.Append("MISMATCH");
      return;
  }
  sink.Append("?");
}

struct Finding {
  enum class Severity { kReview, kMismatch };

  Severity severity = Severity::kReview;
  uint64_t pc = 0;
  std::string message;
  // How many further instructions produced this same message. Reports
  // would be unreadable otherwise: one unverifiable CFA rule easily
  // covers a hundred instructions.
  int repeats = 0;
};

// One switch-table dispatch resolved by guessing rather than a
// compiler-declared bound (see FDEChecker::CheckWithGuessing). Purely
// diagnostic: it never feeds back into a verdict, only into what a human
// (or --inspect) is shown about why a REVIEW-LIGHT FDE reads as it does.
struct GuessedJumpTable {
  uint64_t pc = 0;  // the jmp instruction's address
  uint64_t table_addr = 0;
  std::vector<uint64_t> targets;  // resolved absolute addresses, in index order
};

struct FDEResult {
  uint64_t fde_addr = 0;
  uint64_t pc_begin = 0;
  uint64_t pc_end = 0;
  bool signal_frame = false;
  Verdict verdict = Verdict::kBlessed;
  std::vector<Finding> findings;
  size_t instructions_checked = 0;

  // Set by a normal (guessing-disabled) Check() when it found exactly one
  // indirect jump whose table shape (base, index register, entry width)
  // fully resolved but whose bound did not -- the sole precondition
  // CheckWithGuessing requires before it will even attempt a guessing
  // retry. Left unset when no such jump exists, or when more than one
  // does: guessing is only attempted when it is the FDE's one point of
  // uncertainty of this specific kind, not a general "try harder" knob.
  std::optional<uint64_t> guessable_jump_pc;

  // Populated only by a guessing-enabled Check(): every jump table it
  // resolved by probing instead of a declared bound.
  std::vector<GuessedJumpTable> guessed_jump_tables;
};

// One instruction as the forward dataflow walk reached it: its address
// and the converged abstract state right before it runs -- exactly what
// the declared CFI row at that pc is checked against. Populated only
// when a caller passes a non-null `trace_out` to Check(): diagnostics
// tooling (diagnostics.h) wants this to show the converged state per
// instruction, but the ordinary whole-binary checking path does not, and
// snapshotting an AbsState (a btree_map) for every instruction of every
// FDE in something the size of libc would not be free.
struct InsnTrace {
  uint64_t pc = 0;
  AbsState state;
};

struct FDECheckerOptions {
  const ELFImage* image = nullptr;
  Disassembler* disasm = nullptr;

  // Also require that callee-saved registers with no explicit rule
  // still hold their entry value. Off by default: hand-written
  // assembly breaks this constantly and it drowns the report.
  bool check_unmentioned_callee_saved = false;
  // Report bytes inside the FDE that the control-flow walk never
  // reached. Usually exception landing pads or jump-table targets.
  bool report_coverage_gaps = true;
  size_t max_findings_per_fde = 8;
  size_t max_iterations = 200000;

  // Every known checkable FDE, sorted by pc_begin. It backs two things:
  // validating that a resolved switch-table entry lands inside *some* FDE
  // -- not necessarily this one, since a shared, ICF'd throw block can be
  // reached from a table 1.2 MB away in a different FDE (§5) -- and
  // looking up the declared CFI row at a jump target outside this FDE's
  // own range, so a tail call or a switch-table dispatch into another FDE
  // (typically a `.cold` fragment) can be checked against what that FDE
  // actually declares instead of guessed at via the tail-call ABI
  // convention. Leaving it empty simply means neither lookup ever
  // succeeds, which is safe -- it just costs the precision these features
  // exist to recover, and any jump whose target has no entry here (PLT
  // stubs included, since the caller excludes them) falls back to the
  // ABI-based check.
  std::vector<std::pair<std::pair<uint64_t, uint64_t>, const CFI*>> all_cfis;
};

// `at_function_entry` says a function symbol starts exactly at
// cfi.pc_begin. When it does, the FDE's first row must describe the
// canonical x86-64 entry state, and we say so if it does not. When it
// does not -- a cold fragment, a PLT stub -- there is nothing to
// compare the first row against and we take it as given.
// `trace_out`, when non-null, is filled with one entry per instruction
// the walk actually reached (same order Pass 2 visits them, i.e.
// sorted by pc) -- see InsnTrace. Diagnostics-only; leave it null on
// the normal checking path.
//
// `guessing_enabled` switches on the one heuristic recovery this
// checker does: when an indirect jump's table shape is fully resolved
// (base, index register, entry width) but no compiler-declared bound
// was ever captured for it, probe the table directly instead of
// reporting it unresolved -- see CheckWithGuessing, which is what
// should actually be called from a top level driver; this parameter
// exists so CheckWithGuessing can ask for a second, independent run of
// the same algorithm rather than duplicating it.
FDEResult Check(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry,
                std::vector<InsnTrace>* trace_out = nullptr, bool guessing_enabled = false);

// Runs Check() normally. If the result is a REVIEW whose sole point of
// uncertainty was one table-shaped-but-unbounded indirect jump
// (FDEResult::guessable_jump_pc), retries once with guessing enabled.
// The retry is trusted -- and the returned result downgraded from
// REVIEW to REVIEW-LIGHT, with the retry's guessed_jump_tables attached
// for diagnostics -- only when it comes back fully BLESSED. Any other
// outcome (no guessable jump, or a retry that still finds something)
// returns the original, untouched result: guessing is only ever worth
// reporting when it recovers a clean answer, never as a weaker partial
// one.
FDEResult CheckWithGuessing(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry,
                            std::vector<InsnTrace>* trace_out = nullptr);

}  // namespace unwind_analysis

#endif  // FDE_CHECKER_H_

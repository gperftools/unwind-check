/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#ifndef INSN_SEMANTICS_H_
#define INSN_SEMANTICS_H_

#include <stdint.h>

#include <string>

#include "abs-state.h"
#include "disasm.h"

namespace unwind_analysis {

// What one instruction does to control flow, as far as a function-local
// recursive descent cares.
struct TransferOutcome {
  bool falls_through = true;
  bool has_direct_target = false;
  uint64_t direct_target = 0;
  bool indirect_branch = false;
  bool is_return = false;
  bool is_call = false;

  // Set when this is `jmp *%reg` and reg resolved to a PIC switch-table
  // dispatch: a kJumpTarget value whose index register carries a known
  // upper bound (see AbsVal::bound). The table itself still has to be
  // read and validated by the caller, which owns the ELF image and the
  // FDE's PC range.
  bool has_jump_table = false;
  uint64_t jump_table_addr = 0;
  uint64_t jump_table_entries = 0;

  // Set when this is `jmp *%reg` and reg resolved to a kJumpTarget (table
  // base and index register both known) but no bound was ever captured for
  // the index -- the table shape is right, only the compiler-declared size
  // is missing. Mutually exclusive with has_jump_table: a kJumpTarget sets
  // exactly one of the two, depending on whether AbsVal::Bound() had a
  // value. Guessing mode (FDEChecker::CheckWithGuessing) is what this
  // exists for; the ordinary checking path only uses it to fall back to
  // the same "unresolved indirect jump" review has_jump_table's own
  // resolution failure produces.
  bool has_unbounded_jump_target = false;
  uint64_t unbounded_jump_table_addr = 0;

  // Set when the instruction does something to the stack we decline to
  // model exactly. The FDE gets flagged for review rather than analysed
  // on a guess.
  std::string review_reason;
};

// Which successor of a branch a state is being propagated along.
//
// Transfer() describes what an instruction does on every path out of it.
// TransferEdge() adds what one *particular* successor additionally proves,
// which for a guard branch is the entire point of the branch: `ja` sends
// the out-of-range case away, so its fall-through is where the compared
// value is known to be in range.
enum class BranchEdge { kFallThrough, kTaken };

// The stack-effect semantics table.
//
// Only the instructions that touch rsp/rbp and the callee-saved spill
// slots are modelled precisely: push/pop, add/sub/and/lea on rsp,
// mov to and from [rsp+off] / [rbp+off], call/ret/jmp/jcc, leave. That
// is the same small set objtool, LLVM's CFIInstrInserter and Binary
// Ninja's stack tracker each special-case; nobody lifts all of x86-64
// for this question.
//
// Everything else goes through Zydis's per-operand read/write accounting
// and simply drops the registers it writes to unknown, so an unmodelled
// instruction costs us precision and never correctness.
class InsnSemantics {
 public:
  InsnSemantics() = default;

  TransferOutcome Transfer(const Instruction& insn, AbsState* state) const;

  // Refines `state` with what leaving `insn` along `edge` proves, on top of
  // what Transfer() already applied to it.
  //
  // A no-op for everything except the four unsigned guard branches
  // (`ja`/`jae`/`jbe`/`jb`), and then only on the edge where the compared
  // value is in range, where it turns `AbsState::last_cmp` into a proven
  // bound. This is the only place in the analysis where a comparison
  // becomes a bound -- a cmp on its own sets flags and establishes nothing;
  // it is the branch that picks a side. See AbsState::FlagsGuard.
  //
  // Call it *after* Transfer(), on the caller's own per-edge copy of the
  // post-Transfer state. It is deliberately not folded into Transfer(),
  // which runs before the walk knows which successor it is building; a
  // branch writes neither registers nor flags, so the pre- and
  // post-Transfer states are identical here and the split costs nothing,
  // but the order has to hold.
  void TransferEdge(const Instruction& insn, BranchEdge edge, AbsState* state) const;

  // DWARF register number for an x86 register, or -1 if it is not one of
  // the 16 GPRs. Sub-registers map to their 64-bit parent, which is what
  // we want for clobbering: writing %eax makes %rax untracked too.
  static int DWARFRegOf(ZydisRegister reg);

  // True only for the full 64-bit spelling of one of the 16 GPRs. Reading
  // %eax does not yield the value we are tracking in %rax, so only these
  // count as reads -- and RIP/RFLAGS/the MMX registers are deliberately
  // excluded even though they too are 64 bits wide (see the definition).
  static bool IsFull64(ZydisRegister reg);

 private:
  void ClobberWrites(const Instruction& insn, AbsState* state) const;
};

}  // namespace unwind_analysis

#endif  // INSN_SEMANTICS_H_

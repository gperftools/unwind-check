/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef INSN_SEMANTICS_H_
#define INSN_SEMANTICS_H_

#include <stdint.h>

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
  // FDE's PC range -- see initial-switch-tables-plan.md §3.3.
  bool has_jump_table = false;
  uint64_t jump_table_addr = 0;
  uint64_t jump_table_entries = 0;

  // Set when the instruction does something to the stack we decline to
  // model exactly. The FDE gets flagged for review rather than analysed
  // on a guess.
  const char* review_reason = nullptr;
};

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

  // DWARF register number for an x86 register, or -1 if it is not one of
  // the 16 GPRs. Sub-registers map to their 64-bit parent, which is what
  // we want for clobbering: writing %eax makes %rax untracked too.
  static int DWARFRegOf(unsigned reg);

  // True only for the full 64-bit spelling of one of the 16 GPRs. Reading
  // %eax does not yield the value we are tracking in %rax, so only these
  // count as reads -- and RIP/RFLAGS/the MMX registers are deliberately
  // excluded even though they too are 64 bits wide (see the definition).
  static bool IsFull64(unsigned reg);

 private:
  void ClobberWrites(const Instruction& insn, AbsState* state) const;
};

}  // namespace unwind_analysis

#endif  // INSN_SEMANTICS_H_

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef LIGHT_CHECKER_H_
#define LIGHT_CHECKER_H_

#include "fde-checker.h"

namespace unwind_analysis {

// A second, much narrower checker alongside FDEChecker (fde-checker.h).
//
// The full checker runs a worklist dataflow across the whole reachable CFG,
// resolves PIC switch tables, and follows exception landing pads via the
// LSDA -- and it earns a REVIEW every time any of that machinery meets
// something it cannot resolve, which in practice is most of what drives its
// REVIEW count on real binaries. It can also, rarely, manufacture a false
// MISMATCH when FallThroughIsReal (fde-checker.cc) mis-guesses whether a
// call's fallthrough is real and carries stale state into unrelated code.
//
// This checker avoids both failure modes by not doing a dataflow walk at
// all. It decodes every instruction in [pc_begin, pc_end) in straight
// address order -- see LightCheck's own comment for why no CFG discovery is
// needed -- and for each one, independently reseeds a fresh AbsState
// straight from the CFI row declared at that exact instruction's own
// address (AbsState::SeedFromRow), runs exactly one instruction's Transfer
// through it, and checks the result against the row that governs the very
// next instruction (or, for a direct jmp/jcc/tail-call target, the row at
// that target -- possibly in a different FDE). No state is ever carried
// past one instruction, so there is nothing for a bogus edge to poison: a
// call whose callee never returns just leaves the following bytes checked
// on their own terms, never compared against what came before it. See the
// exemption for `call` documented at its use site in the .cc file.
//
// The tradeoff for that safety is scope. This checker:
//  - never resolves a switch table's dispatch (the unresolved indirect jmp
//    itself goes unchecked; case bodies still get walked and checked, since
//    they are just more bytes in the FDE's address range);
//  - never verifies a register's save-*location* rule beyond a narrow,
//    purely positional check at the exact instruction that writes it (see
//    CheckSavedRegisterSlots in the .cc file) -- it does not attempt to
//    verify that a value is later restored correctly, or track a slot's
//    contents across more than one instruction;
//  - does not check the x86-64 return convention at `ret`, or the ABI-based
//    tail-call fallback FDEChecker::CheckExitState provides.
//
// Every finding is either a MISMATCH (a concrete, provable disagreement) or,
// only when a CFI row's own CFA rule is something this checker's simple
// model cannot evaluate at all (DW_CFA_def_cfa_expression, or no CFA rule
// stated) -- a REVIEW. There is no REVIEW-LIGHT: FDEResult::guessable_jump_pc
// and guessed_jump_tables are always left unset, since this checker never
// attempts the guessing recovery FDEChecker::CheckWithGuessing does.
FDEResult LightCheck(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry);

}  // namespace unwind_analysis

#endif  // LIGHT_CHECKER_H_

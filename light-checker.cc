/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#include "light-checker.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <span>
#include <string>
#include <string_view>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "cfi-table.h"
#include "insn-semantics.h"

namespace unwind_analysis {

namespace {

// Collects findings, folding repeats of the same message into one entry.
// A near-identical class lives in fde-checker.cc, private to its own
// anonymous namespace; it is small enough, and specific enough to how each
// checker phrases things, that duplicating it here beats exposing it from a
// file this checker otherwise shares almost nothing with.
class FindingSink {
 public:
  explicit FindingSink(size_t cap) : cap_(cap) {
  }

  void Mismatch(uint64_t pc, std::string_view message) {
    Add(Finding::Severity::kMismatch, pc, message);
  }
  void Review(uint64_t pc, std::string_view message) {
    Add(Finding::Severity::kReview, pc, message);
  }
  void Add(Finding::Severity severity, uint64_t pc, std::string_view message) {
    auto it = index_.find(message);
    if (it != index_.end()) {
      findings_[it->second].repeats++;
      return;
    }
    if (findings_.size() >= cap_) {
      truncated_++;
      return;
    }
    index_.emplace(message, findings_.size());
    findings_.emplace_back(severity, pc, std::string{message}, 0);
  }

  std::vector<Finding> Take() {
    if (truncated_ > 0) {
      findings_.emplace_back(Finding::Severity::kReview, 0,
                             absl::StrFormat("%d further distinct findings not shown", truncated_), 0);
    }
    return std::move(findings_);
  }

 private:
  const size_t cap_;
  int truncated_ = 0;
  std::vector<Finding> findings_;
  absl::flat_hash_map<std::string, size_t> index_;
};

// Same lookup FDEChecker::CFIContaining (fde-checker.cc) performs, over the
// same sorted index (FDECheckerOptions::all_cfis) -- small enough, and
// self-contained enough, to duplicate rather than expose.
const CFI* CFIContaining(const FDECheckerOptions& options, uint64_t pc) {
  const auto& index = options.all_cfis;
  auto it = absl::c_upper_bound(
      index, pc,
      [](uint64_t a, const std::pair<std::pair<uint64_t, uint64_t>, const CFI*>& e) { return a < e.first.first; });
  if (it == index.begin()) {
    return nullptr;
  }
  --it;
  if (pc < it->first.first || pc >= it->first.second) {
    return nullptr;
  }
  return it->second;
}

// Whether `target`'s CFA rule, evaluated against `v`, is the CFA `v`
// itself claims to be relative to -- i.e., whether `v` is a value this row
// could plausibly be describing.
bool CFASatisfiedBy(const CFARule& target, const AbsVal& v) {
  return target.kind == CFARule::Kind::kRegOffset && v.kind == AbsVal::Kind::kCFARel && v.delta + target.offset == 0;
}

// The only check this file does: is `state`'s value for the CFA-defining
// register consistent with the declared rule `target`? In practice `target`
// is always rsp-based or rbp-based -- the two shapes this checker's simple
// per-instruction model can actually follow -- so this either confirms a
// `push`/`sub`/`add`/`lea`/`leave` kept the running CFA delta correct, or it
// does not.
//
// Returns true if the CFA can no longer be verified from here on, having
// already emitted the single REVIEW that says so -- covering both a CFA
// rule this model cannot evaluate at all (`DW_CFA_def_cfa_expression`, or no
// rule stated) and a rule this model normally could evaluate, but whose
// register has gone untracked (glibc's `swapcontext` loading a brand-new
// rsp mid-function is the motivating case). Both are "cannot say," not "is
// wrong" -- matching `RowChecker::CheckCFA`'s own precedent (fde-checker.cc)
// of treating any non-`kCFARel` value as unverifiable rather than guessing
// at it -- but unlike that full-checker dataflow walk, this checker makes
// no attempt to keep going and see if tracking recovers later: once one
// instruction's effect on the CFA can no longer be confirmed, nothing this
// checker concludes about any instruction after it would be trustworthy
// either, so it gives up on the rest of this FDE rather than press on and
// risk reporting a "mismatch" built on a foundation it already knows is
// unsound. Only a concrete, disagreeing value is ever reported as a
// mismatch -- a real, provable claim, not a heuristic.
bool CheckCFA(FindingSink* sink, uint64_t pc, const CFARule& target, const AbsState& state,
              std::string_view edge_desc) {
  if (target.kind != CFARule::Kind::kRegOffset) {
    sink->Review(pc, absl::StrCat(edge_desc,
                                  "CFA is given by a DWARF expression, or left undeclared, which the light "
                                  "checker does not evaluate; giving up on the rest of this FDE"));
    return true;
  }
  const AbsVal& v = state.reg(target.reg);
  if (v.kind != AbsVal::Kind::kCFARel) {
    sink->Review(pc, absl::StrCat(edge_desc, absl::StrFormat("CFA is declared as %v, but %s holds %v here, so the rule "
                                                             "cannot be verified; giving up on the rest of this FDE",
                                                             target, DWARFRegName(target.reg), v)));
    return true;
  }
  if (!CFASatisfiedBy(target, v)) {
    sink->Mismatch(pc, absl::StrFormat("%sdeclared CFA is %v, but the code leaves %s at %v", edge_desc, target,
                                       DWARFRegName(target.reg), v));
  }
  return false;
}

}  // namespace

FDEResult LightCheck(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry) {
  (void)at_function_entry;  // kept for API parity with FDEChecker's Check(); see light-checker.h

  FDEResult result;
  result.fde_addr = cfi.fde_addr;
  result.pc_begin = cfi.pc_begin;
  result.pc_end = cfi.pc_end;
  result.signal_frame = cfi.signal_frame;

  const CFIRow* first_row = cfi.RowAt(cfi.pc_begin);
  if (first_row != nullptr && first_row->regs[kDWARFRip].kind == RegRule::Kind::kUndefined) {
    // Same special case FDEChecker::Run() applies (fde-checker.cc): _start
    // and some thread-entry routines declare RA undefined from the very
    // first row to say "no unwind from here," and the rest of the row is
    // then free to be whatever the crt code needs -- glibc/musl _start
    // routines `pop` argc straight off the incoming stack, moving CFA away
    // from what an unchanging `cfa=rsp+8` row still claims, and that is not
    // a bug, just a frame nothing will ever unwind through. Found via a
    // 400-binary sweep: without this, LightCheck flagged a MISMATCH on
    // dozens of otherwise-clean executables' `_start`, all the identical
    // "pop right after an undefined-RA entry row" shape, none a real bug.
    result.verdict = Verdict::kBlessed;
    return result;
  }

  FindingSink sink{options.max_findings_per_fde};
  InsnSemantics semantics;

  // No state survives from one instruction to the next: every instruction
  // gets a completely fresh `AbsState`, seeded straight from the CFI row
  // that governs its own address, run through exactly one `Transfer`, and
  // checked. This is only sound because `CheckCFA` gives up on the rest of
  // the FDE the moment it can no longer confirm the CFA-defining register's
  // value (see its own comment) -- earlier versions of this file instead
  // tried to carry state forward so a "before" and "after" pair could tell
  // a real target bug apart from an artifact of decoding straight through a
  // stale row, which is real complexity that giving up early makes
  // unnecessary: there is no later instruction left to falsely disagree
  // with a row this checker has already stopped trusting.
  uint64_t pc = cfi.pc_begin;
  while (pc < cfi.pc_end) {
    const CFIRow* row = cfi.RowAt(pc);
    if (row == nullptr) {
      break;  // structurally should not happen inside [pc_begin, pc_end)
    }

    std::span<const uint8_t> bytes = options.image->BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
    Instruction insn;
    if (!options.disasm->Decode(bytes.data(), bytes.size(), pc, &insn)) {
      sink.Mismatch(pc, absl::StrFormat("could not decode instruction at %x (buffer size: %d)", pc, bytes.size()));
      break;  // cannot keep decoding forward past an undecodable byte
    }
    result.instructions_checked++;

    AbsState state = AbsState::SeedFromRow(*row, /*at_function_entry=*/false);
    TransferOutcome outcome = semantics.Transfer(insn, &state);
    const uint64_t next_pc = pc + insn.size;

    // A call's own Transfer never moves rsp -- call/ret are balanced from
    // the caller frame's perspective -- so comparing the row before a call
    // against the row after it is not "does this instruction match its
    // CFI", it is "do two blocks' rows happen to agree", and they need not:
    // a noreturn call (`call abort`, `call __cxa_throw`) can fall through
    // into an unrelated fragment's own fresh prologue-shaped row with
    // nothing wrong on either side. AGENT.md §4.5 documents this exact
    // shape as the reason FDEChecker needs FallThroughIsReal at all. The
    // fix here is simply to not ask this one question at a call -- the
    // bytes after it are still decoded and checked on their own terms next
    // iteration, against whatever row actually governs them.
    if (outcome.falls_through && !outcome.is_call && next_pc < cfi.pc_end) {
      const CFIRow* next_row = cfi.RowAt(next_pc);
      CHECK(next_row != nullptr) << "next_pc: " << absl::Hex(next_pc);
      // Special case: transition from rbp-based to rsp-based CFA we
      // cannot verify "normally" (since we don't track RSP and CFI rules don't
      // tell us where it would be).
      if (row->cfa == CFARule::RegOffset(kDWARFRbp, 16) && next_row->cfa == CFARule::RegOffset(kDWARFRsp, 8)) {
        if (insn.id == ZYDIS_MNEMONIC_POP && insn.op_count == 1 &&
            insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && insn.operands[0].reg.value == ZYDIS_REGISTER_RBP) {
          // blessed
        } else if (insn.id == ZYDIS_MNEMONIC_LEAVE) {
          // blessed
        } else {
          sink.Review(pc, "transition to rsp-based CFA is not on pop %rbp or leave instruction");
          break;
        }
      } else if (insn.id == ZYDIS_MNEMONIC_NOP) {
        // sometimes nop is where "effect of ret" is
        // delayed. Instruction is no-op, but CFI flips from "at ret"
        // to "something else"
      } else if (CheckCFA(&sink, pc, next_row->cfa, state, "")) {
        break;
      }
    }

    // Check CFI matching state if we took the branch. NOTE: this also
    // reaches into CFI of different FDEs as necessary (sometimes
    // conditional branches target .cold version of the function)
    if (outcome.has_direct_target) {
      const CFI* target_cfi = CFIContaining(options, outcome.direct_target);
      if (target_cfi != nullptr) {
        const CFIRow* target_row = target_cfi->RowAt(outcome.direct_target);
        if (target_row != nullptr) {
          std::string edge_desc =
              (target_cfi == &cfi)
                  ? std::string()
                  : absl::StrFormat("jump to 0x%x (FDE at 0x%x): ", outcome.direct_target, target_cfi->fde_addr);
          if (CheckCFA(&sink, pc, target_row->cfa, state, edge_desc)) {
            break;
          }
        }
      }
    }

    pc = next_pc;
  }

  result.findings = sink.Take();
  result.verdict = Verdict::kBlessed;
  for (const Finding& f : result.findings) {
    if (f.severity == Finding::Severity::kMismatch) {
      result.verdict = Verdict::kMismatch;
      break;
    }
  }
  if (result.verdict == Verdict::kBlessed) {
    for (const Finding& f : result.findings) {
      if (f.severity == Finding::Severity::kReview) {
        result.verdict = Verdict::kReview;
        break;
      }
    }
  }
  return result;
}

}  // namespace unwind_analysis

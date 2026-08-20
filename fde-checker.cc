/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "fde-checker.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"
#include "eh-frame-reader.h"
#include "insn-semantics.h"
#include "lsda-reader.h"

namespace unwind_analysis {

namespace {

constexpr int kCalleeSaved[] = {kDwarfRbx, kDwarfRbp, 12, 13, 14, 15};

bool IsCalleeSaved(int reg) {
  return std::find(std::begin(kCalleeSaved), std::end(kCalleeSaved), reg) != std::end(kCalleeSaved);
}

// Collects findings, folding repeats of the same message into one entry.
class FindingSink {
 public:
  explicit FindingSink(size_t cap) : cap_(cap) {
  }

  void Add(Finding::Severity severity, uint64_t pc, std::string message, std::string insn_text) {
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
    findings_.push_back(Finding{severity, pc, std::move(message), std::move(insn_text), 0});
  }

  std::vector<Finding> Take() {
    if (truncated_ > 0) {
      findings_.push_back(Finding{Finding::Severity::kReview, 0,
                                  absl::StrFormat("%d further distinct findings not shown", truncated_), "", 0});
    }
    return std::move(findings_);
  }

 private:
  size_t cap_;
  int truncated_ = 0;
  std::vector<Finding> findings_;
  absl::flat_hash_map<std::string, size_t> index_;
};

// Compares one CFI row against the state the code actually produces.
class RowChecker {
 public:
  RowChecker(const FdeChecker::Options& options, FindingSink* sink) : options_(options), sink_(sink) {
  }

  void Check(uint64_t pc, const CfiRow& row, const AbsState& state, const std::string& insn_text) {
    insn_text_ = insn_text;
    pc_ = pc;
    CheckCfa(row.cfa, state);
    for (int r = 0; r < kNumDwarfRegs; r++) {
      CheckReg(r, row.regs[r], state);
    }
  }

 private:
  void Review(std::string msg) {
    sink_->Add(Finding::Severity::kReview, pc_, std::move(msg), insn_text_);
  }
  void Mismatch(std::string msg) {
    sink_->Add(Finding::Severity::kMismatch, pc_, std::move(msg), insn_text_);
  }

  void CheckCfa(const CfaRule& cfa, const AbsState& state) {
    switch (cfa.kind) {
      case CfaRule::Kind::kUndefined:
        Review("no CFA rule is in force here");
        return;
      case CfaRule::Kind::kExpression:
        Review("CFA is given by a DWARF expression, which this version does not evaluate");
        return;
      case CfaRule::Kind::kRegOffset:
        break;
    }
    if (cfa.reg >= kNumGpRegs) {
      Review(absl::StrFormat("CFA is based on DWARF register %d, which is not a general-purpose register", cfa.reg));
      return;
    }
    const AbsVal& v = state.reg(cfa.reg);
    if (v.kind != AbsVal::Kind::kCfaRel) {
      Review(absl::StrFormat("CFA is declared as %s, but %s holds %s here, so the rule cannot be verified",
                             cfa.ToString(), DwarfRegName(cfa.reg), v.ToString()));
      return;
    }
    if (v.delta + cfa.offset != 0) {
      Mismatch(absl::StrFormat("declared CFA is %s, but %s is CFA%+d here, so the rule yields CFA%+d (should be %s%+d)",
                               cfa.ToString(), DwarfRegName(cfa.reg), static_cast<int>(v.delta),
                               static_cast<int>(v.delta + cfa.offset), DwarfRegName(cfa.reg),
                               static_cast<int>(-v.delta)));
    }
  }

  // Reads a register out of the state, or nullopt for RA, which is not a
  // GPR and so has no tracked value of its own.
  static std::optional<AbsVal> RegValue(const AbsState& state, int reg) {
    if (reg < 0 || reg >= kNumGpRegs) {
      return std::nullopt;
    }
    return state.reg(reg);
  }

  void CheckReg(int r, const RegRule& rule, const AbsState& state) {
    switch (rule.kind) {
      case RegRule::Kind::kUnset:
        if (options_.check_unmentioned_callee_saved && IsCalleeSaved(r)) {
          CheckSameValue(r, state);
        }
        return;

      case RegRule::Kind::kUndefined:
        // Legitimate: _start and thread entry points say the return
        // address is not recoverable, which is how a walk terminates.
        return;

      case RegRule::Kind::kSameValue:
        CheckSameValue(r, state);
        return;

      case RegRule::Kind::kAtCfaOffset: {
        AbsVal at = state.Slot(rule.offset);
        if (at.is_unknown()) {
          Review(absl::StrFormat("CFI says %s is saved at [CFA%+d], but we cannot say what is stored there",
                                 DwarfRegName(r), static_cast<int>(rule.offset)));
          return;
        }
        if (!at.IsOrigReg(r)) {
          Mismatch(absl::StrFormat("CFI says %s is saved at [CFA%+d], but that slot holds %s", DwarfRegName(r),
                                   static_cast<int>(rule.offset), at.ToString()));
        }
        return;
      }

      case RegRule::Kind::kValOffset: {
        std::optional<AbsVal> v = RegValue(state, r);
        if (!v.has_value()) {
          return;
        }
        if (v->is_unknown()) {
          Review(absl::StrFormat("CFI says %s is CFA%+d, but we are not tracking it here", DwarfRegName(r),
                                 static_cast<int>(rule.offset)));
          return;
        }
        if (!v->IsCfaRel(rule.offset)) {
          Mismatch(absl::StrFormat("CFI says %s is CFA%+d, but it holds %s", DwarfRegName(r),
                                   static_cast<int>(rule.offset), v->ToString()));
        }
        return;
      }

      case RegRule::Kind::kInRegister: {
        std::optional<AbsVal> v = RegValue(state, rule.reg);
        if (!v.has_value()) {
          Review(absl::StrFormat("CFI says %s was moved into DWARF register %d, which we do not track", DwarfRegName(r),
                                 rule.reg));
          return;
        }
        if (v->is_unknown()) {
          Review(absl::StrFormat("CFI says %s was moved into %s, but we are not tracking %s here", DwarfRegName(r),
                                 DwarfRegName(rule.reg), DwarfRegName(rule.reg)));
          return;
        }
        if (!v->IsOrigReg(r)) {
          Mismatch(absl::StrFormat("CFI says %s was moved into %s, but %s holds %s", DwarfRegName(r),
                                   DwarfRegName(rule.reg), DwarfRegName(rule.reg), v->ToString()));
        }
        return;
      }

      case RegRule::Kind::kExpression:
      case RegRule::Kind::kValExpression:
        Review(absl::StrFormat("%s is described by a DWARF expression, which this version does not evaluate",
                               DwarfRegName(r)));
        return;
    }
  }

  void CheckSameValue(int r, const AbsState& state) {
    std::optional<AbsVal> v = RegValue(state, r);
    if (!v.has_value() || v->is_unknown()) {
      if (v.has_value()) {
        Review(absl::StrFormat("CFI says %s still holds its entry value, but we are not tracking it here",
                               DwarfRegName(r)));
      }
      return;
    }
    if (!v->IsOrigReg(r)) {
      Mismatch(
          absl::StrFormat("CFI says %s still holds its entry value, but it holds %s", DwarfRegName(r), v->ToString()));
    }
  }

  const FdeChecker::Options& options_;
  FindingSink* sink_;
  std::string insn_text_;
  uint64_t pc_ = 0;
};

// Whether the CFI in force at some address actually consults the thing
// two paths disagreed about. If it never reads that register or that
// slot, the disagreement cannot make the row wrong -- it costs us
// precision and nothing more, and reporting it is noise. Should the
// value be consulted further along, it is unknown by then and the
// ordinary per-address check says so.
bool RowDependsOn(const CfiRow& row, const JoinConflict& conflict) {
  if (conflict.reg == JoinConflict::kSlotConflict) {
    for (const RegRule& rule : row.regs) {
      if (rule.kind == RegRule::Kind::kAtCfaOffset && rule.offset == conflict.offset) {
        return true;
      }
    }
    return false;
  }
  if (row.cfa.kind == CfaRule::Kind::kRegOffset && row.cfa.reg == conflict.reg) {
    return true;
  }
  for (int r = 0; r < kNumDwarfRegs; r++) {
    const RegRule& rule = row.regs[r];
    if (rule.kind == RegRule::Kind::kInRegister && rule.reg == conflict.reg) {
      return true;
    }
    if (r != conflict.reg) {
      continue;
    }
    if (rule.kind == RegRule::Kind::kSameValue || rule.kind == RegRule::Kind::kValOffset) {
      return true;
    }
  }
  return false;
}

bool CfaSatisfiedBy(const CfaRule& cfa, const AbsVal& v) {
  return v.kind == AbsVal::Kind::kCfaRel && v.delta + cfa.offset == 0;
}

// Whether the address after this instruction is really its successor.
//
// Falling off the end of an instruction is usually a real edge, but not
// always: `call abort` never comes back, and the alignment nop before a
// cold fragment is never executed. In both cases the bytes that follow
// belong to some other path entirely, and carrying our stack state into
// them manufactures a contradiction that is not in the binary.
//
// The compiler tells us which case this is, through the CFI it emitted.
// Two conditions have to hold before we will drop an edge.
//
// First, a new CFI row must start at `next`. Unrelated code never begins
// in the middle of a row, so within one row the fall-through is real by
// construction -- and that matters, because a stale-CFI bug can span
// several instructions, and we must keep walking through all of them
// rather than stopping at the first.
//
// Second, the rule at `next` must be inconsistent with both sides of
// this instruction. The CFA rule can only change across an instruction
// that changes the register the rule is built on, so:
//
//   * satisfied by the state after   -> an ordinary edge, take it;
//   * satisfied by the state before  -> the CFI is describing the state
//     one instruction late. That is precisely the compiler bug this tool
//     exists to find, so take the edge and let the checker report it;
//   * satisfied by neither           -> the rule describes something
//     unrelated to this instruction, so a different block starts here
//     and the fall-through is not real.
//
// This needs no list of noreturn functions and does not care what the
// callee is named. It does mean a doubly-wrong CFI could be pruned
// instead of reported; the region then shows up as an unchecked
// coverage gap rather than silently passing.
bool FallThroughIsReal(const FdeCfi& cfi, const CfiRow* here, uint64_t next, const AbsVal (&before)[kNumGpRegs],
                       const AbsState& after) {
  const CfiRow* row = cfi.RowAt(next);
  if (row == nullptr || row == here) {
    return true;  // still inside the same row, so certainly the same block
  }
  if (row->cfa.kind != CfaRule::Kind::kRegOffset || row->cfa.reg >= kNumGpRegs) {
    return true;
  }
  const AbsVal& was = before[row->cfa.reg];
  const AbsVal& now = after.reg(row->cfa.reg);
  if (was.kind != AbsVal::Kind::kCfaRel || now.kind != AbsVal::Kind::kCfaRel) {
    return true;  // not confident enough to prune anything
  }
  return CfaSatisfiedBy(row->cfa, now) || CfaSatisfiedBy(row->cfa, was);
}

}  // namespace

const char* VerdictName(Verdict v) {
  switch (v) {
    case Verdict::kBlessed:
      return "BLESSED";
    case Verdict::kReview:
      return "REVIEW";
    case Verdict::kMismatch:
      return "MISMATCH";
  }
  return "?";
}

FdeResult FdeChecker::Check(const FdeCfi& cfi, bool at_function_entry) const {
  FdeResult result;
  result.fde_addr = cfi.fde_addr;
  result.pc_begin = cfi.pc_begin;
  result.pc_end = cfi.pc_end;
  result.signal_frame = cfi.signal_frame;

  FindingSink sink{options_.max_findings_per_fde};
  RowChecker row_checker{options_, &sink};
  InsnSemantics semantics{disasm_->handle()};

  // Forward dataflow over the instructions reachable from pc_begin by
  // direct control flow. Per-instruction rather than per-block: simpler,
  // and functions are small enough that it does not matter.
  absl::flat_hash_map<uint64_t, AbsState> in_states;
  absl::flat_hash_map<uint64_t, size_t> insn_sizes;
  absl::flat_hash_map<uint64_t, std::vector<JoinConflict>> join_conflicts;
  std::vector<uint64_t> worklist;

  auto propagate = [&](uint64_t pc, const AbsState& state) {
    auto it = in_states.find(pc);
    if (it == in_states.end()) {
      in_states.emplace(pc, state);
      worklist.push_back(pc);
      return;
    }
    std::vector<JoinConflict> conflicts;
    bool changed = Join(state, &it->second, &conflicts);
    if (!conflicts.empty()) {
      auto& list = join_conflicts[pc];
      for (auto& c : conflicts) {
        list.push_back(std::move(c));
      }
    }
    if (changed) {
      worklist.push_back(pc);
    }
  };

  const CfiRow* first_row = cfi.RowAt(cfi.pc_begin);
  if (first_row == nullptr) {
    sink.Add(Finding::Severity::kReview, cfi.pc_begin, "no CFI row covers the start of this FDE", "");
    result.findings = sink.Take();
    result.verdict = Verdict::kReview;
    return result;
  }
  if (at_function_entry) {
    // A function entered by `call` has rsp at CFA-8 on its first
    // instruction, with the return address in the word it points at.
    // Anything else is worth a look -- but it is a review and not an
    // accusation, because we cannot prove the FDE is entered by a call.
    // glibc's _dl_runtime_resolve_fxsave carries a real function symbol
    // and legitimately starts at rsp+24: the PLT jumps to it with two
    // words already pushed.
    const char* kEnteredByJump =
        " (either the CFI is wrong, or this is entered by a jump rather than a call, the way a PLT trampoline is)";
    if (first_row->cfa.kind != CfaRule::Kind::kRegOffset || first_row->cfa.reg != kDwarfRsp ||
        first_row->cfa.offset != 8) {
      sink.Add(Finding::Severity::kReview, cfi.pc_begin,
               absl::StrFormat("a function symbol starts here, so the CFA should be rsp+8, but the CFI says %s%s",
                               first_row->cfa.ToString(), kEnteredByJump),
               "");
    }
    const RegRule& ra = first_row->regs[kDwarfRip];
    if (ra.kind != RegRule::Kind::kAtCfaOffset || ra.offset != -8) {
      if (ra.kind != RegRule::Kind::kUndefined) {
        sink.Add(Finding::Severity::kReview, cfi.pc_begin,
                 absl::StrFormat("a function symbol starts here, so the return address should be at [CFA-8], but "
                                 "the CFI says %s%s",
                                 ra.ToString(), kEnteredByJump),
                 "");
      }
    }
  }

  // Exception landing pads are reachable only through the unwinder, via
  // the LSDA -- nothing in the function body branches to one, so the
  // ordinary control-flow walk below would never find them, and their
  // bytes would be reported as an unchecked coverage gap. Seed each one
  // as its own root instead, exactly like the FDE's own start: a landing
  // pad is jumped to, not called, so there is nothing to inherit from a
  // caller and the declared row is trusted the same way a `.cold`
  // fragment's is.
  if (cfi.lsda_addr != 0) {
    std::vector<uint64_t> landing_pads;
    try {
      landing_pads = ReadLsdaLandingPads(image_, cfi.lsda_addr, cfi.pc_begin);
    } catch (const EhFrameError& e) {
      sink.Add(Finding::Severity::kReview, cfi.pc_begin,
               absl::StrFormat("failed to parse this FDE's LSDA (.gcc_except_table) at 0x%016llx: %s",
                               static_cast<unsigned long long>(cfi.lsda_addr), e.what()),
               "");
      landing_pads.clear();
    }
    for (uint64_t lp : landing_pads) {
      if (lp < cfi.pc_begin || lp >= cfi.pc_end) {
        continue;  // a malformed LSDA shouldn't be able to walk us outside the FDE
      }
      const CfiRow* row = cfi.RowAt(lp);
      if (row == nullptr) {
        continue;  // reported as a missing-row finding once the walk reaches nearby code
      }
      propagate(lp, AbsState::SeedFromRow(*row, /*at_function_entry=*/false));
    }
  }

  // Start with "normal" instructions. Landing pads don't have known rsp state.
  propagate(cfi.pc_begin, AbsState::SeedFromRow(*first_row, at_function_entry));

  // Pass 1: Forward dataflow until the abstract state settles across all reached instructions.
  size_t iterations = 0;
  bool hit_cap = false;
  while (!worklist.empty()) {
    if (++iterations > options_.max_iterations) {
      hit_cap = true;
      break;
    }
    uint64_t pc = worklist.back();
    worklist.pop_back();
    AbsState state = in_states[pc];

    std::span<const uint8_t> bytes = image_.BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
    const cs_insn* insn = bytes.empty() ? nullptr : disasm_->DecodeOne(bytes.data(), bytes.size(), pc);
    if (insn == nullptr || pc + insn->size > cfi.pc_end) {
      continue;
    }
    size_t insn_size = insn->size;
    insn_sizes[pc] = insn_size;

    const CfiRow* row = cfi.RowAt(pc);
    AbsVal before[kNumGpRegs];
    std::copy(std::begin(state.gpr), std::end(state.gpr), std::begin(before));
    TransferOutcome outcome = semantics.Transfer(*insn, &state);

    if (outcome.falls_through) {
      uint64_t next = pc + insn_size;
      if (next < cfi.pc_end && FallThroughIsReal(cfi, row, next, before, state)) {
        propagate(next, state);
      }
    }
    if (outcome.has_direct_target) {
      uint64_t target = outcome.direct_target;
      // A branch out of the FDE is a tail call, which is normal and not
      // ours to follow.
      if (target >= cfi.pc_begin && target < cfi.pc_end) {
        propagate(target, state);
      }
    }
  }

  if (hit_cap) {
    sink.Add(Finding::Severity::kReview, cfi.pc_begin,
             absl::StrFormat("analysis gave up after %d dataflow steps", static_cast<int>(options_.max_iterations)),
             "");
  }

  // Pass 2: Verify settled states against declared CFI rows in deterministic (sorted PC) order.
  std::vector<uint64_t> reached_pcs;
  reached_pcs.reserve(in_states.size());
  for (const auto& [pc, _] : in_states) {
    reached_pcs.push_back(pc);
  }
  std::sort(reached_pcs.begin(), reached_pcs.end());

  for (uint64_t pc : reached_pcs) {
    const AbsState& state = in_states[pc];

    std::span<const uint8_t> bytes = image_.BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
    const cs_insn* insn = bytes.empty() ? nullptr : disasm_->DecodeOne(bytes.data(), bytes.size(), pc);
    if (insn == nullptr) {
      sink.Add(Finding::Severity::kReview, pc, "cannot decode the instruction at this address", "");
      continue;
    }
    if (pc + insn->size > cfi.pc_end) {
      sink.Add(Finding::Severity::kReview, pc, "instruction runs past the end of the FDE's PC range",
               Disassembler::Text(*insn));
      continue;
    }
    std::string insn_text = Disassembler::Text(*insn);
    result.instructions_checked++;

    // The row at pc describes the state when RIP == pc, so compare
    // before applying the instruction, not after.
    const CfiRow* row = cfi.RowAt(pc);
    if (row == nullptr) {
      sink.Add(Finding::Severity::kReview, pc, "no CFI row covers this address", insn_text);
    } else {
      row_checker.Check(pc, *row, state, insn_text);
    }

    auto it_conflicts = join_conflicts.find(pc);
    if (it_conflicts != join_conflicts.end()) {
      for (const JoinConflict& c : it_conflicts->second) {
        if (row == nullptr || !RowDependsOn(*row, c)) {
          continue;
        }
        // .eh_frame declares one state per PC, so two edges arriving here
        // with different values cannot both match the single row covering
        // this address -- which makes this either the compiler bug we are
        // hunting or a gap in our own reachability. This version has known
        // gaps (it does not know which calls never return, and it does not
        // resolve jump tables), so it reports rather than accuses.
        sink.Add(Finding::Severity::kReview, pc,
                 absl::StrFormat("paths into this address disagree: %s -- one of them must contradict the single CFI "
                                 "row here, unless one of them is not really reachable",
                                 c.Describe()),
                 "");
      }
    }

    AbsState state_copy = state;
    TransferOutcome outcome = semantics.Transfer(*insn, &state_copy);
    if (outcome.review_reason != nullptr) {
      sink.Add(Finding::Severity::kReview, pc, outcome.review_reason, insn_text);
    }
    if (outcome.indirect_branch) {
      sink.Add(Finding::Severity::kReview, pc,
               "unresolved indirect jump; jump tables are not resolved in this version, so the code it reaches "
               "went unchecked",
               insn_text);
    }

    if (options_.report_coverage_gaps) {
      // Bytes the walk never reached were never checked, so saying the FDE
      // is blessed would be a lie. Padding does not count.
      uint64_t pc = cfi.pc_begin;
      while (pc < cfi.pc_end) {
        auto it = insn_sizes.find(pc);
        if (it != insn_sizes.end()) {
          pc += it->second;
          continue;
        }
        uint64_t gap_start = pc;
        bool all_padding = true;
        while (pc < cfi.pc_end && insn_sizes.find(pc) == insn_sizes.end()) {
          std::span<const uint8_t> bytes = image_.BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
          const cs_insn* insn = bytes.empty() ? nullptr : disasm_->DecodeOne(bytes.data(), bytes.size(), pc);
          if (insn == nullptr) {
            all_padding = false;
            pc++;
            continue;
          }
          if (insn->id != X86_INS_NOP && insn->id != X86_INS_INT3) {
            all_padding = false;
          }
          pc += insn->size;
        }
        if (!all_padding) {
          sink.Add(Finding::Severity::kReview, gap_start,
                   absl::StrFormat("%d bytes from here were not reached by the control-flow walk, so their CFI went "
                                   "unchecked (exception landing pads and jump-table targets look like this)",
                                   static_cast<int>(pc - gap_start)),
                   "");
        }
      }
    }
  }

  result.findings = sink.Take();
  result.verdict = Verdict::kBlessed;
  for (const Finding& f : result.findings) {
    if (f.severity == Finding::Severity::kMismatch) {
      result.verdict = Verdict::kMismatch;
      break;
    }
    result.verdict = Verdict::kReview;
  }
  return result;
}

}  // namespace unwind_analysis

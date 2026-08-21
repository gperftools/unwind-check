/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "fde-checker.h"

#include <string.h>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "eh-frame-reader.h"
#include "insn-semantics.h"
#include "lsda-reader.h"

namespace unwind_analysis {

namespace {

constexpr int kCalleeSaved[] = {kDWARFRbx, kDWARFRbp, 12, 13, 14, 15};
constexpr uint64_t kMaxJumpTableEntries = 512;

bool IsCalleeSaved(int reg) {
  return std::find(std::begin(kCalleeSaved), std::end(kCalleeSaved), reg) != std::end(kCalleeSaved);
}

// Switch-table bound tracking: the guard (`cmp $imm,%r; ja/jae default`) is
// now tracked forward as part of AbsState (AbsState::last_cmp, joined like
// any other lattice field), so there is no backward byte-walk or parallel
// bound-clearing pass to maintain here any more -- see AbsVal::bound and
// InsnSemantics::Transfer.

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
  RowChecker(const FDEChecker::Options& options, FindingSink* sink) : options_(options), sink_(sink) {
  }

  // `edge_context`, when non-empty, is prefixed onto every finding's
  // message -- used when `row` is not this instruction's own FDE's row but
  // a foreign FDE's declared row being checked across a jump-out edge, so
  // the finding says which edge and which FDE it is about rather than
  // reading like an ordinary in-FDE disagreement.
  //
  // `force_callee_saved_same_value` overrides options_.check_unmentioned_callee_saved
  // for callee-saved registers `row` leaves unmentioned (kUnset). It exists
  // for exactly one case: `row` is a foreign FDE's own canonical entry row
  // (checked via IsCanonicalEntry()). There, silence is not "nothing to
  // say" the way it usually is within one FDE -- it is the ordinary DWARF
  // convention that an unmentioned register at a genuine call entry still
  // holds the caller's value, the same convention AbsState::SeedFromRow
  // already applies when seeding a canonical entry's own analysis. Without
  // this, a tail call that clobbers a callee-saved register without
  // restoring it would go unnoticed whenever the target FDE's own body
  // never bothered to say so explicitly (which is the common case).
  void Check(uint64_t pc, const CFIRow& row, const AbsState& state, const std::string& insn_text,
             std::string_view edge_context = "", bool force_callee_saved_same_value = false) {
    insn_text_ = insn_text;
    pc_ = pc;
    edge_context_ = edge_context;
    force_callee_saved_same_value_ = force_callee_saved_same_value;
    CheckCFA(row.cfa, state);
    for (int r = 0; r < kNumDWARFRegs; r++) {
      CheckReg(r, row.regs[r], state);
    }
  }

 private:
  void Review(std::string msg) {
    sink_->Add(Finding::Severity::kReview, pc_, absl::StrCat(edge_context_, msg), insn_text_);
  }
  void Mismatch(std::string msg) {
    sink_->Add(Finding::Severity::kMismatch, pc_, absl::StrCat(edge_context_, msg), insn_text_);
  }

  void CheckCFA(const CFARule& cfa, const AbsState& state) {
    switch (cfa.kind) {
      case CFARule::Kind::kUndefined:
        Review("no CFA rule is in force here");
        return;
      case CFARule::Kind::kExpression:
        Review("CFA is given by a DWARF expression, which this version does not evaluate");
        return;
      case CFARule::Kind::kRegOffset:
        break;
    }
    if (cfa.reg >= kNumGPRs) {
      Review(absl::StrFormat("CFA is based on DWARF register %d, which is not a general-purpose register", cfa.reg));
      return;
    }
    const AbsVal& v = state.reg(cfa.reg);
    if (v.kind != AbsVal::Kind::kCFARel) {
      Review(absl::StrFormat("CFA is declared as %v, but %s holds %v here, so the rule cannot be verified", cfa,
                             DWARFRegName(cfa.reg), v));
      return;
    }
    if (v.delta + cfa.offset != 0) {
      Mismatch(absl::StrFormat("declared CFA is %v, but %s is CFA%+d here, so the rule yields CFA%+d (should be %s%+d)",
                               cfa, DWARFRegName(cfa.reg), static_cast<int>(v.delta),
                               static_cast<int>(v.delta + cfa.offset), DWARFRegName(cfa.reg),
                               static_cast<int>(-v.delta)));
    }
  }

  // Reads a register out of the state, or nullopt for RA, which is not a
  // GPR and so has no tracked value of its own.
  static std::optional<AbsVal> RegValue(const AbsState& state, int reg) {
    if (reg < 0 || reg >= kNumGPRs) {
      return std::nullopt;
    }
    return state.reg(reg);
  }

  void CheckReg(int r, const RegRule& rule, const AbsState& state) {
    switch (rule.kind) {
      case RegRule::Kind::kUnset:
        if ((options_.check_unmentioned_callee_saved || force_callee_saved_same_value_) && IsCalleeSaved(r)) {
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

      case RegRule::Kind::kAtCFAOffset: {
        AbsVal at = state.Slot(rule.offset);
        if (at.is_unknown()) {
          Review(absl::StrFormat("CFI says %s is saved at [CFA%+d], but we cannot say what is stored there",
                                 DWARFRegName(r), static_cast<int>(rule.offset)));
          return;
        }
        if (!at.IsOrigReg(r)) {
          Mismatch(absl::StrFormat("CFI says %s is saved at [CFA%+d], but that slot holds %v", DWARFRegName(r),
                                   static_cast<int>(rule.offset), at));
        }
        return;
      }

      case RegRule::Kind::kValOffset: {
        std::optional<AbsVal> v = RegValue(state, r);
        if (!v.has_value()) {
          return;
        }
        if (v->is_unknown()) {
          Review(absl::StrFormat("CFI says %s is CFA%+d, but we are not tracking it here", DWARFRegName(r),
                                 static_cast<int>(rule.offset)));
          return;
        }
        if (!v->IsCFARel(rule.offset)) {
          Mismatch(absl::StrFormat("CFI says %s is CFA%+d, but it holds %v", DWARFRegName(r),
                                   static_cast<int>(rule.offset), *v));
        }
        return;
      }

      case RegRule::Kind::kInRegister: {
        std::optional<AbsVal> v = RegValue(state, rule.reg);
        if (!v.has_value()) {
          Review(absl::StrFormat("CFI says %s was moved into DWARF register %d, which we do not track", DWARFRegName(r),
                                 rule.reg));
          return;
        }
        if (v->is_unknown()) {
          Review(absl::StrFormat("CFI says %s was moved into %s, but we are not tracking %s here", DWARFRegName(r),
                                 DWARFRegName(rule.reg), DWARFRegName(rule.reg)));
          return;
        }
        if (!v->IsOrigReg(r)) {
          Mismatch(absl::StrFormat("CFI says %s was moved into %s, but %s holds %v", DWARFRegName(r),
                                   DWARFRegName(rule.reg), DWARFRegName(rule.reg), *v));
        }
        return;
      }

      case RegRule::Kind::kExpression:
      case RegRule::Kind::kValExpression:
        Review(absl::StrFormat("%s is described by a DWARF expression, which this version does not evaluate",
                               DWARFRegName(r)));
        return;
    }
  }

  void CheckSameValue(int r, const AbsState& state) {
    std::optional<AbsVal> v = RegValue(state, r);
    if (!v.has_value() || v->is_unknown()) {
      if (v.has_value()) {
        Review(absl::StrFormat("CFI says %s still holds its entry value, but we are not tracking it here",
                               DWARFRegName(r)));
      }
      return;
    }
    if (!v->IsOrigReg(r)) {
      Mismatch(absl::StrFormat("CFI says %s still holds its entry value, but it holds %v", DWARFRegName(r), *v));
    }
  }

  const FDEChecker::Options& options_;
  FindingSink* sink_;
  std::string insn_text_;
  uint64_t pc_ = 0;
  std::string_view edge_context_;
  bool force_callee_saved_same_value_ = false;
};

// Whether the CFI in force at some address actually consults the thing
// two paths disagreed about. If it never reads that register or that
// slot, the disagreement cannot make the row wrong -- it costs us
// precision and nothing more, and reporting it is noise. Should the
// value be consulted further along, it is unknown by then and the
// ordinary per-address check says so.
bool RowDependsOn(const CFIRow& row, const JoinConflict& conflict) {
  if (conflict.reg == JoinConflict::kSlotConflict) {
    for (const RegRule& rule : row.regs) {
      if (rule.kind == RegRule::Kind::kAtCFAOffset && rule.offset == conflict.offset) {
        return true;
      }
    }
    return false;
  }
  if (row.cfa.kind == CFARule::Kind::kRegOffset && row.cfa.reg == conflict.reg) {
    return true;
  }
  for (int r = 0; r < kNumDWARFRegs; r++) {
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

bool CFASatisfiedBy(const CFARule& cfa, const AbsVal& v) {
  return v.kind == AbsVal::Kind::kCFARel && v.delta + cfa.offset == 0;
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
bool FallThroughIsReal(const CFI& cfi, const CFIRow* here, uint64_t next, const AbsVal (&before)[kNumGPRs],
                       const AbsState& after) {
  const CFIRow* row = cfi.RowAt(next);
  if (row == nullptr || row == here) {
    return true;  // still inside the same row, so certainly the same block
  }
  if (row->cfa.kind != CFARule::Kind::kRegOffset || row->cfa.reg >= kNumGPRs) {
    return true;
  }
  const AbsVal& was = before[row->cfa.reg];
  const AbsVal& now = after.reg(row->cfa.reg);
  if (was.kind != AbsVal::Kind::kCFARel || now.kind != AbsVal::Kind::kCFARel) {
    return true;  // not confident enough to prune anything
  }
  return CFASatisfiedBy(row->cfa, now) || CFASatisfiedBy(row->cfa, was);
}

// Checks a `ret`, or a tail-call-style jump whose target has no known FDE
// to check it against instead (see check_cross_fde_edge in Check() below,
// which handles every jump target that does), against the x86-64 return
// convention: rsp back at CFA-8, callee-saved registers restored, the
// return-address slot untouched. For a `ret` this is the ABI, not
// optional. For a jump it is a fallback guess -- the target might be a PLT
// stub (excluded from the checkable FDE set even when one exists, so it
// always lands here) or genuinely uncovered code, and there is nothing
// declared to compare against, so this is what "looks like a tail call"
// has to mean instead.
void CheckExitState(uint64_t pc, const AbsState& state, const std::string& insn_text, FindingSink* sink,
                    bool at_function_entry, bool is_tail_call) {
  const char* context = is_tail_call ? "tail call" : "return";
  if (!at_function_entry) {
    sink->Add(Finding::Severity::kReview, pc,
              absl::StrFormat("%s in an FDE that did not start at a canonical function entry", context), insn_text);
    return;
  }

  // 1. Check stack pointer
  const AbsVal& rsp = state.reg(kDWARFRsp);
  if (rsp.is_unknown()) {
    sink->Add(Finding::Severity::kReview, pc, absl::StrFormat("%s with untracked rsp (%v)", context, rsp), insn_text);
  } else if (!rsp.IsCFARel(-8)) {
    if (is_tail_call) {
      sink->Add(Finding::Severity::kReview, pc,
                absl::StrFormat("unconditional jump out of FDE to an address with no covering FDE, with rsp at "
                                "CFA%+d (should be CFA-8 for a tail call; could be a branch to a noreturn call, or "
                                "into code with no CFI at all)",
                                static_cast<int>(rsp.delta)),
                insn_text);
    } else {
      sink->Add(Finding::Severity::kMismatch, pc,
                absl::StrFormat("return with rsp at CFA%+d (should be CFA-8)", rsp.delta), insn_text);
    }
  }

  // A tail call whose rsp is not back at CFA-8 already earned the review
  // above and might just be a branch into a noreturn call or otherwise
  // uncovered code rather than a real tail call -- in which case the frame
  // is not really torn down yet either, so checking callee-saved registers
  // and the return-address slot against the ABI's return convention would
  // only add redundant noise on top of that one review. (A jump into a
  // `.cold` fragment with an FDE of its own no longer reaches this
  // function at all -- it is checked against that FDE's declared row by
  // check_cross_fde_edge in Check() instead.)
  bool ambiguous_tail_call = is_tail_call && !rsp.IsCFARel(-8);

  // 2. Check callee-saved registers
  if (!ambiguous_tail_call) {
    for (int r : kCalleeSaved) {
      const AbsVal& v = state.reg(r);
      if (v.is_unknown()) {
        sink->Add(Finding::Severity::kReview, pc,
                  absl::StrFormat("%s with untracked callee-saved register %s (%v)", context, DWARFRegName(r), v),
                  insn_text);
      } else if (!v.IsOrigReg(r)) {
        sink->Add(Finding::Severity::kMismatch, pc,
                  absl::StrFormat("%s with callee-saved register %s holding %v (entry value was not restored)", context,
                                  DWARFRegName(r), v),
                  insn_text);
      }
    }
  }

  // 3. Check return address slot at [CFA-8]
  if (!ambiguous_tail_call) {
    AbsVal ra = state.Slot(-8);
    if (ra.is_unknown()) {
      sink->Add(Finding::Severity::kReview, pc,
                absl::StrFormat("%s with untracked return address slot at [CFA-8] (%v)", context, ra), insn_text);
    } else if (!ra.IsOrigReg(kDWARFRip)) {
      sink->Add(Finding::Severity::kMismatch, pc,
                absl::StrFormat("%s with return address slot at [CFA-8] holding %v (overwritten)", context, ra),
                insn_text);
    }
  }
}

bool IsExitState(const AbsState& state) {
  if (!state.reg(kDWARFRsp).IsCFARel(-8)) {
    return false;
  }
  for (int r : kCalleeSaved) {
    if (!state.reg(r).IsOrigReg(r)) {
      return false;
    }
  }
  return true;
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

bool FDEChecker::LandsInsideSomeFDE(uint64_t addr) const {
  return CFIContaining(addr) != nullptr;
}

const CFI* FDEChecker::CFIContaining(uint64_t pc) const {
  auto it = std::upper_bound(
      cfi_index_.begin(), cfi_index_.end(), pc,
      [](uint64_t a, const std::pair<std::pair<uint64_t, uint64_t>, const CFI*>& e) { return a < e.first.first; });
  if (it == cfi_index_.begin()) {
    return nullptr;
  }
  --it;
  if (pc < it->first.first || pc >= it->first.second) {
    return nullptr;
  }
  return it->second;
}

std::optional<std::vector<uint64_t>> FDEChecker::ResolveJumpTable(uint64_t table_addr, uint64_t entries) const {
  VLOG(1) << absl::StrFormat("ResolveJumpTable(0x%x, %u entries)", table_addr, entries);
  if (entries == 0 || entries > kMaxJumpTableEntries) {
    VLOG(1) << absl::StrFormat("ResolveJumpTable(0x%x): entries=%u out of [1,%u], rejecting", table_addr, entries,
                               kMaxJumpTableEntries);
    return std::nullopt;
  }
  uint64_t size = entries * 4;
  if (!image_.IsFileBackedNonExecutable(table_addr, size)) {
    VLOG(1) << absl::StrFormat("ResolveJumpTable(0x%x): not file-backed & non-executable for %u bytes, rejecting",
                               table_addr, size);
    return std::nullopt;
  }
  std::span<const uint8_t> bytes = image_.BytesAt(table_addr, size);
  if (bytes.size() != size) {
    VLOG(1) << absl::StrFormat("ResolveJumpTable(0x%x): could only read %u of %u bytes, rejecting", table_addr,
                               bytes.size(), size);
    return std::nullopt;
  }
  std::vector<uint64_t> targets;
  targets.reserve(entries);
  for (uint64_t i = 0; i < entries; i++) {
    int32_t rel;
    memcpy(&rel, bytes.data() + i * 4, 4);
    uint64_t target = table_addr + static_cast<int64_t>(rel);
    if (!LandsInsideSomeFDE(target)) {
      VLOG(1) << absl::StrFormat(
          "ResolveJumpTable(0x%x): entry %u -> 0x%x lands outside any FDE, rejecting whole table", table_addr, i,
          target);
      return std::nullopt;
    }
    std::span<const uint8_t> tbytes = image_.BytesAt(target, 16);
    Instruction tinsn;
    if (tbytes.empty() || !disasm_->Decode(tbytes.data(), tbytes.size(), target, &tinsn)) {
      VLOG(1) << absl::StrFormat(
          "ResolveJumpTable(0x%x): entry %u -> 0x%x does not decode as an instruction, rejecting whole table",
          table_addr, i, target);
      return std::nullopt;
    }
    targets.push_back(target);
  }
  VLOG(1) << absl::StrFormat("ResolveJumpTable(0x%x): resolved all %u entries", table_addr, entries);
  return targets;
}

FDEResult FDEChecker::Check(const CFI& cfi, bool at_function_entry) const {
  FDEResult result;
  result.fde_addr = cfi.fde_addr;
  result.pc_begin = cfi.pc_begin;
  result.pc_end = cfi.pc_end;
  result.signal_frame = cfi.signal_frame;

  FindingSink sink{options_.max_findings_per_fde};
  RowChecker row_checker{options_, &sink};
  InsnSemantics semantics;

  // Checks `state` (the abstract state right before an unconditional jump,
  // or a resolved jump-table entry, at `pc`) against the declared CFI row
  // at `target`, when some other checkable FDE covers it. This is strictly
  // more precise than guessing at tail-call-ABI compliance: a jump into
  // another FDE's `.cold` fragment or a shared switch-table case is
  // checked against what that FDE actually declares, the same way any
  // other CFI row is checked in this tool. Returns false when no FDE
  // covers `target` (a PLT stub is exactly this case, since
  // RunStructuralChecks excludes PLT-covered FDEs from what the caller
  // hands us), so the caller can fall back to the ABI-based check.
  auto check_cross_fde_edge = [&](uint64_t edge_pc, uint64_t target, const AbsState& edge_state,
                                  const std::string& edge_insn_text) {
    const CFI* target_cfi = CFIContaining(target);
    if (target_cfi == nullptr) {
      return false;
    }
    const CFIRow* target_row = target_cfi->RowAt(target);
    if (target_row == nullptr) {
      return false;
    }
    // Force-check unmentioned callee-saved registers only at the target
    // FDE's own canonical entry row: there, DWARF convention (and
    // AbsState::SeedFromRow's own seeding, see §4.3) already treats
    // silence as "still holds the caller's value", so this just applies
    // that same convention here instead of leaving a tail-call-breaking
    // clobber unnoticed because the target's body never bothered to spell
    // out what a genuine entry implies for free.
    bool target_is_canonical_entry = target == target_cfi->pc_begin && target_row->IsCanonicalEntry();
    row_checker.Check(edge_pc, *target_row, edge_state, edge_insn_text,
                      absl::StrFormat("jump to 0x%x (FDE at 0x%x): ", target, target_cfi->fde_addr),
                      target_is_canonical_entry);
    return true;
  };

  // Forward dataflow over the instructions reachable from pc_begin by
  // direct control flow. Per-instruction rather than per-block: simpler,
  // and functions are small enough that it does not matter.
  absl::flat_hash_map<uint64_t, AbsState> in_states;
  absl::flat_hash_map<uint64_t, size_t> insn_sizes;
  absl::flat_hash_map<uint64_t, std::vector<JoinConflict>> join_conflicts;
  std::vector<uint64_t> worklist;
  // Tracks which addresses currently have an entry sitting in `worklist`,
  // so `propagate` never pushes a second entry for a pc that is already
  // pending -- without this, several predecessors each detecting a change
  // before the target is dequeued produces duplicate pops that redo
  // decode/Transfer work for no new information (the state read out of
  // in_states is already fully joined by the time any of the duplicates
  // run). Cleared to false when the pc is actually popped in `drain`.
  absl::flat_hash_map<uint64_t, bool> pending_pushes;

  size_t estimated_capacity = std::max<size_t>(1024, (cfi.pc_end - cfi.pc_begin) / 3);
  in_states.reserve(estimated_capacity);
  insn_sizes.reserve(estimated_capacity);
  worklist.reserve(estimated_capacity);
  pending_pushes.reserve(estimated_capacity);
  join_conflicts.reserve(estimated_capacity / 4);

  size_t propagate_calls = 0;
  size_t propagate_changed = 0;
  size_t propagate_dedup_skipped = 0;

  auto propagate = [&](uint64_t pc, const AbsState& state) {
    propagate_calls++;
    auto it = in_states.find(pc);
    if (it == in_states.end()) {
      in_states.emplace(pc, state);
      worklist.push_back(pc);
      pending_pushes[pc] = true;
      VLOG(2) << absl::StrFormat("propagate(0x%x): first sighting, enqueued", pc);
      return;
    }
    std::vector<JoinConflict> conflicts;
    bool changed = Join(state, &it->second, &conflicts);
    if (!conflicts.empty()) {
      std::vector<JoinConflict>& list = join_conflicts[pc];
      list.insert(std::end(list), conflicts.begin(), conflicts.end());
    }
    if (changed) {
      propagate_changed++;
      if (pending_pushes[pc]) {
        propagate_dedup_skipped++;
        VLOG(2) << absl::StrFormat("propagate(0x%x): state changed but entry already pending -- not re-enqueuing", pc);
      } else {
        pending_pushes[pc] = true;
        worklist.push_back(pc);
        VLOG(2) << absl::StrFormat("propagate(0x%x): state changed, enqueued", pc);
      }
    } else {
      VLOG(2) << absl::StrFormat("propagate(0x%x): no change", pc);
    }
  };

  const CFIRow* first_row = cfi.RowAt(cfi.pc_begin);
  if (first_row == nullptr) {
    sink.Add(Finding::Severity::kReview, cfi.pc_begin, "no CFI row covers the start of this FDE", "");
    result.findings = sink.Take();
    result.verdict = Verdict::kReview;
    return result;
  }
  bool is_canonical_entry = first_row->IsCanonicalEntry();

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
    if (first_row->cfa.kind != CFARule::Kind::kRegOffset || first_row->cfa.reg != kDWARFRsp ||
        first_row->cfa.offset != 8) {
      sink.Add(Finding::Severity::kReview, cfi.pc_begin,
               absl::StrFormat("a function symbol starts here, so the CFA should be rsp+8, but the CFI says %v%s",
                               first_row->cfa, kEnteredByJump),
               "");
    }
    const RegRule& ra = first_row->regs[kDWARFRip];
    if (ra.kind != RegRule::Kind::kAtCFAOffset || ra.offset != -8) {
      if (ra.kind != RegRule::Kind::kUndefined) {
        sink.Add(Finding::Severity::kReview, cfi.pc_begin,
                 absl::StrFormat("a function symbol starts here, so the return address should be at [CFA-8], but "
                                 "the CFI says %v%s",
                                 ra, kEnteredByJump),
                 "");
      }
    }
  }

  // Exception landing pads are reachable only through the unwinder, via
  // the LSDA -- nothing in the function body branches to one directly, so
  // the ordinary control-flow walk below would never find them on its
  // own. The LSDA's call-site table says exactly which `call` instructions
  // can throw into which landing pad, so each of those is wired in below
  // as a real CFG edge, carrying the abstract state computed right after
  // the call (callee-saved and CFA preserved, caller-saved clobbered --
  // the same transfer function already used for the call's own
  // fall-through edge, since that is exactly what the unwinder would
  // restore before jumping to the pad). This is strictly more precise
  // than trusting the pad's own declared row: the state is derived from
  // code actually walked, so it both fixes the coverage gap and doubles
  // as a real check that the row agrees with it -- a stale CFI on the
  // exceptional edge now shows up as a mismatch instead of being
  // definitionally unobservable.
  std::vector<LSDACallSite> call_sites;
  if (cfi.lsda_addr != 0) {
    try {
      call_sites = ReadLSDACallSites(image_, cfi.lsda_addr, cfi.pc_begin);
    } catch (const EHFrameError& e) {
      sink.Add(Finding::Severity::kReview, cfi.pc_begin,
               absl::StrFormat("failed to parse this FDE's LSDA (.gcc_except_table) at 0x%016x: %s", cfi.lsda_addr,
                               e.what()),
               "");
      call_sites.clear();
    }
    // A malformed LSDA shouldn't be able to walk us outside the FDE.
    call_sites.erase(std::remove_if(call_sites.begin(), call_sites.end(),
                                    [&](const LSDACallSite& cs) {
                                      return cs.landing_pad < cfi.pc_begin || cs.landing_pad >= cfi.pc_end;
                                    }),
                     call_sites.end());
  }
  // call_sites is sorted by start (ReadLSDACallSites) and, per the
  // Itanium ABI, partitions the FDE without overlap, so the entry
  // covering call_pc (if any) is the last one whose start is <= call_pc.
  auto landing_pad_for_call = [&](uint64_t call_pc) -> std::optional<uint64_t> {
    auto it = std::upper_bound(call_sites.begin(), call_sites.end(), call_pc,
                               [](uint64_t pc, const LSDACallSite& cs) { return pc < cs.start; });
    if (it == call_sites.begin()) {
      return std::nullopt;
    }
    --it;
    if (call_pc >= it->start && call_pc < it->end) {
      return it->landing_pad;
    }
    return std::nullopt;
  };

  // Start with "normal" instructions. Landing pads don't have known rsp
  // state. Seeded on is_canonical_entry, not at_function_entry: symbol
  // tables are frequently absent (a stripped binary has one for maybe a
  // third of its FDEs), but a callee-saved register cannot be clobbered
  // without first being spilled, and spilling one requires moving off
  // CFA=rsp+8 -- so an unmoved, canonical CFA is itself proof nothing
  // relevant has run yet, no symbol required. This does mean a genuine
  // function entry with a non-canonical first row (_dl_runtime_resolve_fxsave)
  // seeds unmentioned registers to kTop instead of their entry value; that
  // costs precision, never soundness, and such rows already earn their own
  // review above.
  propagate(cfi.pc_begin, AbsState::SeedFromRow(*first_row, is_canonical_entry));

  // Pass 1: Forward dataflow until the abstract state settles across all reached instructions.
  size_t iterations = 0;
  bool hit_cap = false;
  auto drain = [&]() {
    while (!worklist.empty()) {
      if (++iterations > options_.max_iterations) {
        hit_cap = true;
        break;
      }
      uint64_t pc = worklist.back();
      worklist.pop_back();
      pending_pushes[pc] = false;
      VLOG(2) << absl::StrFormat("drain: pop 0x%x (iteration %u, %u still queued)", pc, iterations, worklist.size());
      AbsState state = in_states[pc];

      std::span<const uint8_t> bytes = image_.BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
      Instruction insn;
      if (bytes.empty() || !disasm_->Decode(bytes.data(), bytes.size(), pc, &insn) || pc + insn.size > cfi.pc_end) {
        continue;
      }
      size_t insn_size = insn.size;
      insn_sizes[pc] = insn_size;
      bool is_ja_or_jae = insn.id == ZYDIS_MNEMONIC_JNBE || insn.id == ZYDIS_MNEMONIC_JNB;
      bool is_jae = insn.id == ZYDIS_MNEMONIC_JNB;

      const CFIRow* row = cfi.RowAt(pc);
      AbsVal before[kNumGPRs];
      std::copy(std::begin(state.gpr), std::end(state.gpr), std::begin(before));
      TransferOutcome outcome = semantics.Transfer(insn, &state);

      if (outcome.is_call) {
        std::optional<uint64_t> lp = landing_pad_for_call(pc);
        if (lp.has_value()) {
          VLOG(2) << absl::StrFormat("0x%x: call site propagates to landing pad 0x%x", pc, *lp);
          propagate(*lp, state);
        }
      }

      if (outcome.falls_through) {
        uint64_t next = pc + insn_size;
        if (next < cfi.pc_end && FallThroughIsReal(cfi, row, next, before, state)) {
          AbsState fallthrough_state = state;
          // `state` here is the already-transferred state for this
          // ja/jae itself, which doesn't write EFLAGS -- so if a `cmp
          // $imm,%reg` guard dominates this point, it's sitting right in
          // `state.last_cmp`, tracked forward as part of the ordinary
          // lattice (AbsState::last_cmp, joined like any other field).
          // No backward search needed: a bypassing predecessor that never
          // ran the cmp would already have cleared this via Join.
          if (is_ja_or_jae && state.last_cmp.has_value()) {
            int reg = state.last_cmp->reg;
            uint8_t width = state.last_cmp->width_bits;
            uint64_t imm = state.last_cmp->imm;
            // On the in-bounds (fall-through) edge, `ja` means reg <= imm
            // and `jae` means reg < imm.
            if (!is_jae || imm != 0) {
              uint64_t ubound = is_jae ? imm - 1 : imm;
              fallthrough_state.last_cmp->imm = ubound;
              if (width >= 32) {
                VLOG(1) << absl::StrFormat("0x%x: %s taken-edge guard sets bound[%d]=%u on fall-through to 0x%x", pc,
                                           is_jae ? "jae" : "ja", reg, ubound, next);
                fallthrough_state.SetBound(reg, ubound);
              }
            }
          }
          propagate(next, fallthrough_state);
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
      if (outcome.has_jump_table) {
        std::optional<std::vector<uint64_t>> targets =
            ResolveJumpTable(outcome.jump_table_addr, outcome.jump_table_entries);
        if (targets.has_value()) {
          for (uint64_t target : *targets) {
            if (target >= cfi.pc_begin && target < cfi.pc_end) {
              propagate(target, state);
            }
            // A target outside our own FDE is cross-FDE dispatch (§6); that
            // FDE gets its own walk, and pass 2 below notes it without
            // trying to follow.
          }
        }
      }
    }
  };
  drain();

  // A handful of landing pads may still be unreached: a call-site region
  // whose call instruction was never itself walked (e.g. dead by an
  // unrelated reachability gap), or an encoding this reader didn't
  // resolve to an edge. Fall back to trusting each one's own declared
  // row -- the same "seed the target's row directly" trust used
  // everywhere else a predecessor state cannot be derived -- so a
  // landing pad is never silently left as a coverage gap merely because
  // its precise edge could not be found. This is strictly the weaker,
  // pre-existing behavior, so it is flagged as a review rather than
  // treated as equivalent to a state actually checked against.
  {
    std::vector<uint64_t> distinct_landing_pads;
    distinct_landing_pads.reserve(call_sites.size());
    for (const LSDACallSite& cs : call_sites) {
      distinct_landing_pads.push_back(cs.landing_pad);
    }
    std::sort(distinct_landing_pads.begin(), distinct_landing_pads.end());
    distinct_landing_pads.erase(std::unique(distinct_landing_pads.begin(), distinct_landing_pads.end()),
                                distinct_landing_pads.end());
    bool seeded_any = false;
    for (uint64_t lp : distinct_landing_pads) {
      if (in_states.contains(lp)) {
        continue;
      }
      const CFIRow* row = cfi.RowAt(lp);
      if (row == nullptr) {
        continue;  // reported as a missing-row finding once the walk reaches nearby code
      }
      sink.Add(Finding::Severity::kReview, lp,
               "this landing pad's incoming state could not be derived from any call site actually walked, so it is "
               "trusted from its own declared CFI row instead of independently checked",
               "");
      propagate(lp, AbsState::SeedFromRow(*row, /*at_function_entry=*/false));
      seeded_any = true;
    }
    if (seeded_any) {
      drain();
    }
  }

  VLOG(2) << absl::StrFormat(
      "FDE 0x%x done: %u worklist pops, %u propagate() calls (%u changed, %u deduped against an already-"
      "pending entry), %u distinct addresses reached, %u call sites in LSDA",
      cfi.pc_begin, iterations, propagate_calls, propagate_changed, propagate_dedup_skipped, in_states.size(),
      call_sites.size());

  if (hit_cap) {
    sink.Add(Finding::Severity::kReview, cfi.pc_begin,
             absl::StrFormat("analysis gave up after %d dataflow steps", options_.max_iterations), "");
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
    Instruction insn;
    if (bytes.empty() || !disasm_->Decode(bytes.data(), bytes.size(), pc, &insn)) {
      sink.Add(Finding::Severity::kReview, pc, "cannot decode the instruction at this address", "");
      continue;
    }
    std::string insn_text =
        Disassembler::Text(insn).value_or(absl::StrFormat("<cannot format instruction at 0x%x>", pc));
    if (pc + insn.size > cfi.pc_end) {
      sink.Add(Finding::Severity::kReview, pc, "instruction runs past the end of the FDE's PC range", insn_text);
      continue;
    }
    result.instructions_checked++;

    // The row at pc describes the state when RIP == pc, so compare
    // before applying the instruction, not after.
    const CFIRow* row = cfi.RowAt(pc);
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
    TransferOutcome outcome = semantics.Transfer(insn, &state_copy);
    if (outcome.review_reason != nullptr) {
      sink.Add(Finding::Severity::kReview, pc, outcome.review_reason, insn_text);
    }
    if (outcome.has_jump_table) {
      std::optional<std::vector<uint64_t>> targets =
          ResolveJumpTable(outcome.jump_table_addr, outcome.jump_table_entries);
      if (!targets.has_value()) {
        sink.Add(Finding::Severity::kReview, pc,
                 "unresolved indirect jump; jump tables are not resolved in this version, so the code it reaches "
                 "went unchecked",
                 insn_text);
      } else {
        for (uint64_t target : *targets) {
          if (target < cfi.pc_begin || target >= cfi.pc_end) {
            if (!check_cross_fde_edge(pc, target, state, insn_text)) {
              sink.Add(Finding::Severity::kReview, pc,
                       absl::StrFormat("resolved switch-table entry at 0x%x lands outside this FDE's range and no "
                                       "FDE covers it, so there is no declared row to check it against",
                                       target),
                       insn_text);
            }
          }
        }
        // In-range targets were walked in pass 1 and are checked in their
        // own right when pass 2 reaches them; nothing further to say here.
      }
    } else if (outcome.is_return) {
      CheckExitState(pc, state, insn_text, &sink, is_canonical_entry, /*is_tail_call=*/false);
    } else if (!outcome.falls_through && outcome.has_direct_target &&
               (outcome.direct_target < cfi.pc_begin || outcome.direct_target >= cfi.pc_end)) {
      if (!check_cross_fde_edge(pc, outcome.direct_target, state, insn_text)) {
        CheckExitState(pc, state, insn_text, &sink, is_canonical_entry, /*is_tail_call=*/true);
      }
    } else if (outcome.indirect_branch) {
      if (is_canonical_entry && IsExitState(state)) {
        // Indirect tail call (e.g. virtual call or function pointer tail call)
        // with valid exit state -- blessed.
      } else {
        sink.Add(Finding::Severity::kReview, pc,
                 "unresolved indirect jump; jump tables are not resolved in this version, so the code it reaches "
                 "went unchecked",
                 insn_text);
      }
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
          Instruction insn;
          if (bytes.empty() || !disasm_->Decode(bytes.data(), bytes.size(), pc, &insn)) {
            all_padding = false;
            pc++;
            continue;
          }
          if (insn.id != ZYDIS_MNEMONIC_NOP && insn.id != ZYDIS_MNEMONIC_INT3) {
            all_padding = false;
          }
          pc += insn.size;
        }
        if (!all_padding) {
          sink.Add(Finding::Severity::kReview, gap_start,
                   absl::StrFormat("%d bytes from here were not reached by the control-flow walk, so their CFI went "
                                   "unchecked (exception landing pads and jump-table targets look like this)",
                                   pc - gap_start),
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

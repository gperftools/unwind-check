/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "fde-checker.h"

#include <string.h>

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

constexpr int kCalleeSaved[] = {kDWARFRbx, kDWARFRbp, 12, 13, 14, 15};
constexpr uint64_t kMaxJumpTableEntries = 512;

bool IsCalleeSaved(int reg) {
  return std::find(std::begin(kCalleeSaved), std::end(kCalleeSaved), reg) != std::end(kCalleeSaved);
}

// Switch-table bound tracking (initial-switch-tables-plan.md §3.2). One
// register's fact: a `cmp $imm,%r; ja/jae default` guard was found
// dominating this point, so %r's value is known to be at most `ubound`
// on the in-bounds edge.
struct BoundGuard {
  int reg;
  uint64_t ubound;
};

// Walks backward from a ja/jae at `branch_pc` over the straight-line
// fall-through predecessor chain, stopping at the first instruction that
// writes EFLAGS. `fallthrough_pred` records, for every address reached
// via ordinary fall-through during pass 1, the single instruction that
// falls through to it -- which is exactly "the previous instruction in
// this straight-line block", so this walk naturally stops at a block
// boundary (a predecessor reached only by a jump has no entry there)
// without needing real dominance.
//
// Relaxing this to "the nearest preceding cmp on some register" was
// measured and is wrong: it picks up an unrelated cmp in glibc's
// nss_database_check_reload_and_get, which is a genuinely unbounded
// data-driven dispatch with no guard at all.
std::optional<BoundGuard> FindGuardBound(uint64_t branch_pc, bool is_jae, const ELFImage& image, Disassembler* disasm,
                                         uint64_t pc_end,
                                         const absl::flat_hash_map<uint64_t, uint64_t>& fallthrough_pred) {
  uint64_t pc = branch_pc;
  for (int hops = 0; hops < 64; hops++) {
    auto it = fallthrough_pred.find(pc);
    if (it == fallthrough_pred.end()) {
      return std::nullopt;
    }
    pc = it->second;
    std::span<const uint8_t> bytes = image.BytesAt(pc, std::min<uint64_t>(16, pc_end - pc));
    const cs_insn* insn = bytes.empty() ? nullptr : disasm->DecodeOne(bytes.data(), bytes.size(), pc);
    if (insn == nullptr) {
      return std::nullopt;
    }
    cs_regs read;
    cs_regs written;
    uint8_t read_count = 0;
    uint8_t write_count = 0;
    bool writes_eflags = false;
    if (cs_regs_access(disasm->handle(), insn, read, &read_count, written, &write_count) == CS_ERR_OK) {
      for (uint8_t i = 0; i < write_count; i++) {
        if (written[i] == X86_REG_EFLAGS) {
          writes_eflags = true;
          break;
        }
      }
    }
    if (!writes_eflags) {
      continue;
    }
    if (insn->id != X86_INS_CMP || insn->detail->x86.op_count != 2) {
      return std::nullopt;
    }
    const cs_x86_op& a = insn->detail->x86.operands[0];
    const cs_x86_op& b = insn->detail->x86.operands[1];
    if (a.type != X86_OP_REG || b.type != X86_OP_IMM || b.imm < 0) {
      return std::nullopt;
    }
    int r = InsnSemantics::DWARFRegOf(a.reg);
    if (r < 0) {
      return std::nullopt;
    }
    uint64_t imm = static_cast<uint64_t>(b.imm);
    if (is_jae) {
      if (imm == 0) {
        return std::nullopt;  // imm-1 would underflow: not a usable bound
      }
      imm -= 1;
    }
    return BoundGuard{r, imm};
  }
  return std::nullopt;
}

// Drops a register's tracked bound on any write to it, with two
// exceptions:
//
//  * a zero-extending mov/movzx of the register into itself (`movzbl
//    %al,%eax` and friends) -- GCC's tables insert exactly that between
//    the guard and the table load, and the numeric bound still applies
//    to the widened value;
//  * `movslq disp(%B,%I,4),%I` and `add %B,%I` writing back into their
//    own index register `%I` -- a compiler is free to reuse the index
//    register as the destination once it no longer needs the plain
//    index value (measured: sqlite's own case, `movslq
//    (%r8,%rcx,4),%rcx`), and by construction (checked below via
//    `state`, already updated by Transfer) `%I` is still exactly the
//    register the eventual `jmp` will look the bound up under.
void UpdateUBoundsAfterTransfer(csh handle, const cs_insn& insn, AbsState* state) {
  if ((insn.id == X86_INS_MOV || insn.id == X86_INS_MOVZX) && insn.detail->x86.op_count == 2) {
    const cs_x86_op& dst = insn.detail->x86.operands[0];
    const cs_x86_op& src = insn.detail->x86.operands[1];
    if (dst.type == X86_OP_REG && src.type == X86_OP_REG) {
      int d = InsnSemantics::DWARFRegOf(dst.reg);
      int s = InsnSemantics::DWARFRegOf(src.reg);
      if (d >= 0 && d == s && !InsnSemantics::IsFull64(dst.reg)) {
        return;
      }
    }
  }
  cs_regs read;
  cs_regs written;
  uint8_t read_count = 0;
  uint8_t write_count = 0;
  if (cs_regs_access(handle, &insn, read, &read_count, written, &write_count) != CS_ERR_OK) {
    for (int r = 0; r < kNumGPRs; r++) {
      state->ClearUBound(r);
    }
    return;
  }
  for (uint8_t i = 0; i < write_count; i++) {
    int d = InsnSemantics::DWARFRegOf(written[i]);
    if (d < 0) {
      continue;
    }
    const AbsVal& v = state->reg(d);
    if ((v.IsTableEntry() || v.IsJumpTarget()) && v.IndexReg() == d) {
      continue;
    }
    state->ClearUBound(d);
  }
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
  RowChecker(const FDEChecker::Options& options, FindingSink* sink) : options_(options), sink_(sink) {
  }

  void Check(uint64_t pc, const CFIRow& row, const AbsState& state, const std::string& insn_text) {
    insn_text_ = insn_text;
    pc_ = pc;
    CheckCFA(row.cfa, state);
    for (int r = 0; r < kNumDWARFRegs; r++) {
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
      Review(absl::StrFormat("CFA is declared as %s, but %s holds %s here, so the rule cannot be verified",
                             cfa.ToString(), DWARFRegName(cfa.reg), v.ToString()));
      return;
    }
    if (v.delta + cfa.offset != 0) {
      Mismatch(absl::StrFormat("declared CFA is %s, but %s is CFA%+d here, so the rule yields CFA%+d (should be %s%+d)",
                               cfa.ToString(), DWARFRegName(cfa.reg), static_cast<int>(v.delta),
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

      case RegRule::Kind::kAtCFAOffset: {
        AbsVal at = state.Slot(rule.offset);
        if (at.is_unknown()) {
          Review(absl::StrFormat("CFI says %s is saved at [CFA%+d], but we cannot say what is stored there",
                                 DWARFRegName(r), static_cast<int>(rule.offset)));
          return;
        }
        if (!at.IsOrigReg(r)) {
          Mismatch(absl::StrFormat("CFI says %s is saved at [CFA%+d], but that slot holds %s", DWARFRegName(r),
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
          Review(absl::StrFormat("CFI says %s is CFA%+d, but we are not tracking it here", DWARFRegName(r),
                                 static_cast<int>(rule.offset)));
          return;
        }
        if (!v->IsCFARel(rule.offset)) {
          Mismatch(absl::StrFormat("CFI says %s is CFA%+d, but it holds %s", DWARFRegName(r),
                                   static_cast<int>(rule.offset), v->ToString()));
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
          Mismatch(absl::StrFormat("CFI says %s was moved into %s, but %s holds %s", DWARFRegName(r),
                                   DWARFRegName(rule.reg), DWARFRegName(rule.reg), v->ToString()));
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
      Mismatch(
          absl::StrFormat("CFI says %s still holds its entry value, but it holds %s", DWARFRegName(r), v->ToString()));
    }
  }

  const FDEChecker::Options& options_;
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
    sink->Add(Finding::Severity::kReview, pc, absl::StrFormat("%s with untracked rsp (%s)", context, rsp.ToString()),
              insn_text);
  } else if (!rsp.IsCFARel(-8)) {
    if (is_tail_call) {
      sink->Add(Finding::Severity::kReview, pc,
                absl::StrFormat("unconditional jump out of FDE with rsp at CFA%+d (should be CFA-8 for a tail call; "
                                "could be a branch to a cold fragment or noreturn call)",
                                static_cast<int>(rsp.delta)),
                insn_text);
    } else {
      sink->Add(Finding::Severity::kMismatch, pc,
                absl::StrFormat("return with rsp at CFA%+d (should be CFA-8)", static_cast<int>(rsp.delta)),
                insn_text);
    }
  }

  // A tail call whose rsp is not back at CFA-8 already earned the review
  // above and might just be a branch to a `.cold` fragment rather than a
  // real tail call -- in which case the frame is not really torn down yet
  // either, so checking callee-saved registers and the return-address slot
  // against the ABI's return convention would only add redundant noise on
  // top of that one review.
  bool ambiguous_tail_call = is_tail_call && !rsp.IsCFARel(-8);

  // 2. Check callee-saved registers
  if (!ambiguous_tail_call) {
    for (int r : kCalleeSaved) {
      const AbsVal& v = state.reg(r);
      if (v.is_unknown()) {
        sink->Add(Finding::Severity::kReview, pc,
                  absl::StrFormat("%s with untracked callee-saved register %s (%s)", context, DWARFRegName(r),
                                  v.ToString()),
                  insn_text);
      } else if (!v.IsOrigReg(r)) {
        sink->Add(Finding::Severity::kMismatch, pc,
                  absl::StrFormat("%s with callee-saved register %s holding %s (entry value was not restored)",
                                  context, DWARFRegName(r), v.ToString()),
                  insn_text);
      }
    }
  }

  // 3. Check return address slot at [CFA-8]
  if (!ambiguous_tail_call) {
    AbsVal ra = state.Slot(-8);
    if (ra.is_unknown()) {
      sink->Add(Finding::Severity::kReview, pc,
                absl::StrFormat("%s with untracked return address slot at [CFA-8] (%s)", context, ra.ToString()),
                insn_text);
    } else if (!ra.IsOrigReg(kDWARFRip)) {
      sink->Add(Finding::Severity::kMismatch, pc,
                absl::StrFormat("%s with return address slot at [CFA-8] holding %s (overwritten)", context,
                                ra.ToString()),
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
  auto it = std::upper_bound(all_fde_ranges_.begin(), all_fde_ranges_.end(), addr,
                             [](uint64_t a, const std::pair<uint64_t, uint64_t>& r) { return a < r.first; });
  if (it == all_fde_ranges_.begin()) {
    return false;
  }
  --it;
  return addr >= it->first && addr < it->second;
}

std::optional<std::vector<uint64_t>> FDEChecker::ResolveJumpTable(uint64_t table_addr, uint64_t entries) const {
  if (entries == 0 || entries > kMaxJumpTableEntries) {
    return std::nullopt;
  }
  uint64_t size = entries * 4;
  if (!image_.IsFileBackedNonExecutable(table_addr, size)) {
    return std::nullopt;
  }
  std::span<const uint8_t> bytes = image_.BytesAt(table_addr, size);
  if (bytes.size() != size) {
    return std::nullopt;
  }
  std::vector<uint64_t> targets;
  targets.reserve(entries);
  for (uint64_t i = 0; i < entries; i++) {
    int32_t rel;
    memcpy(&rel, bytes.data() + i * 4, 4);
    uint64_t target = table_addr + static_cast<int64_t>(rel);
    if (!LandsInsideSomeFDE(target)) {
      return std::nullopt;
    }
    std::span<const uint8_t> tbytes = image_.BytesAt(target, 16);
    const cs_insn* tinsn = tbytes.empty() ? nullptr : disasm_->DecodeOne(tbytes.data(), tbytes.size(), target);
    if (tinsn == nullptr) {
      return std::nullopt;
    }
    targets.push_back(target);
  }
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
  InsnSemantics semantics{disasm_->handle()};

  // Forward dataflow over the instructions reachable from pc_begin by
  // direct control flow. Per-instruction rather than per-block: simpler,
  // and functions are small enough that it does not matter.
  absl::flat_hash_map<uint64_t, AbsState> in_states;
  absl::flat_hash_map<uint64_t, size_t> insn_sizes;
  absl::flat_hash_map<uint64_t, std::vector<JoinConflict>> join_conflicts;
  // Records, for every address reached via ordinary fall-through, the
  // single instruction that falls through to it. Used only to walk
  // backward for a switch-table bound guard (§3.2) -- see FindGuardBound.
  absl::flat_hash_map<uint64_t, uint64_t> fallthrough_pred;
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

  const CFIRow* first_row = cfi.RowAt(cfi.pc_begin);
  if (first_row == nullptr) {
    sink.Add(Finding::Severity::kReview, cfi.pc_begin, "no CFI row covers the start of this FDE", "");
    result.findings = sink.Take();
    result.verdict = Verdict::kReview;
    return result;
  }
  bool is_canonical_entry = (first_row->cfa.kind == CFARule::Kind::kRegOffset &&
                              first_row->cfa.reg == kDWARFRsp &&
                              first_row->cfa.offset == 8 &&
                              (first_row->regs[kDWARFRip].kind == RegRule::Kind::kAtCFAOffset &&
                               first_row->regs[kDWARFRip].offset == -8));

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
               absl::StrFormat("a function symbol starts here, so the CFA should be rsp+8, but the CFI says %s%s",
                               first_row->cfa.ToString(), kEnteredByJump),
               "");
    }
    const RegRule& ra = first_row->regs[kDWARFRip];
    if (ra.kind != RegRule::Kind::kAtCFAOffset || ra.offset != -8) {
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
      landing_pads = ReadLSDALandingPads(image_, cfi.lsda_addr, cfi.pc_begin);
    } catch (const EHFrameError& e) {
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
      const CFIRow* row = cfi.RowAt(lp);
      if (row == nullptr) {
        continue;  // reported as a missing-row finding once the walk reaches nearby code
      }
      propagate(lp, AbsState::SeedFromRow(*row, /*at_function_entry=*/false));
    }
  }

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
    bool is_ja_or_jae = insn->id == X86_INS_JA || insn->id == X86_INS_JAE;
    bool is_jae = insn->id == X86_INS_JAE;

    const CFIRow* row = cfi.RowAt(pc);
    AbsVal before[kNumGPRs];
    std::copy(std::begin(state.gpr), std::end(state.gpr), std::begin(before));
    TransferOutcome outcome = semantics.Transfer(*insn, &state);
    UpdateUBoundsAfterTransfer(disasm_->handle(), *insn, &state);

    if (outcome.falls_through) {
      uint64_t next = pc + insn_size;
      if (next < cfi.pc_end && FallThroughIsReal(cfi, row, next, before, state)) {
        AbsState fallthrough_state = state;
        if (is_ja_or_jae) {
          std::optional<BoundGuard> guard = FindGuardBound(pc, is_jae, image_, disasm_, cfi.pc_end, fallthrough_pred);
          if (guard.has_value()) {
            fallthrough_state.SetUBound(guard->reg, guard->ubound);
          }
        }
        propagate(next, fallthrough_state);
        fallthrough_pred[next] = pc;
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
      std::optional<std::vector<uint64_t>> targets = ResolveJumpTable(outcome.jump_table_addr, outcome.jump_table_entries);
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
    TransferOutcome outcome = semantics.Transfer(*insn, &state_copy);
    if (outcome.review_reason != nullptr) {
      sink.Add(Finding::Severity::kReview, pc, outcome.review_reason, insn_text);
    }
    if (outcome.has_jump_table) {
      std::optional<std::vector<uint64_t>> targets = ResolveJumpTable(outcome.jump_table_addr, outcome.jump_table_entries);
      if (!targets.has_value()) {
        sink.Add(Finding::Severity::kReview, pc,
                 "unresolved indirect jump; jump tables are not resolved in this version, so the code it reaches "
                 "went unchecked",
                 insn_text);
      } else {
        for (uint64_t target : *targets) {
          if (target < cfi.pc_begin || target >= cfi.pc_end) {
            sink.Add(Finding::Severity::kReview, pc,
                     absl::StrFormat("resolved switch-table entry at 0x%llx lands outside this FDE's range; it is "
                                     "not followed here and is checked on its own as part of whatever FDE covers it",
                                     static_cast<unsigned long long>(target)),
                     insn_text);
          }
        }
        // In-range targets were walked in pass 1 and are checked in their
        // own right when pass 2 reaches them; nothing further to say here.
      }
    } else if (outcome.is_return) {
      CheckExitState(pc, state, insn_text, &sink, is_canonical_entry, /*is_tail_call=*/false);
    } else if (!outcome.falls_through && outcome.has_direct_target &&
               (outcome.direct_target < cfi.pc_begin || outcome.direct_target >= cfi.pc_end)) {
      CheckExitState(pc, state, insn_text, &sink, is_canonical_entry, /*is_tail_call=*/true);
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

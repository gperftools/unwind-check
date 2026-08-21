/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "insn-semantics.h"

#include <memory>
#include <optional>

#include "absl/container/flat_hash_map.h"
#include "absl/log/log.h"
#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

struct RegAlias {
  x86_reg reg;
  int dwarf;
  bool full64;
};

// Registers a call may destroy, per the x86-64 psABI.
constexpr int kCallerSaved[] = {0, 1, 2, 4, 5, 8, 9, 10, 11};

const RegAlias* FindAlias(unsigned reg) {
  // DWARF numbering for x86-64 is the psABI's, not the encoding order:
  // rax rdx rcx rbx rsi rdi rbp rsp, then r8..r15.
  static constexpr RegAlias kAliases[] = {
      {X86_REG_RAX, 0, true},  {X86_REG_EAX, 0, false},   {X86_REG_AX, 0, false},    {X86_REG_AL, 0, false},
      {X86_REG_AH, 0, false},  {X86_REG_RDX, 1, true},    {X86_REG_EDX, 1, false},   {X86_REG_DX, 1, false},
      {X86_REG_DL, 1, false},  {X86_REG_DH, 1, false},    {X86_REG_RCX, 2, true},    {X86_REG_ECX, 2, false},
      {X86_REG_CX, 2, false},  {X86_REG_CL, 2, false},    {X86_REG_CH, 2, false},    {X86_REG_RBX, 3, true},
      {X86_REG_EBX, 3, false}, {X86_REG_BX, 3, false},    {X86_REG_BL, 3, false},    {X86_REG_BH, 3, false},
      {X86_REG_RSI, 4, true},  {X86_REG_ESI, 4, false},   {X86_REG_SI, 4, false},    {X86_REG_SIL, 4, false},
      {X86_REG_RDI, 5, true},  {X86_REG_EDI, 5, false},   {X86_REG_DI, 5, false},    {X86_REG_DIL, 5, false},
      {X86_REG_RBP, 6, true},  {X86_REG_EBP, 6, false},   {X86_REG_BP, 6, false},    {X86_REG_BPL, 6, false},
      {X86_REG_RSP, 7, true},  {X86_REG_ESP, 7, false},   {X86_REG_SP, 7, false},    {X86_REG_SPL, 7, false},
      {X86_REG_R8, 8, true},   {X86_REG_R8D, 8, false},   {X86_REG_R8W, 8, false},   {X86_REG_R8B, 8, false},
      {X86_REG_R9, 9, true},   {X86_REG_R9D, 9, false},   {X86_REG_R9W, 9, false},   {X86_REG_R9B, 9, false},
      {X86_REG_R10, 10, true}, {X86_REG_R10D, 10, false}, {X86_REG_R10W, 10, false}, {X86_REG_R10B, 10, false},
      {X86_REG_R11, 11, true}, {X86_REG_R11D, 11, false}, {X86_REG_R11W, 11, false}, {X86_REG_R11B, 11, false},
      {X86_REG_R12, 12, true}, {X86_REG_R12D, 12, false}, {X86_REG_R12W, 12, false}, {X86_REG_R12B, 12, false},
      {X86_REG_R13, 13, true}, {X86_REG_R13D, 13, false}, {X86_REG_R13W, 13, false}, {X86_REG_R13B, 13, false},
      {X86_REG_R14, 14, true}, {X86_REG_R14D, 14, false}, {X86_REG_R14W, 14, false}, {X86_REG_R14B, 14, false},
      {X86_REG_R15, 15, true}, {X86_REG_R15D, 15, false}, {X86_REG_R15W, 15, false}, {X86_REG_R15B, 15, false},
  };

  static const absl::flat_hash_map<x86_reg, RegAlias>& kMap = ([]() {
    auto map = std::make_unique<absl::flat_hash_map<x86_reg, RegAlias>>();
    for (const RegAlias& a : kAliases) {
      map->emplace(a.reg, a);
    }
    return *map.release();
  })();

  auto it = kMap.find(static_cast<x86_reg>(reg));
  if (it == kMap.end()) {
    return nullptr;
  }
  return &it->second;
}

const cs_x86& X86(const cs_insn& insn) {
  return insn.detail->x86;
}

// The value a register operand reads, as far as we track it.
AbsVal ReadReg(const AbsState& state, unsigned reg) {
  if (!InsnSemantics::IsFull64(reg)) {
    return AbsVal::Top();
  }
  return state.reg(InsnSemantics::DWARFRegOf(reg));
}

// The CFA-relative offset a memory operand addresses, when we can name
// it. Anything with an index register, a segment override or a base we
// are not tracking is simply not a stack slot as far as we are
// concerned.
std::optional<int64_t> MemSlot(const AbsState& state, const x86_op_mem& mem) {
  if (mem.segment != X86_REG_INVALID || mem.index != X86_REG_INVALID) {
    return std::nullopt;
  }
  if (mem.base == X86_REG_INVALID || !InsnSemantics::IsFull64(mem.base)) {
    return std::nullopt;
  }
  const AbsVal& base = state.reg(InsnSemantics::DWARFRegOf(mem.base));
  if (base.kind != AbsVal::Kind::kCFARel) {
    return std::nullopt;
  }
  return base.delta + mem.disp;
}

// The address a `lea` computes, as a value.
AbsVal LeaValue(const AbsState& state, const x86_op_mem& mem) {
  std::optional<int64_t> slot = MemSlot(state, mem);
  if (!slot.has_value()) {
    return AbsVal::Top();
  }
  return AbsVal::CFARel(*slot);
}

void EraseSlots(AbsState* state, int64_t start, int64_t size) {
  auto it = state->slots.lower_bound(start - 7);
  while (it != state->slots.end() && it->first < start + size) {
    it = state->slots.erase(it);
  }
}

// A memory write we could not place. We assume it does not alias the
// frame slots we track.
//
// This is unsound in principle: nothing stops a program from writing its
// own spill slot through a laundered pointer. It is also exactly the
// assumption objtool and LLVM's CFIInstrInserter make, for the same
// reason -- the alternative, dropping every tracked slot on every store
// through an untracked base, would make essentially every real function
// unverifiable and drown the report in noise.
void HandleUnplacedMemWrite(AbsState*) {
}

// True when this instruction's Capstone write-set includes EFLAGS.
bool WritesEflags(csh handle, const cs_insn& insn) {
  cs_regs read;
  cs_regs written;
  uint8_t read_count = 0;
  uint8_t write_count = 0;
  if (cs_regs_access(handle, &insn, read, &read_count, written, &write_count) != CS_ERR_OK) {
    return true;  // unknown effect -- assume the worst, same as ClobberWrites does
  }
  for (uint8_t i = 0; i < write_count; i++) {
    if (written[i] == X86_REG_EFLAGS) {
      return true;
    }
  }
  return false;
}

}  // namespace

int InsnSemantics::DWARFRegOf(unsigned reg) {
  const RegAlias* a = FindAlias(reg);
  return a == nullptr ? -1 : a->dwarf;
}

bool InsnSemantics::IsFull64(unsigned reg) {
  const RegAlias* a = FindAlias(reg);
  return a != nullptr && a->full64;
}

void InsnSemantics::ClobberWrites(const cs_insn& insn, AbsState* state) const {
  cs_regs read;
  cs_regs written;
  uint8_t read_count = 0;
  uint8_t write_count = 0;
  if (cs_regs_access(handle_, &insn, read, &read_count, written, &write_count) != CS_ERR_OK) {
    // We could not find out what it writes, so assume the worst.
    for (int r = 0; r < kNumGPRs; r++) {
      state->ClobberReg(r);
    }
    state->slots.clear();
    return;
  }
  for (uint8_t i = 0; i < write_count; i++) {
    int d = DWARFRegOf(written[i]);
    if (d >= 0) {
      state->ClobberReg(d);
    }
  }
  // Belt and braces: also take the written operands directly, in case
  // the access tables miss something.
  const cs_x86& x = X86(insn);
  for (uint8_t i = 0; i < x.op_count; i++) {
    const cs_x86_op& op = x.operands[i];
    if ((op.access & CS_AC_WRITE) == 0) {
      continue;
    }
    if (op.type == X86_OP_REG) {
      int d = DWARFRegOf(op.reg);
      if (d >= 0) {
        state->ClobberReg(d);
      }
    } else if (op.type == X86_OP_MEM) {
      std::optional<int64_t> slot = MemSlot(*state, op.mem);
      if (slot.has_value()) {
        EraseSlots(state, *slot, op.size);
      } else {
        HandleUnplacedMemWrite(state);
      }
    }
  }
}

TransferOutcome InsnSemantics::Transfer(const cs_insn& insn, AbsState* state) const {
  TransferOutcome out;
  const cs_x86& x = X86(insn);

  // Any instruction that writes EFLAGS invalidates whatever `cmp` guard
  // was last seen (initial-switch-tables-plan.md §3.2), except a fresh
  // matching `cmp` itself, which sets state->last_cmp again below,
  // overwriting this clear. Doing this unconditionally, once, up front
  // means no case below -- or the unmodelled-instruction fallback -- has
  // to remember to do it by hand.
  if (WritesEflags(handle_, insn)) {
    state->last_cmp = std::nullopt;
  }

  // Control flow first: the classification is independent of what the
  // instruction does to the stack.
  if (cs_insn_group(handle_, &insn, X86_GRP_RET) || insn.id == X86_INS_IRET || insn.id == X86_INS_IRETD ||
      insn.id == X86_INS_IRETQ) {
    out.is_return = true;
    out.falls_through = false;
    return out;
  }
  if (cs_insn_group(handle_, &insn, X86_GRP_JUMP)) {
    bool conditional = insn.id != X86_INS_JMP && insn.id != X86_INS_LJMP;
    out.falls_through = conditional;
    if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
      out.has_direct_target = true;
      out.direct_target = static_cast<uint64_t>(x.operands[0].imm);
      return out;
    }
    if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
      int r = DWARFRegOf(x.operands[0].reg);
      const AbsVal v = r >= 0 ? state->reg(r) : AbsVal::Top();
      VLOG(1) << absl::StrFormat("0x%llx: indirect jmp via reg %d, value=%s", (unsigned long long)insn.address, r,
                                 v.ToString());
      if (v.IsJumpTarget()) {
        // The bound was captured once at movslq-time and carried through
        // the `add` into this kJumpTarget -- not re-derived with a live
        // AbsState::Bound lookup here, which would be vulnerable to an
        // intervening instruction reusing the same register number for an
        // unrelated guard (switch-table-amend-plan.md §2).
        std::optional<uint64_t> bound = v.Bound();
        VLOG(1) << absl::StrFormat(
            "0x%llx:   jump target table=0x%llx index_reg=%d captured_bound=%s", (unsigned long long)insn.address,
            (unsigned long long)v.TableAddr(), v.IndexReg(),
            bound.has_value() ? absl::StrFormat("%llu", (unsigned long long)*bound) : std::string("<none>"));
        if (bound.has_value()) {
          out.has_jump_table = true;
          out.jump_table_addr = v.TableAddr();
          out.jump_table_entries = *bound + 1;
          return out;
        }
      }
    }
    VLOG(1) << absl::StrFormat("0x%llx: indirect jmp not resolved to a switch table", (unsigned long long)insn.address);
    out.indirect_branch = true;
    return out;
  }
  if (insn.id == X86_INS_UD0 || insn.id == X86_INS_UD1 || insn.id == X86_INS_UD2 || insn.id == X86_INS_HLT ||
      insn.id == X86_INS_INT3) {
    out.falls_through = false;
    return out;
  }

  switch (insn.id) {
    case X86_INS_CALL:
    case X86_INS_LCALL: {
      out.is_call = true;
      // The call pushes and the matching ret pops, so rsp is unchanged
      // across it -- but everything below rsp is the callee's now, and
      // the red zone does not survive a call.
      const AbsVal& rsp = state->reg(kDWARFRsp);
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        state->DropSlotsBelow(rsp.delta);
      }
      // When rsp is untracked -- after a stack realignment or an alloca
      // -- we cannot locate the red zone, so there is nothing to drop.
      // We keep the slots rather than clearing them: everything we track
      // is CFA-relative, which is the *caller's* frame, and a callee
      // that scribbled on that would be broken in a way no unwind table
      // could describe. Clearing here instead would make every realigned
      // function report that it cannot say where its own saved
      // registers went.
      for (int r : kCallerSaved) {
        state->ClobberReg(r);
      }
      return out;
    }

    case X86_INS_PUSH:
    case X86_INS_PUSHFQ: {
      if (insn.id == X86_INS_PUSH && (x.op_count != 1 || x.operands[0].size != 8)) {
        out.review_reason = "push with an operand size other than 8 bytes";
        state->ClobberReg(kDWARFRsp);
        return out;
      }
      AbsVal pushed = AbsVal::Top();
      if (insn.id == X86_INS_PUSH) {
        const cs_x86_op& op = x.operands[0];
        if (op.type == X86_OP_REG) {
          pushed = ReadReg(*state, op.reg);
        } else if (op.type == X86_OP_MEM) {
          std::optional<int64_t> slot = MemSlot(*state, op.mem);
          pushed = slot.has_value() ? state->Slot(*slot) : AbsVal::Top();
        }
      }
      const AbsVal rsp = state->reg(kDWARFRsp);
      if (rsp.kind != AbsVal::Kind::kCFARel) {
        return out;  // rsp already untracked; nothing to say
      }
      int64_t at = rsp.delta - 8;
      state->SetReg(kDWARFRsp, AbsVal::CFARel(at));
      state->SetSlot(at, pushed);
      return out;
    }

    case X86_INS_POP:
    case X86_INS_POPFQ: {
      if (insn.id == X86_INS_POP && (x.op_count != 1 || x.operands[0].size != 8)) {
        out.review_reason = "pop with an operand size other than 8 bytes";
        state->ClobberReg(kDWARFRsp);
        return out;
      }
      const AbsVal rsp = state->reg(kDWARFRsp);
      AbsVal popped = AbsVal::Top();
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        popped = state->Slot(rsp.delta);
        state->SetReg(kDWARFRsp, AbsVal::CFARel(rsp.delta + 8));
        state->DropDeadSlots(rsp.delta + 8);
      }
      if (insn.id == X86_INS_POP) {
        const cs_x86_op& op = x.operands[0];
        if (op.type == X86_OP_REG) {
          int d = DWARFRegOf(op.reg);
          if (d >= 0) {
            state->SetReg(d, IsFull64(op.reg) ? popped : AbsVal::Top());
          }
        } else if (op.type == X86_OP_MEM) {
          std::optional<int64_t> slot = MemSlot(*state, op.mem);
          if (slot.has_value()) {
            state->SetSlot(*slot, popped);
          }
        }
      }
      return out;
    }

    case X86_INS_LEAVE: {
      // leave == mov %rbp,%rsp ; pop %rbp
      state->SetReg(kDWARFRsp, state->reg(kDWARFRbp));
      const AbsVal rsp = state->reg(kDWARFRsp);
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        state->SetReg(kDWARFRbp, state->Slot(rsp.delta));
        state->SetReg(kDWARFRsp, AbsVal::CFARel(rsp.delta + 8));
        state->DropDeadSlots(rsp.delta + 8);
      } else {
        state->ClobberReg(kDWARFRbp);
      }
      return out;
    }

    case X86_INS_LEA: {
      if (x.op_count != 2 || x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_MEM) {
        break;
      }
      int d = DWARFRegOf(x.operands[0].reg);
      if (d < 0) {
        break;
      }
      if (!IsFull64(x.operands[0].reg)) {
        state->ClobberReg(d);
        return out;
      }
      const x86_op_mem& mem = x.operands[1].mem;
      // `lea disp(%rip),%B` -- the switch-table base load. Capstone's
      // `disp` is the raw encoded displacement; the effective address is
      // relative to the end of this instruction, not its start.
      if (mem.base == X86_REG_RIP && mem.index == X86_REG_INVALID) {
        uint64_t target = insn.address + insn.size + static_cast<int64_t>(mem.disp);
        VLOG(1) << absl::StrFormat("0x%llx: lea rip-relative -> reg %d = kConst(0x%llx)",
                                   (unsigned long long)insn.address, d, (unsigned long long)target);
        state->SetReg(d, AbsVal::Const(static_cast<int64_t>(target)));
        return out;
      }
      state->SetReg(d, LeaValue(*state, mem));
      return out;
    }

    case X86_INS_MOV:
    case X86_INS_MOVQ:
    case X86_INS_MOVABS: {
      if (x.op_count != 2) {
        break;
      }
      const cs_x86_op& dst = x.operands[0];
      const cs_x86_op& src = x.operands[1];
      if (dst.type == X86_OP_REG) {
        int d = DWARFRegOf(dst.reg);
        if (d < 0) {
          break;
        }
        if (!IsFull64(dst.reg)) {
          // A narrower mov's identity does not survive -- see the 8/16-bit
          // case below for why this stays a clobber rather than a value
          // copy -- but same-width-or-widening register-to-register moves
          // (`mov %esi,%eax` and friends: a 32-bit destination write still
          // zero-extends to the full 64-bit register on x86-64, the same
          // as movzx) carry a numeric bound across exactly the way movzx
          // does, and for the same reason: GCC frequently widens the
          // guard register into whatever register the table load actually
          // reads (switch-table-amend-plan.md §1).
          std::optional<uint64_t> carried;
          if (src.type == X86_OP_REG) {
            int s = DWARFRegOf(src.reg);
            // Deliberately not gated on IsFull64(src.reg): the bound
            // lives on the DWARF-level register regardless of which
            // sub-register spelling read it (`mov %esi,%eax` reads the
            // same rsi-level bound `mov %rsi,%rax` would), unlike a
            // value read, which ReadReg rightly refuses to give for a
            // sub-register.
            carried = s >= 0 ? state->reg(s).Bound() : std::nullopt;
          }
          state->ClobberReg(d);
          if (carried.has_value()) {
            state->SetBound(d, *carried);
          }
          return out;
        }
        if (src.type == X86_OP_REG) {
          state->SetReg(d, ReadReg(*state, src.reg));
        } else if (src.type == X86_OP_MEM) {
          std::optional<int64_t> slot = MemSlot(*state, src.mem);
          state->SetReg(d, (slot.has_value() && src.size == 8) ? state->Slot(*slot) : AbsVal::Top());
        } else {
          // `mov $imm,%r` is deliberately left untracked rather than
          // turned into a kConst: nothing in the switch-table pattern
          // needs it (the table base always comes from a rip-relative
          // lea), and check_unmentioned_callee_saved fixtures rely on an
          // immediate load clobbering a register to unknown.
          state->ClobberReg(d);
        }
        return out;
      }
      if (dst.type == X86_OP_MEM) {
        std::optional<int64_t> slot = MemSlot(*state, dst.mem);
        if (!slot.has_value()) {
          HandleUnplacedMemWrite(state);
          return out;
        }
        if (dst.size != 8) {
          EraseSlots(state, *slot, dst.size);
          return out;
        }
        state->SetSlot(*slot, src.type == X86_OP_REG ? ReadReg(*state, src.reg) : AbsVal::Top());
        return out;
      }
      break;
    }

    case X86_INS_MOVSXD: {
      // `movslq disp(%B,%I,4),%T` -- the switch-table load: T becomes the
      // table entry once %B is a known constant and the scale is 4 (an
      // int32 table). Anything else falls through to the generic clobber
      // below, same as any other unmodelled case.
      if (x.op_count != 2 || x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_MEM) {
        break;
      }
      int d = DWARFRegOf(x.operands[0].reg);
      if (d < 0 || !IsFull64(x.operands[0].reg)) {
        break;
      }
      const x86_op_mem& mem = x.operands[1].mem;
      if (mem.index == X86_REG_INVALID || mem.scale != 4 || mem.base == X86_REG_INVALID) {
        break;
      }
      int idx_reg = DWARFRegOf(mem.index);
      int base_reg = DWARFRegOf(mem.base);
      if (idx_reg < 0 || base_reg < 0 || !IsFull64(mem.base)) {
        break;
      }
      const AbsVal& base_val = state->reg(base_reg);
      if (!base_val.IsConst()) {
        VLOG(1) << absl::StrFormat(
            "0x%llx: movslq disp(%%B,%%I,4),%%T base reg %d is not a known constant (value=%s) -- not a table load",
            (unsigned long long)insn.address, base_reg, base_val.ToString());
        break;
      }
      uint64_t table = static_cast<uint64_t>(base_val.ConstValue()) + mem.disp;
      // Snapshot the index register's bound now, while its job is still
      // fresh, rather than re-deriving it with a live lookup at the
      // eventual `jmp` (switch-table-amend-plan.md §2) -- an intervening
      // instruction reusing the same register number for an unrelated
      // guard would otherwise be able to hand the resolver the wrong
      // bound.
      std::optional<uint64_t> bound = state->Bound(idx_reg);
      VLOG(1) << absl::StrFormat(
          "0x%llx: movslq -> reg %d = kTableEntry(table=0x%llx, index_reg=%d, captured_bound=%s)",
          (unsigned long long)insn.address, d, (unsigned long long)table, idx_reg,
          bound.has_value() ? absl::StrFormat("%llu", (unsigned long long)*bound) : std::string("<none>"));
      state->SetReg(d, AbsVal::TableEntry(table, static_cast<uint8_t>(idx_reg),
                                          static_cast<uint64_t>(base_val.ConstValue()), bound));
      return out;
    }

    case X86_INS_ADD:
    case X86_INS_SUB: {
      // `add %B,%T` (either operand order) where %B is the same known
      // constant %T's table was derived from -- the switch-table
      // dispatch address. Capstone's operands[0] is always the
      // destination for a 2-operand ADD/SUB, regardless of which
      // register held the constant and which held the table entry.
      if (insn.id == X86_INS_ADD && x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
          x.operands[1].type == X86_OP_REG) {
        int d0 = DWARFRegOf(x.operands[0].reg);
        int d1 = DWARFRegOf(x.operands[1].reg);
        if (d0 >= 0 && d1 >= 0 && IsFull64(x.operands[0].reg) && IsFull64(x.operands[1].reg)) {
          const AbsVal op0 = state->reg(d0);
          const AbsVal op1 = state->reg(d1);
          auto resolve = [](const AbsVal& base_candidate, const AbsVal& entry_candidate) -> std::optional<AbsVal> {
            if (base_candidate.IsConst() && entry_candidate.IsTableEntry() &&
                entry_candidate.TableBaseConst() == static_cast<uint64_t>(base_candidate.ConstValue())) {
              return AbsVal::JumpTarget(entry_candidate.TableAddr(), static_cast<uint8_t>(entry_candidate.IndexReg()),
                                        entry_candidate.Bound());
            }
            return std::nullopt;
          };
          std::optional<AbsVal> resolved = resolve(op0, op1);
          if (!resolved.has_value()) {
            resolved = resolve(op1, op0);
          }
          if (resolved.has_value()) {
            VLOG(1) << absl::StrFormat("0x%llx: %s -> reg %d = kJumpTarget(%s)", (unsigned long long)insn.address,
                                       insn.id == X86_INS_ADD ? "add" : "sub", d0, resolved->ToString());
            state->SetReg(d0, *resolved);
            return out;
          }
        }
      }
      if (x.op_count != 2 || x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_IMM) {
        break;
      }
      int d = DWARFRegOf(x.operands[0].reg);
      if (d < 0) {
        break;
      }
      const AbsVal cur = state->reg(d);
      if (!IsFull64(x.operands[0].reg) || cur.kind != AbsVal::Kind::kCFARel) {
        state->ClobberReg(d);
        return out;
      }
      int64_t imm = x.operands[1].imm;
      int64_t delta = insn.id == X86_INS_ADD ? cur.delta + imm : cur.delta - imm;
      state->SetReg(d, AbsVal::CFARel(delta));
      if (d == kDWARFRsp && delta > cur.delta) {
        state->DropDeadSlots(delta);
      }
      return out;
    }

    case X86_INS_CMP: {
      // `cmp $non_negative_imm,%reg` -- the switch-table guard
      // (initial-switch-tables-plan.md §3.2). cmp writes no register or
      // memory, only EFLAGS, which the unconditional check at the top of
      // this function already cleared; a matching cmp sets it again here.
      // Anything else (cmp of two registers, a negative immediate, a
      // memory operand) simply leaves it cleared -- not a guard this
      // analysis resolves.
      if (x.op_count == 2 && x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM &&
          x.operands[1].imm >= 0) {
        int r = DWARFRegOf(x.operands[0].reg);
        if (r >= 0) {
          state->last_cmp = AbsState::FlagsGuard{r, static_cast<uint64_t>(x.operands[1].imm)};
        }
      }
      return out;
    }

    case X86_INS_MOVZX: {
      // `movzbl %r8b,%ecx` and friends: the destination's own identity
      // does not survive the truncation in general, but a numeric bound
      // established on the source does -- GCC routinely widens the guard
      // register into whatever register the table load actually reads
      // (switch-table-amend-plan.md §1), so carrying just the bound
      // across, rather than the whole value, is what lets the guard and
      // the table load disagree on register without losing the guard.
      if (x.op_count == 2 && x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_REG) {
        int d = DWARFRegOf(x.operands[0].reg);
        int s = DWARFRegOf(x.operands[1].reg);
        if (d >= 0) {
          std::optional<uint64_t> carried = s >= 0 ? state->reg(s).Bound() : std::nullopt;
          state->ClobberReg(d);
          if (carried.has_value()) {
            state->SetBound(d, *carried);
          }
          return out;
        }
      }
      break;  // no reg destination we can name -- fall through to the generic clobber
    }

    case X86_INS_NOP:
    case X86_INS_ENDBR32:
    case X86_INS_ENDBR64:
      return out;

    default:
      break;
  }

  // The long tail. `and $-16,%rsp` lands here too and simply makes rsp
  // untracked, which is the graceful thing: an rbp-based CFA rule stays
  // checkable, an rsp-based one turns into a review note instead of a
  // guess.
  ClobberWrites(insn, state);
  return out;
}

}  // namespace unwind_analysis

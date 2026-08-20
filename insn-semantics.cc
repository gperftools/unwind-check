/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "insn-semantics.h"

#include <memory>
#include <optional>

#include "absl/container/flat_hash_map.h"

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
  return state.reg(InsnSemantics::DwarfRegOf(reg));
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
  const AbsVal& base = state.reg(InsnSemantics::DwarfRegOf(mem.base));
  if (base.kind != AbsVal::Kind::kCfaRel) {
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
  return AbsVal::CfaRel(*slot);
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

}  // namespace

int InsnSemantics::DwarfRegOf(unsigned reg) {
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
    for (int r = 0; r < kNumGpRegs; r++) {
      state->ClobberReg(r);
    }
    state->slots.clear();
    return;
  }
  for (uint8_t i = 0; i < write_count; i++) {
    int d = DwarfRegOf(written[i]);
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
      int d = DwarfRegOf(op.reg);
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
    } else {
      out.indirect_branch = true;
    }
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
      const AbsVal& rsp = state->reg(kDwarfRsp);
      if (rsp.kind == AbsVal::Kind::kCfaRel) {
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
        state->ClobberReg(kDwarfRsp);
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
      const AbsVal rsp = state->reg(kDwarfRsp);
      if (rsp.kind != AbsVal::Kind::kCfaRel) {
        return out;  // rsp already untracked; nothing to say
      }
      int64_t at = rsp.delta - 8;
      state->SetReg(kDwarfRsp, AbsVal::CfaRel(at));
      state->SetSlot(at, pushed);
      return out;
    }

    case X86_INS_POP:
    case X86_INS_POPFQ: {
      if (insn.id == X86_INS_POP && (x.op_count != 1 || x.operands[0].size != 8)) {
        out.review_reason = "pop with an operand size other than 8 bytes";
        state->ClobberReg(kDwarfRsp);
        return out;
      }
      const AbsVal rsp = state->reg(kDwarfRsp);
      AbsVal popped = AbsVal::Top();
      if (rsp.kind == AbsVal::Kind::kCfaRel) {
        popped = state->Slot(rsp.delta);
        state->SetReg(kDwarfRsp, AbsVal::CfaRel(rsp.delta + 8));
        state->DropDeadSlots(rsp.delta + 8);
      }
      if (insn.id == X86_INS_POP) {
        const cs_x86_op& op = x.operands[0];
        if (op.type == X86_OP_REG) {
          int d = DwarfRegOf(op.reg);
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
      state->SetReg(kDwarfRsp, state->reg(kDwarfRbp));
      const AbsVal rsp = state->reg(kDwarfRsp);
      if (rsp.kind == AbsVal::Kind::kCfaRel) {
        state->SetReg(kDwarfRbp, state->Slot(rsp.delta));
        state->SetReg(kDwarfRsp, AbsVal::CfaRel(rsp.delta + 8));
        state->DropDeadSlots(rsp.delta + 8);
      } else {
        state->ClobberReg(kDwarfRbp);
      }
      return out;
    }

    case X86_INS_LEA: {
      if (x.op_count != 2 || x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_MEM) {
        break;
      }
      int d = DwarfRegOf(x.operands[0].reg);
      if (d < 0) {
        break;
      }
      state->SetReg(d, IsFull64(x.operands[0].reg) ? LeaValue(*state, x.operands[1].mem) : AbsVal::Top());
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
        int d = DwarfRegOf(dst.reg);
        if (d < 0) {
          break;
        }
        if (!IsFull64(dst.reg)) {
          state->ClobberReg(d);
          return out;
        }
        if (src.type == X86_OP_REG) {
          state->SetReg(d, ReadReg(*state, src.reg));
        } else if (src.type == X86_OP_MEM) {
          std::optional<int64_t> slot = MemSlot(*state, src.mem);
          state->SetReg(d, (slot.has_value() && src.size == 8) ? state->Slot(*slot) : AbsVal::Top());
        } else {
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

    case X86_INS_ADD:
    case X86_INS_SUB: {
      if (x.op_count != 2 || x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_IMM) {
        break;
      }
      int d = DwarfRegOf(x.operands[0].reg);
      if (d < 0) {
        break;
      }
      const AbsVal cur = state->reg(d);
      if (!IsFull64(x.operands[0].reg) || cur.kind != AbsVal::Kind::kCfaRel) {
        state->ClobberReg(d);
        return out;
      }
      int64_t imm = x.operands[1].imm;
      int64_t delta = insn.id == X86_INS_ADD ? cur.delta + imm : cur.delta - imm;
      state->SetReg(d, AbsVal::CfaRel(delta));
      if (d == kDwarfRsp && delta > cur.delta) {
        state->DropDeadSlots(delta);
      }
      return out;
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

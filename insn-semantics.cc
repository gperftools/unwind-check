/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "insn-semantics.h"

#include <algorithm>
#include <optional>

#include "absl/log/log.h"
#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

// DWARF numbering for x86-64 is the psABI's, not the encoding order: rax
// rdx rcx rbx rsi rdi rbp rsp, then r8..r15.
constexpr ZydisRegister kDwarfGprs[kNumGPRs] = {
    ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RBX,
    ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSP,
    ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
    ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
};

// Registers a call may destroy, per the x86-64 psABI.
constexpr int kCallerSaved[] = {0, 1, 2, 4, 5, 8, 9, 10, 11};

// The value a register operand reads, as far as we track it.
AbsVal ReadReg(const AbsState& state, ZydisRegister reg) {
  if (!InsnSemantics::IsFull64(reg)) {
    return AbsVal::Top();
  }
  return state.reg(InsnSemantics::DWARFRegOf(reg));
}

// The CFA-relative offset a memory operand addresses, when we can name
// it. Anything with an index register, an explicit segment override or a
// base we are not tracking is simply not a stack slot as far as we are
// concerned.
std::optional<int64_t> MemSlot(const AbsState& state, const Instruction& insn, const ZydisDecodedOperandMem& mem) {
  // Zydis always fills in the *implicit* default segment (SS for an
  // rbp/rsp-based operand, DS otherwise) even when no override prefix is
  // present in the encoding -- unlike Capstone, which leaves `segment`
  // invalid unless a prefix byte actually appears. Reading mem.segment
  // directly here would make every ordinary `-0x8(%rbp)` stack access
  // look segment-relative and never resolve to a slot, so "explicit
  // override present" has to come from the instruction's attributes
  // instead.
  if ((insn.insn.attributes & ZYDIS_ATTRIB_HAS_SEGMENT) != 0 || mem.index != ZYDIS_REGISTER_NONE) {
    return std::nullopt;
  }
  if (!InsnSemantics::IsFull64(mem.base)) {
    return std::nullopt;
  }
  const AbsVal& base = state.reg(InsnSemantics::DWARFRegOf(mem.base));
  if (base.kind != AbsVal::Kind::kCFARel) {
    return std::nullopt;
  }
  return base.delta + mem.disp.value;
}

// The address a `lea` computes, as a value.
AbsVal LeaValue(const AbsState& state, const Instruction& insn, const ZydisDecodedOperandMem& mem) {
  std::optional<int64_t> slot = MemSlot(state, insn, mem);
  if (!slot.has_value()) {
    return AbsVal::Top();
  }
  return AbsVal::CFARel(*slot);
}

void EraseSlots(AbsState* state, int64_t start, int64_t size) {
  if (size <= 0) {
    return;
  }
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

// True when this instruction's accessed-flags info says it modifies
// EFLAGS. `tested` (a read) does not count -- only modified/set_0/set_1/
// undefined do, matching what "this instruction writes EFLAGS" means for
// AbsState::last_cmp.
bool WritesEflags(const Instruction& insn) {
  const ZydisAccessedFlags* flags = insn.insn.cpu_flags;
  if (flags == nullptr) {
    return true;  // unknown effect -- assume the worst, same as ClobberWrites does
  }
  return flags->modified != 0 || flags->set_0 != 0 || flags->set_1 != 0 || flags->undefined != 0;
}

struct RegInfoTable {
  int8_t dwarf_reg[ZYDIS_REGISTER_MAX_VALUE + 1];
  bool is_full_64[ZYDIS_REGISTER_MAX_VALUE + 1];
  // Width of this register spelling in bits, 0 for anything that is not
  // one of the 16 GPRs. Needed because a write's *width* is itself a fact
  // about the value: see WrittenRegBound.
  uint8_t width_bits[ZYDIS_REGISTER_MAX_VALUE + 1];

  RegInfoTable() {
    for (int r = 0; r <= ZYDIS_REGISTER_MAX_VALUE; ++r) {
      dwarf_reg[r] = -1;
      is_full_64[r] = false;
      width_bits[r] = 0;
      auto zreg = static_cast<ZydisRegister>(r);
      ZydisRegister parent = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, zreg);
      for (int i = 0; i < kNumGPRs; ++i) {
        if (kDwarfGprs[i] == parent) {
          dwarf_reg[r] = static_cast<int8_t>(i);
          width_bits[r] = static_cast<uint8_t>(ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, zreg));
          if (parent == zreg) {
            is_full_64[r] = true;
          }
          break;
        }
      }
    }
  }
};

const RegInfoTable& GetRegInfoTable() {
  static const RegInfoTable table;
  return table;
}

// Width in bits of a GPR spelling (%al -> 8, %eax -> 32, %rax -> 64), or 0
// if it is not one of the 16 GPRs.
unsigned RegWidthBits(ZydisRegister reg) {
  if (reg < 0 || reg > ZYDIS_REGISTER_MAX_VALUE) {
    return 0;
  }
  return GetRegInfoTable().width_bits[reg];
}

// What merely *writing* this register spelling proves about the resulting
// full 64-bit register, before looking at what was written.
//
// On x86-64 every write to a 32-bit GPR destination zero-extends into the
// upper half, so `add %ecx,%eax` -- whatever it computed -- leaves rax at
// most 0xffffffff. That fact is small but load-bearing: it is what later
// lets `cmp $imm,%eax; ja` say anything about *rax*, which is the register
// a table load actually indexes with. A 64-bit destination proves nothing
// (kBoundTop), and an 8- or 16-bit destination proves nothing either,
// because those writes leave the upper bits of the register alone.
uint64_t WrittenRegBound(ZydisRegister reg) {
  return RegWidthBits(reg) == 32 ? WidthBound(32) : kBoundTop;
}

// Clobbers the register `reg` names, keeping whatever its width alone
// proves. Every explicitly-modelled case that gives up on a destination
// should go through this rather than bare ClobberReg, so the
// zero-extension fact survives being unable to model the value.
void ClobberWrittenReg(AbsState* state, ZydisRegister reg, int dwarf_reg) {
  state->ClobberReg(dwarf_reg);
  state->gpr[dwarf_reg].value_bound = WrittenRegBound(reg);
}

// What a *proven* guard contributes to a zero-extending read of the low
// `read_bits` bits of register `reg`.
//
// A proven guard says the low `width_bits` bits of its register are at most
// `imm` -- a width-qualified fact, useless on its own to a table load that
// indexes with all 64 bits. A widen is what cashes it in: reading those
// bits and zero-extending them makes the destination equal to the bounded
// quantity, so the qualification disappears and the result is a bound on
// the whole destination register. That only works while the read stays
// inside what the guard covered, hence the `read_bits <= width_bits` test:
// reading 32 bits of a register guarded only in its low 8 reaches 24 bits
// the guard never spoke about.
//
// Unproven guards contribute nothing. A comparison that has not yet had a
// branch pick a side establishes no fact, and treating one as though it had
// is what made an earlier version of this invent bounds on the default edge
// of a switch -- or with no branch at all.
uint64_t ProvenGuardBound(const AbsState& state, int reg, unsigned read_bits) {
  if (reg < 0 || !state.last_cmp.has_value() || !state.last_cmp->proven()) {
    return kBoundTop;
  }
  if (state.last_cmp->reg != reg || read_bits > state.last_cmp->width_bits) {
    return kBoundTop;
  }
  return std::min(WidthBound(read_bits), state.last_cmp->proven_bound);
}

// The bounds of `src` after a zero-extending widen that keeps its low
// `src_bits` bits -- `movzbl %al,%ecx`, or the narrow `mov %esi,%eax` that
// x86-64 zero-extends for free. Truncation can only tighten an upper bound
// (if src <= B < 2^w then src mod 2^w == src <= B; otherwise it is capped
// by 2^w - 1), so both bounds survive and the width itself contributes a
// new value bound.
//
// `table_bound` is carried across unchanged rather than tightened to the
// width: tightening it would manufacture a compiler-declared bound out of
// an instruction width, which is exactly what table_bound exists not to be.
void ApplyZeroExtendedFrom(AbsVal* dst, const AbsVal& src, unsigned src_bits, uint64_t guard_bound) {
  dst->value_bound = std::min({WidthBound(src_bits), src.value_bound, guard_bound});
  // A guard is compiler-declared, so unlike the width term above it may
  // size a table -- that is the whole point of collecting it here.
  dst->table_bound = std::min(src.table_bound, guard_bound);
}

// The same for a sign-extending widen (`movsbl`, `movslq`). Sound only
// when the source's low `src_bits` bits are known to have a clear sign
// bit, since otherwise the result is a huge unsigned number rather than a
// small one -- and `value_bound` is precisely the fact that proves it.
// When it cannot be proven, nothing survives.
void ApplySignExtendedFrom(AbsVal* dst, const AbsVal& src, unsigned src_bits, uint64_t guard_bound) {
  const uint64_t low = std::min({WidthBound(src_bits), src.value_bound, guard_bound});
  if (src_bits >= 64 || low >= (uint64_t{1} << (src_bits - 1))) {
    dst->ClearBounds();
    return;
  }
  dst->value_bound = low;
  dst->table_bound = std::min(src.table_bound, guard_bound);
}

}  // namespace

int InsnSemantics::DWARFRegOf(ZydisRegister reg) {
  if (reg < 0 || reg > ZYDIS_REGISTER_MAX_VALUE) {
    return -1;
  }
  return GetRegInfoTable().dwarf_reg[reg];
}

bool InsnSemantics::IsFull64(ZydisRegister reg) {
  if (reg < 0 || reg > ZYDIS_REGISTER_MAX_VALUE) {
    return false;
  }
  return GetRegInfoTable().is_full_64[reg];
}

void InsnSemantics::ClobberWrites(const Instruction& insn, AbsState* state) const {
  // Unlike Capstone -- which needed a separate register-access-table call
  // plus a "belt and braces" explicit-operand loop, because its operand
  // list only ever carried the explicit operands -- Zydis's operand array
  // already includes every implicit and hidden register/memory access
  // (e.g. an implicit stack write) with its own read/write actions. One
  // pass over the full operand list (not just the visible ones) is the
  // whole story.
  for (uint8_t i = 0; i < insn.insn.operand_count; i++) {
    const ZydisDecodedOperand& op = insn.operands[i];
    if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) == 0) {
      continue;
    }
    if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
      int d = DWARFRegOf(op.reg.value);
      if (d >= 0) {
        // Not a bare ClobberReg: an unmodelled instruction still tells us
        // how wide its destination was, and on x86-64 that alone bounds
        // the register. See WrittenRegBound.
        ClobberWrittenReg(state, op.reg.value, d);
      }
    } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
      std::optional<int64_t> slot = MemSlot(*state, insn, op.mem);
      if (slot.has_value()) {
        EraseSlots(state, *slot, std::max<int64_t>(1, op.size / 8));
      } else {
        HandleUnplacedMemWrite(state);
      }
    }
  }
}

TransferOutcome InsnSemantics::Transfer(const Instruction& insn, AbsState* state) const {
  TransferOutcome out;

  // Any instruction that writes EFLAGS invalidates whatever `cmp` guard
  // was last seen, except a fresh matching `cmp` itself, which sets
  // state->last_cmp again below, overwriting this clear. Doing this
  // unconditionally, once, up front means no case below -- or the
  // unmodelled-instruction fallback -- has to remember to do it by hand.
  //
  // A *proven* guard is exempt: once a branch has selected the in-range
  // edge, "the low 32 bits of rsi are at most 14" is a fact about rsi, and
  // no amount of later arithmetic on unrelated registers makes it untrue.
  // Only writing rsi does, which SetReg/ClobberReg handle. Without this
  // exemption any flag-writing instruction between the guard branch and
  // the widen that collects it would throw the guard away.
  if (WritesEflags(insn) && (!state->last_cmp.has_value() || !state->last_cmp->proven())) {
    state->last_cmp = std::nullopt;
  }

  // Control flow first: the classification is independent of what the
  // instruction does to the stack.
  if (insn.id == ZYDIS_MNEMONIC_RET || insn.id == ZYDIS_MNEMONIC_IRET || insn.id == ZYDIS_MNEMONIC_IRETD ||
      insn.id == ZYDIS_MNEMONIC_IRETQ) {
    out.is_return = true;
    out.falls_through = false;
    return out;
  }
  const ZydisInstructionCategory category = insn.insn.meta.category;
  if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
    bool conditional = insn.id != ZYDIS_MNEMONIC_JMP;
    out.falls_through = conditional;
    if (insn.op_count >= 1 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
      uint64_t target = 0;
      if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn.insn, &insn.operands[0], insn.address, &target))) {
        out.has_direct_target = true;
        out.direct_target = target;
        return out;
      }
    }
    if (insn.op_count >= 1 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
      int r = DWARFRegOf(insn.operands[0].reg.value);
      const AbsVal v = r >= 0 ? state->reg(r) : AbsVal::Top();
      VLOG(1) << absl::StrFormat("0x%x: indirect jmp via reg %d, value=%v", insn.address, r, v);
      if (v.IsJumpTarget()) {
        // The index's bound was captured once at movslq-time and carried
        // through the `add` into this kJumpTarget -- not re-derived with a
        // live lookup here, which would be vulnerable to an intervening
        // instruction reusing the same register number for an unrelated
        // guard. Only a table_bound will do: a value_bound is a width fact
        // (`movzbl` proves an index is at most 255) and sizing a table from
        // one would read whatever .rodata follows the real table. See
        // AbsVal's comment.
        VLOG(1) << absl::StrFormat("0x%x:   jump target table=0x%x index_reg=%d captured_bound=%s", insn.address,
                                   v.TableAddr(), v.IndexReg(),
                                   v.HasTableBound() ? absl::StrFormat("%u", v.table_bound) : std::string("<none>"));
        if (v.HasTableBound()) {
          out.has_jump_table = true;
          out.jump_table_addr = v.TableAddr();
          out.jump_table_entries = v.table_bound + 1;
          return out;
        }
        out.has_unbounded_jump_target = true;
        out.unbounded_jump_table_addr = v.TableAddr();
      }
    }
    VLOG(1) << absl::StrFormat("0x%x: indirect jmp not resolved to a switch table", insn.address);
    out.indirect_branch = true;
    return out;
  }
  if (insn.id == ZYDIS_MNEMONIC_UD0 || insn.id == ZYDIS_MNEMONIC_UD1 || insn.id == ZYDIS_MNEMONIC_UD2 ||
      insn.id == ZYDIS_MNEMONIC_HLT || insn.id == ZYDIS_MNEMONIC_INT3) {
    out.falls_through = false;
    return out;
  }

  switch (insn.id) {
    case ZYDIS_MNEMONIC_CALL: {
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

    case ZYDIS_MNEMONIC_SYSCALL:
    case ZYDIS_MNEMONIC_SYSENTER:
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT1:
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_INTO:
    case ZYDIS_MNEMONIC_VMCALL:
    case ZYDIS_MNEMONIC_VMMCALL: {
      const AbsVal& rsp = state->reg(kDWARFRsp);
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        state->DropSlotsBelow(rsp.delta);
      }
      for (int r : kCallerSaved) {
        state->ClobberReg(r);
      }
      return out;
    }

    case ZYDIS_MNEMONIC_PUSH:
    case ZYDIS_MNEMONIC_PUSHFQ: {
      // insn.operands[0].size is not the right thing to gate on here: for
      // an immediate operand it is the *encoded* immediate width (`push
      // $0x1` reports 8, imm8's own size, even though the push itself is
      // the normal 8-byte one) rather than the push's actual stack
      // effect. insn.insn.operand_width is the effective operand width
      // regardless of operand kind, and is 16 only for the genuine
      // oddity this check exists to catch (a 66h-prefixed `pushw`, which
      // moves rsp by 2, not 8).
      if (insn.id == ZYDIS_MNEMONIC_PUSH && (insn.op_count != 1 || insn.insn.operand_width != 64)) {
        out.review_reason = "push with an operand size other than 8 bytes";
        state->ClobberReg(kDWARFRsp);
        return out;
      }
      AbsVal pushed = AbsVal::Top();
      if (insn.id == ZYDIS_MNEMONIC_PUSH) {
        const ZydisDecodedOperand& op = insn.operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
          pushed = ReadReg(*state, op.reg.value);
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
          std::optional<int64_t> slot = MemSlot(*state, insn, op.mem);
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

    case ZYDIS_MNEMONIC_POP:
    case ZYDIS_MNEMONIC_POPFQ: {
      if (insn.id == ZYDIS_MNEMONIC_POP && (insn.op_count != 1 || insn.insn.operand_width != 64)) {
        out.review_reason = "pop with an operand size other than 8 bytes";
        state->ClobberReg(kDWARFRsp);
        return out;
      }
      const AbsVal rsp = state->reg(kDWARFRsp);
      AbsVal popped = AbsVal::Top();
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        popped = state->Slot(rsp.delta);
        state->SetReg(kDWARFRsp, AbsVal::CFARel(rsp.delta + 8));
      }
      if (insn.id == ZYDIS_MNEMONIC_POP) {
        const ZydisDecodedOperand& op = insn.operands[0];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
          int d = DWARFRegOf(op.reg.value);
          if (d >= 0) {
            state->SetReg(d, IsFull64(op.reg.value) ? popped : AbsVal::Top());
          }
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
          std::optional<int64_t> slot = MemSlot(*state, insn, op.mem);
          if (slot.has_value()) {
            state->SetSlot(*slot, popped);
          }
        }
      }
      return out;
    }

    case ZYDIS_MNEMONIC_LEAVE: {
      // leave == mov %rbp,%rsp ; pop %rbp
      state->SetReg(kDWARFRsp, state->reg(kDWARFRbp));
      const AbsVal rsp = state->reg(kDWARFRsp);
      if (rsp.kind == AbsVal::Kind::kCFARel) {
        state->SetReg(kDWARFRbp, state->Slot(rsp.delta));
        state->SetReg(kDWARFRsp, AbsVal::CFARel(rsp.delta + 8));
      } else {
        state->ClobberReg(kDWARFRbp);
      }
      return out;
    }

    case ZYDIS_MNEMONIC_LEA: {
      if (insn.op_count != 2 || insn.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
          insn.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) {
        break;
      }
      int d = DWARFRegOf(insn.operands[0].reg.value);
      if (d < 0) {
        break;
      }
      if (!IsFull64(insn.operands[0].reg.value)) {
        ClobberWrittenReg(state, insn.operands[0].reg.value, d);
        return out;
      }
      const ZydisDecodedOperandMem& mem = insn.operands[1].mem;
      // `lea disp(%rip),%B` -- the switch-table base load.
      // ZydisCalcAbsoluteAddress resolves the RIP-relative displacement
      // against this instruction's own length, so there is no manual
      // "address + size + disp" arithmetic to get right here.
      if (mem.base == ZYDIS_REGISTER_RIP && mem.index == ZYDIS_REGISTER_NONE) {
        uint64_t target = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn.insn, &insn.operands[1], insn.address, &target))) {
          VLOG(1) << absl::StrFormat("0x%x: lea rip-relative -> reg %d = kConst(0x%x)", insn.address, d, target);
          state->SetReg(d, AbsVal::Const(static_cast<int64_t>(target)));
          return out;
        }
      }
      AbsVal val = LeaValue(*state, insn, mem);
      state->SetReg(d, val);
      return out;
    }

    case ZYDIS_MNEMONIC_MOV:
    case ZYDIS_MNEMONIC_MOVQ: {
      if (insn.op_count != 2) {
        break;
      }
      const ZydisDecodedOperand& dst = insn.operands[0];
      const ZydisDecodedOperand& src = insn.operands[1];
      if (dst.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int d = DWARFRegOf(dst.reg.value);
        if (d < 0) {
          break;
        }
        if (!IsFull64(dst.reg.value)) {
          // A narrower mov's identity does not survive the truncation. Its
          // bounds can, but only for a 32-bit destination, which x86-64
          // zero-extends into the full register -- exactly like movzx, and
          // it matters for the same reason: GCC frequently widens a guarded
          // index into whatever register the table load actually reads. An
          // 8- or 16-bit destination leaves the upper bits of the register
          // alone, so `mov %sil,%al` proves nothing whatsoever about rax,
          // however tightly bounded %sil was.
          // Read the source before writing the destination: they are very
          // often the same register (`mov %eax,%eax`), and clobbering first
          // would destroy both the value being read and the guard riding on
          // it. Deliberately not gated on IsFull64(src.reg): the bounds live
          // on the DWARF-level register regardless of which sub-register
          // spelling read it, unlike a value read, which ReadReg rightly
          // refuses to give for a sub-register.
          const bool widening = RegWidthBits(dst.reg.value) == 32;
          const int sr = (widening && src.type == ZYDIS_OPERAND_TYPE_REGISTER) ? DWARFRegOf(src.reg.value) : -1;
          const AbsVal src_val = sr >= 0 ? state->reg(sr) : AbsVal::Top();
          const uint64_t guard = sr >= 0 ? ProvenGuardBound(*state, sr, src.size) : kBoundTop;
          ClobberWrittenReg(state, dst.reg.value, d);
          if (sr >= 0) {
            ApplyZeroExtendedFrom(&state->gpr[d], src_val, src.size, guard);
          }
          return out;
        }
        if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
          state->SetReg(d, ReadReg(*state, src.reg.value));
        } else if (src.type == ZYDIS_OPERAND_TYPE_MEMORY) {
          std::optional<int64_t> slot = MemSlot(*state, insn, src.mem);
          state->SetReg(d, (slot.has_value() && src.size == 64) ? state->Slot(*slot) : AbsVal::Top());
        } else {
          // `mov $imm,%r` is deliberately left untracked rather than
          // turned into a kConst: nothing in the switch-table pattern
          // needs it (the table base always comes from a rip-relative
          // lea), and check_unmentioned_callee_saved fixtures rely on an
          // immediate load clobbering a register to unknown. (This also
          // covers what Capstone spelled the separate MOVABS mnemonic:
          // Zydis has no such mnemonic, a 64-bit-immediate mov decodes as
          // plain MOV, and it lands here the same way.)
          state->ClobberReg(d);
        }
        return out;
      }
      if (dst.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        std::optional<int64_t> slot = MemSlot(*state, insn, dst.mem);
        if (!slot.has_value()) {
          HandleUnplacedMemWrite(state);
          return out;
        }
        EraseSlots(state, *slot, std::max<int64_t>(1, dst.size / 8));
        if (dst.size == 64 && src.type == ZYDIS_OPERAND_TYPE_REGISTER && IsFull64(src.reg.value)) {
          state->SetSlot(*slot, ReadReg(*state, src.reg.value));
        }
        return out;
      }
      break;
    }

    case ZYDIS_MNEMONIC_MOVSXD: {
      if (insn.op_count != 2 || insn.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        break;
      }
      int d = DWARFRegOf(insn.operands[0].reg.value);
      if (d < 0 || !IsFull64(insn.operands[0].reg.value)) {
        break;
      }
      // Register-to-register `movsxd %src32,%dst64`: the bounds survive only
      // when the source's own value_bound proves the sign bit is clear, so
      // that sign-extension and zero-extension agree -- ApplySignExtendedFrom
      // is where that test lives.
      if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        const int sr = DWARFRegOf(insn.operands[1].reg.value);
        const unsigned src_bits = insn.operands[1].size;
        // Snapshot before the clobber -- `movsxd %eax,%rax` reads and writes
        // the same register.
        const AbsVal src_val = sr >= 0 ? state->reg(sr) : AbsVal::Top();
        const uint64_t guard = sr >= 0 ? ProvenGuardBound(*state, sr, src_bits) : kBoundTop;
        state->ClobberReg(d);
        if (sr >= 0) {
          ApplySignExtendedFrom(&state->gpr[d], src_val, src_bits, guard);
        }
        return out;
      }
      if (insn.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) {
        break;
      }
      // `movslq disp(%B,%I,4),%T` -- the switch-table load: T becomes the
      // table entry once %B is a known constant and the scale is 4 (an
      // int32 table). Anything else falls through to the generic clobber
      // below, same as any other unmodelled case.
      const ZydisDecodedOperandMem& mem = insn.operands[1].mem;
      if (mem.index == ZYDIS_REGISTER_NONE || mem.scale != 4 || mem.base == ZYDIS_REGISTER_NONE) {
        break;
      }
      // A 64-bit movsxd destination forces a 32-bit source, so scale 4 and
      // the load width already agree; assert it rather than re-deriving it.
      assert(insn.operands[1].size == 32);
      int idx_reg = DWARFRegOf(mem.index);
      int base_reg = DWARFRegOf(mem.base);
      if (idx_reg < 0 || base_reg < 0 || !IsFull64(mem.base)) {
        break;
      }
      const AbsVal& base_val = state->reg(base_reg);
      if (!base_val.IsConst()) {
        VLOG(1) << absl::StrFormat(
            "0x%x: movslq disp(%%B,%%I,4),%%T base reg %d is not a known constant (value=%v) -- not a table load",
            insn.address, base_reg, base_val);
        break;
      }
      uint64_t table = static_cast<uint64_t>(base_val.ConstValue()) + mem.disp.value;
      // Snapshot the index register's bound now, while its job is still
      // fresh, rather than re-deriving it with a live lookup at the
      // eventual `jmp` -- an intervening instruction reusing the same
      // register number for an unrelated guard would otherwise be able to
      // hand the resolver the wrong bound.
      uint64_t index_bound = state->reg(idx_reg).table_bound;
      VLOG(1) << absl::StrFormat("0x%x: movslq -> reg %d = kTableEntry(table=0x%x, index_reg=%d, captured_bound=%s)",
                                 insn.address, d, table, idx_reg,
                                 index_bound != kBoundTop ? absl::StrFormat("%u", index_bound) : std::string("<none>"));
      state->SetReg(d, AbsVal::TableEntry(table, static_cast<uint8_t>(idx_reg),
                                          static_cast<uint64_t>(base_val.ConstValue()), index_bound));
      return out;
    }

    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB: {
      // `add %B,%T` (either operand order) where %B is the same known
      // constant %T's table was derived from -- the switch-table
      // dispatch address. Zydis's operands[0] is always the destination
      // for a 2-operand ADD/SUB, regardless of which register held the
      // constant and which held the table entry.
      if (insn.id == ZYDIS_MNEMONIC_ADD && insn.op_count == 2 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int d0 = DWARFRegOf(insn.operands[0].reg.value);
        int d1 = DWARFRegOf(insn.operands[1].reg.value);
        if (d0 >= 0 && d1 >= 0 && IsFull64(insn.operands[0].reg.value) && IsFull64(insn.operands[1].reg.value)) {
          const AbsVal op0 = state->reg(d0);
          const AbsVal op1 = state->reg(d1);
          auto resolve = [](const AbsVal& base_candidate, const AbsVal& entry_candidate) -> std::optional<AbsVal> {
            if (base_candidate.IsConst() && entry_candidate.IsTableEntry() &&
                entry_candidate.TableBaseConst() == static_cast<uint64_t>(base_candidate.ConstValue())) {
              return AbsVal::JumpTarget(entry_candidate.TableAddr(), static_cast<uint8_t>(entry_candidate.IndexReg()),
                                        entry_candidate.table_bound);
            }
            return std::nullopt;
          };
          std::optional<AbsVal> resolved = resolve(op0, op1);
          if (!resolved.has_value()) {
            resolved = resolve(op1, op0);
          }
          if (resolved.has_value()) {
            VLOG(1) << absl::StrFormat("0x%x: %s -> reg %d = kJumpTarget(%v)", insn.address,
                                       insn.id == ZYDIS_MNEMONIC_ADD ? "add" : "sub", d0, *resolved);
            state->SetReg(d0, *resolved);
            return out;
          }
        }
      }
      if (insn.op_count != 2 || insn.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
          insn.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        break;
      }
      int d = DWARFRegOf(insn.operands[0].reg.value);
      if (d < 0) {
        break;
      }
      const AbsVal cur = state->reg(d);
      if (!IsFull64(insn.operands[0].reg.value) || cur.kind != AbsVal::Kind::kCFARel) {
        ClobberWrittenReg(state, insn.operands[0].reg.value, d);
        return out;
      }
      uint64_t imm = static_cast<uint64_t>(insn.operands[1].imm.value.s);
      uint64_t udelta = static_cast<uint64_t>(cur.delta);
      int64_t delta = static_cast<int64_t>(insn.id == ZYDIS_MNEMONIC_ADD ? udelta + imm : udelta - imm);
      state->SetReg(d, AbsVal::CFARel(delta));
      return out;
    }

    case ZYDIS_MNEMONIC_CMP: {
      // `cmp $imm,%reg` -- the switch-table guard. cmp writes no register or
      // memory, only EFLAGS, which the unconditional check at the top of
      // this function already cleared; a matching cmp sets it again here.
      // Anything else (cmp of two registers, a memory operand) simply
      // leaves it cleared -- not a guard this analysis resolves.
      //
      // Recording it is *all* that happens here, deliberately. A comparison
      // on its own establishes nothing -- it sets flags; it is the branch
      // that picks a side and turns it into a fact, and only on the edge
      // where the comparison came out in bounds. Deriving a bound here
      // instead (an earlier version did, to rescue narrow compares) invents
      // one out of thin air on the taken edge, or with no branch at all.
      // See the guard conversion in fde-checker.cc's Drain.
      if (insn.op_count == 2 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        int r = DWARFRegOf(insn.operands[0].reg.value);
        if (r >= 0) {
          uint8_t width = insn.operands[0].size;
          uint64_t imm = insn.operands[1].imm.value.u;
          if (width < 64) {
            imm &= ((1ULL << width) - 1);
          }
          state->last_cmp = AbsState::FlagsGuard{r, width, imm};
        }
      }
      return out;
    }

    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX: {
      // `movzbl %r8b,%ecx`, `movsbl %al,%edx` and friends: the destination's
      // own identity does not survive the truncation, but its numeric bounds
      // can -- GCC routinely widens a guarded index into whatever register
      // the table load actually reads, so carrying the bounds across, rather
      // than the whole value, is what lets the guard and the table load
      // disagree on register without losing the guard.
      //
      // Only a destination that writes the whole 64-bit register qualifies:
      // 64-bit explicitly, or 32-bit because x86-64 zero-extends those. A
      // 16-bit destination (`movzbw %al,%cx`) leaves the upper bits of the
      // register alone and so proves nothing about it.
      if (insn.op_count != 2 || insn.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        break;  // no reg destination we can name -- fall through to the generic clobber
      }
      int d = DWARFRegOf(insn.operands[0].reg.value);
      if (d < 0) {
        break;
      }
      const ZydisDecodedOperand& src = insn.operands[1];
      if (src.type != ZYDIS_OPERAND_TYPE_REGISTER && src.type != ZYDIS_OPERAND_TYPE_MEMORY) {
        break;
      }
      // Everything the source has to say is read *before* the destination is
      // clobbered: `movzbl %al,%eax` is the single most common spelling of
      // this instruction, and there the two are the same register.
      //
      // A memory source is worth handling and not just for symmetry: it is
      // where a byte-wide index usually comes from, and `movzbl (%rdi),%eax`
      // proving rax <= 255 is what later lets `cmp $imm,%al` bound rax at
      // all. There is no source AbsVal in that case, only the load width.
      const int sr = src.type == ZYDIS_OPERAND_TYPE_REGISTER ? DWARFRegOf(src.reg.value) : -1;
      const AbsVal src_val = sr >= 0 ? state->reg(sr) : AbsVal::Top();
      const uint64_t guard = sr >= 0 ? ProvenGuardBound(*state, sr, src.size) : kBoundTop;
      ClobberWrittenReg(state, insn.operands[0].reg.value, d);
      if (RegWidthBits(insn.operands[0].reg.value) < 32) {
        return out;  // an 8/16-bit destination proves nothing about the parent
      }
      if (insn.id == ZYDIS_MNEMONIC_MOVZX) {
        ApplyZeroExtendedFrom(&state->gpr[d], src_val, src.size, guard);
      } else {
        ApplySignExtendedFrom(&state->gpr[d], src_val, src.size, guard);
      }
      // Whatever the widen proved, the destination's own width still caps it.
      state->gpr[d].value_bound = std::min(state->gpr[d].value_bound, WrittenRegBound(insn.operands[0].reg.value));
      return out;
    }

    case ZYDIS_MNEMONIC_NOP:
    case ZYDIS_MNEMONIC_ENDBR32:
    case ZYDIS_MNEMONIC_ENDBR64:
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

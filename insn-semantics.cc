/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "insn-semantics.h"

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

  RegInfoTable() {
    for (int r = 0; r <= ZYDIS_REGISTER_MAX_VALUE; ++r) {
      dwarf_reg[r] = -1;
      is_full_64[r] = false;
      auto zreg = static_cast<ZydisRegister>(r);
      ZydisRegister parent = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, zreg);
      for (int i = 0; i < kNumGPRs; ++i) {
        if (kDwarfGprs[i] == parent) {
          dwarf_reg[r] = static_cast<int8_t>(i);
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
        state->ClobberReg(d);
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
  if (WritesEflags(insn)) {
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
      VLOG(1) << absl::StrFormat("0x%x: indirect jmp via reg %d, value=%s", insn.address, r, v.ToString());
      if (v.IsJumpTarget()) {
        // The bound was captured once at movslq-time and carried through
        // the `add` into this kJumpTarget -- not re-derived with a live
        // AbsState::Bound lookup here, which would be vulnerable to an
        // intervening instruction reusing the same register number for an
        // unrelated guard.
        std::optional<uint64_t> bound = v.Bound();
        VLOG(1) << absl::StrFormat("0x%x:   jump target table=0x%x index_reg=%d captured_bound=%s", insn.address,
                                   v.TableAddr(), v.IndexReg(),
                                   bound.has_value() ? absl::StrFormat("%u", *bound) : std::string("<none>"));
        if (bound.has_value()) {
          out.has_jump_table = true;
          out.jump_table_addr = v.TableAddr();
          out.jump_table_entries = *bound + 1;
          return out;
        }
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
        state->ClobberReg(d);
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
          // A narrower mov's identity does not survive -- see the 8/16-bit
          // case below for why this stays a clobber rather than a value
          // copy -- but same-width-or-widening register-to-register moves
          // (`mov %esi,%eax` and friends: a 32-bit destination write still
          // zero-extends to the full 64-bit register on x86-64, the same
          // as movzx) carry a numeric bound across exactly the way movzx
          // does, and for the same reason: GCC frequently widens the
          // guard register into whatever register the table load actually
          // reads.
          std::optional<uint64_t> carried;
          if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            int s = DWARFRegOf(src.reg.value);
            // Deliberately not gated on IsFull64(src.reg): the bound
            // lives on the DWARF-level register regardless of which
            // sub-register spelling read it (`mov %esi,%eax` reads the
            // same rsi-level bound `mov %rsi,%rax` would), unlike a
            // value read, which ReadReg rightly refuses to give for a
            // sub-register.
            if (s >= 0) {
              carried = state->reg(s).Bound();
              if (!carried.has_value() && state->last_cmp.has_value() && state->last_cmp->reg == s &&
                  state->last_cmp->width_bits == src.size) {
                carried = state->last_cmp->imm;
              }
            }
          }
          state->ClobberReg(d);
          if (carried.has_value()) {
            state->SetBound(d, *carried);
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
      // Register-to-register `movsxd %src32, %dst64`: carries the bound across if the
      // bound is non-negative (< 2^31), so the sign bit is 0 and sign-extension matches zero-extension.
      if (insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int s = DWARFRegOf(insn.operands[1].reg.value);
        std::optional<uint64_t> carried;
        if (s >= 0) {
          std::optional<uint64_t> b = state->reg(s).Bound();
          if (!b.has_value() && state->last_cmp.has_value() && state->last_cmp->reg == s &&
              state->last_cmp->width_bits == 32) {
            b = state->last_cmp->imm;
          }
          if (b.has_value() && *b < (1ULL << 31)) {
            carried = b;
          }
        }
        state->ClobberReg(d);
        if (carried.has_value()) {
          state->SetBound(d, *carried);
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
      int idx_reg = DWARFRegOf(mem.index);
      int base_reg = DWARFRegOf(mem.base);
      if (idx_reg < 0 || base_reg < 0 || !IsFull64(mem.base)) {
        break;
      }
      const AbsVal& base_val = state->reg(base_reg);
      if (!base_val.IsConst()) {
        VLOG(1) << absl::StrFormat(
            "0x%x: movslq disp(%%B,%%I,4),%%T base reg %d is not a known constant (value=%s) -- not a table load",
            insn.address, base_reg, base_val.ToString());
        break;
      }
      uint64_t table = static_cast<uint64_t>(base_val.ConstValue()) + mem.disp.value;
      // Snapshot the index register's bound now, while its job is still
      // fresh, rather than re-deriving it with a live lookup at the
      // eventual `jmp` -- an intervening instruction reusing the same
      // register number for an unrelated guard would otherwise be able to
      // hand the resolver the wrong bound.
      std::optional<uint64_t> bound = state->Bound(idx_reg);
      VLOG(1) << absl::StrFormat("0x%x: movslq -> reg %d = kTableEntry(table=0x%x, index_reg=%d, captured_bound=%s)",
                                 insn.address, d, table, idx_reg,
                                 bound.has_value() ? absl::StrFormat("%u", *bound) : std::string("<none>"));
      state->SetReg(d, AbsVal::TableEntry(table, static_cast<uint8_t>(idx_reg),
                                          static_cast<uint64_t>(base_val.ConstValue()), bound));
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
                                        entry_candidate.Bound());
            }
            return std::nullopt;
          };
          std::optional<AbsVal> resolved = resolve(op0, op1);
          if (!resolved.has_value()) {
            resolved = resolve(op1, op0);
          }
          if (resolved.has_value()) {
            VLOG(1) << absl::StrFormat("0x%x: %s -> reg %d = kJumpTarget(%s)", insn.address,
                                       insn.id == ZYDIS_MNEMONIC_ADD ? "add" : "sub", d0, resolved->ToString());
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
        state->ClobberReg(d);
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
      // `movzbl %r8b,%ecx`, `movsbl %al,%edx` and friends: the destination's own identity
      // does not survive the truncation in general, but a numeric bound
      // established on the source does -- GCC routinely widens the guard
      // register into whatever register the table load actually reads,
      // so carrying just the bound across, rather than the whole value, is
      // what lets the guard and the table load disagree on register without
      // losing the guard.
      //
      // For sign-extension (`movsx`), the bound is valid only when the immediate
      // bound is small enough that the sign bit is guaranteed to be 0 (i.e.
      // bound < (1 << (src_bits - 1))), so sign-extension is identical to zero-extension.
      if (insn.op_count == 2 && insn.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          insn.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        int d = DWARFRegOf(insn.operands[0].reg.value);
        int s = DWARFRegOf(insn.operands[1].reg.value);
        if (d >= 0) {
          std::optional<uint64_t> carried;
          uint8_t src_bits = insn.operands[1].size;
          if (s >= 0) {
            std::optional<uint64_t> b = state->reg(s).Bound();
            if (!b.has_value() && state->last_cmp.has_value() && state->last_cmp->reg == s &&
                state->last_cmp->width_bits == src_bits) {
              b = state->last_cmp->imm;
            }
            if (b.has_value()) {
              if (insn.id == ZYDIS_MNEMONIC_MOVZX) {
                carried = b;
              } else {
                if (src_bits < 64 && *b < (1ULL << (src_bits - 1))) {
                  carried = b;
                }
              }
            }
          }
          state->ClobberReg(d);
          if (carried.has_value()) {
            state->SetBound(d, *carried);
          }
          return out;
        }
      }
      break;  // no reg destination we can name -- fall through to the generic clobber
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

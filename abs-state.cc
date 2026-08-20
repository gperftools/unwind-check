/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include "absl/strings/str_format.h"

namespace unwind_analysis {

std::string AbsVal::ToString() const {
  switch (kind) {
    case Kind::kTop:
      return "unknown";
    case Kind::kBottom:
      return "conflict";
    case Kind::kCfaRel:
      return absl::StrFormat("CFA%+d", static_cast<int>(delta));
    case Kind::kOrigReg:
      return absl::StrFormat("entry %s", DwarfRegName(reg));
  }
  return "?";
}

AbsState AbsState::Entry() {
  AbsState s;
  for (int r = 0; r < kNumGpRegs; r++) {
    s.gpr[r] = AbsVal::OrigReg(r);
  }
  s.gpr[kDwarfRsp] = AbsVal::CfaRel(-8);
  s.slots[-8] = AbsVal::OrigReg(kDwarfRip);
  return s;
}

AbsState AbsState::SeedFromRow(const CfiRow& row, bool at_function_entry) {
  AbsState s;
  for (int r = 0; r < kNumGpRegs; r++) {
    s.gpr[r] = AbsVal::OrigReg(r);
  }

  for (int r = 0; r < kNumDwarfRegs; r++) {
    const RegRule& rule = row.regs[r];
    switch (rule.kind) {
      case RegRule::Kind::kUnset:
        // Silence means "still the entry value" only when nothing has
        // run yet to make that untrue -- see the comment on the
        // declaration for the fragment/landing-pad case.
        if (!at_function_entry && r < kNumGpRegs) {
          s.gpr[r] = AbsVal::Top();
        }
        break;
      case RegRule::Kind::kSameValue:
        break;  // an explicit CFI assertion, trusted wherever it appears
      case RegRule::Kind::kAtCfaOffset:
        s.slots[rule.offset] = AbsVal::OrigReg(r);
        break;
      case RegRule::Kind::kInRegister:
        if (rule.reg < kNumGpRegs) {
          s.gpr[rule.reg] = AbsVal::OrigReg(r);
        }
        break;
      case RegRule::Kind::kValOffset:
        if (r < kNumGpRegs) {
          s.gpr[r] = AbsVal::CfaRel(rule.offset);
        }
        break;
      case RegRule::Kind::kUndefined:
      case RegRule::Kind::kExpression:
      case RegRule::Kind::kValExpression:
        if (r < kNumGpRegs) {
          s.gpr[r] = AbsVal::Top();
        }
        break;
    }
  }

  // No usable CFA rule at the start: we cannot anchor anything, so rsp
  // is genuinely unknown (top) rather than assumed.
  s.gpr[kDwarfRsp] = AbsVal::Top();
  // Last, so that the CFA rule wins for its own register.
  if (row.cfa.kind == CfaRule::Kind::kRegOffset && row.cfa.reg < kNumGpRegs) {
    s.gpr[row.cfa.reg] = AbsVal::CfaRel(-row.cfa.offset);
  }
  return s;
}

AbsVal AbsState::Slot(int64_t offset) const {
  auto it = slots.find(offset);
  if (it == slots.end()) {
    return AbsVal::Top();
  }
  return it->second;
}

void AbsState::SetSlot(int64_t offset, const AbsVal& v) {
  // Top is never stored: an absent key already reads as top through
  // Slot() above. kBottom *is* stored -- unlike top, it is a fact about
  // this slot (a recorded conflict), not the absence of one.
  if (v.is_top()) {
    slots.erase(offset);
    return;
  }
  slots[offset] = v;
}

void AbsState::DropSlotsBelow(int64_t rsp_delta) {
  slots.erase(slots.begin(), slots.lower_bound(rsp_delta));
}

void AbsState::DropDeadSlots(int64_t rsp_delta) {
  DropSlotsBelow(rsp_delta - kRedZoneBytes);
}

std::string JoinConflict::Describe() const {
  if (reg == kSlotConflict) {
    return absl::StrFormat("stack slot CFA%+d is %s on one path and %s on another", static_cast<int>(offset),
                           lhs.ToString(), rhs.ToString());
  }
  return absl::StrFormat("%s is %s on one path and %s on another", DwarfRegName(reg), lhs.ToString(), rhs.ToString());
}

bool Join(const AbsState& incoming, AbsState* state, std::vector<JoinConflict>* conflicts) {
  bool changed = false;

  for (int r = 0; r < kNumGpRegs; r++) {
    if (state->gpr[r] == incoming.gpr[r]) {
      continue;
    }
    // kBottom absorbs: a register already flagged as conflicting stays
    // that way, and a register that only just learned of a conflict on
    // the incoming side adopts it. Neither case is a fresh disagreement
    // to report -- that happened (or will happen) at the join that
    // first produced the kBottom.
    if (state->gpr[r].is_bottom()) {
      continue;
    }
    if (incoming.gpr[r].is_bottom()) {
      state->gpr[r] = AbsVal::Bottom();
      changed = true;
      continue;
    }
    // kTop is the identity element: take whatever the other side knows.
    if (state->gpr[r].is_top()) {
      state->gpr[r] = incoming.gpr[r];
      changed = true;
      continue;
    }
    if (incoming.gpr[r].is_top()) {
      continue;
    }
    // Both sides name a concrete value and, per the equality check
    // above, disagree about what it is -- a genuine conflict.
    if (conflicts != nullptr) {
      conflicts->push_back(JoinConflict{r, 0, state->gpr[r], incoming.gpr[r]});
    }
    state->gpr[r] = AbsVal::Bottom();
    changed = true;
  }

  // Slots mirror the register logic above exactly, except a slot's
  // "top" is represented by absence from the map instead of a stored
  // AbsVal -- Slot() already reads a missing key that way. So a slot
  // named by only one side is top on the other, and top is the meet's
  // identity element: it survives when only `state` names it, and is
  // adopted verbatim when only `incoming` names it (the second loop
  // below). A slot named by both survives when they agree, drops to a
  // reported kBottom when they disagree, and a kBottom on either side
  // -- already a recorded conflict -- absorbs without a fresh report.
  for (auto it = state->slots.begin(); it != state->slots.end();) {
    if (it->second.is_bottom()) {
      ++it;
      continue;
    }
    auto other = incoming.slots.find(it->first);
    if (other == incoming.slots.end()) {
      ++it;
      continue;
    }
    if (other->second == it->second) {
      ++it;
      continue;
    }
    if (other->second.is_bottom()) {
      it->second = AbsVal::Bottom();
      changed = true;
      ++it;
      continue;
    }
    if (conflicts != nullptr) {
      conflicts->push_back(JoinConflict{JoinConflict::kSlotConflict, it->first, it->second, other->second});
    }
    it->second = AbsVal::Bottom();
    changed = true;
    ++it;
  }
  for (const auto& [offset, val] : incoming.slots) {
    if (state->slots.find(offset) == state->slots.end()) {
      state->slots.emplace(offset, val);
      changed = true;
    }
  }

  return changed;
}

}  // namespace unwind_analysis

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include "absl/strings/str_format.h"

namespace unwind_analysis {

std::string AbsVal::ToString() const {
  switch (kind) {
    case Kind::kUnknown:
      return "unknown";
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

AbsState AbsState::SeedFromRow(const CfiRow& row) {
  AbsState s;
  for (int r = 0; r < kNumGpRegs; r++) {
    s.gpr[r] = AbsVal::OrigReg(r);
  }

  for (int r = 0; r < kNumDwarfRegs; r++) {
    const RegRule& rule = row.regs[r];
    switch (rule.kind) {
      case RegRule::Kind::kUnset:
      case RegRule::Kind::kSameValue:
        break;  // already holds its own entry value
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
          s.gpr[r] = AbsVal::Unknown();
        }
        break;
    }
  }

  // No usable CFA rule at the start: we cannot anchor anything, so rsp
  // is genuinely unknown rather than assumed.
  s.gpr[kDwarfRsp] = AbsVal::Unknown();
  // Last, so that the CFA rule wins for its own register.
  if (row.cfa.kind == CfaRule::Kind::kRegOffset && row.cfa.reg < kNumGpRegs) {
    s.gpr[row.cfa.reg] = AbsVal::CfaRel(-row.cfa.offset);
  }
  return s;
}

AbsVal AbsState::Slot(int64_t offset) const {
  auto it = slots.find(offset);
  if (it == slots.end()) {
    return AbsVal::Unknown();
  }
  return it->second;
}

void AbsState::SetSlot(int64_t offset, const AbsVal& v) {
  if (v.is_unknown()) {
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
    bool dest_unknown = state->gpr[r].is_unknown();
    bool src_unknown = incoming.gpr[r].is_unknown();
    if (!dest_unknown && !src_unknown) {
      if (conflicts != nullptr) {
        conflicts->push_back(JoinConflict{r, 0, state->gpr[r], incoming.gpr[r]});
      }
      state->gpr[r] = AbsVal::Unknown();
      changed = true;
    } else if (dest_unknown) {
      state->gpr[r] = incoming.gpr[r];
      changed = true;
    }
  }

  // A slot survives the meet only if both sides name it and agree.
  for (auto it = state->slots.begin(); it != state->slots.end();) {
    auto other = incoming.slots.find(it->first);
    if (other != incoming.slots.end() && other->second == it->second) {
      ++it;
      continue;
    }
    if (other != incoming.slots.end() && conflicts != nullptr) {
      conflicts->push_back(JoinConflict{JoinConflict::kSlotConflict, it->first, it->second, other->second});
    }
    it = state->slots.erase(it);
    changed = true;
  }

  return changed;
}

}  // namespace unwind_analysis

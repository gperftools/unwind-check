/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#include "abs-state.h"

#include <algorithm>

#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

// What Join() does to one pair of CFI values, whether they are a
// register's contents or a stack slot's -- the two used to have
// separately-written, subtly different logic; this is now the single
// place that logic lives.
struct JoinValueResult {
  AbsVal value;
  bool changed;
  // Set only for a genuine disagreement the caller should report. Every
  // disagreement in this lattice is one: the values that were not worth
  // reporting about have moved to TableVal, which has no reporting at all.
  bool real_conflict;
};

JoinValueResult JoinValue(const AbsVal& current, const AbsVal& incoming) {
  if (current == incoming) {
    return {current, false, false};
  }
  // kBottom absorbs: a value already flagged as conflicting stays that
  // way, and a value that only just learned of a conflict on the incoming
  // side adopts it. Neither is a fresh disagreement to report -- that
  // happened (or will happen) at the join that first produced the kBottom.
  if (current.is_bottom()) {
    return {current, false, false};
  }
  if (incoming.is_bottom()) {
    return {AbsVal::Bottom(), true, false};
  }
  // kTop is the identity element: take whatever the other side knows.
  if (current.is_top()) {
    return {incoming, true, false};
  }
  if (incoming.is_top()) {
    return {current, false, false};
  }
  // Two sides that each name something, and name different things. That
  // is a real disagreement about a value a CFI row may well consult, so
  // it goes to kBottom *and* gets reported.
  //
  // Note there is no carve-out here any more. Two unrelated `.rodata`
  // pointers meeting at a merge used to arrive as two different kConst
  // values and need suppressing; they now arrive as two kOthers, which
  // compare equal above and never reach this point at all. The
  // suppression became unnecessary rather than moving somewhere else.
  return {AbsVal::Bottom(), true, true};
}

// The table lattice's join. Deliberately much smaller than the CFI one:
// it reports nothing, because nothing here is a CFI claim.
//
// Identity follows the same top/bottom shape AbsVal uses -- kNone is the
// identity element, kConflict is absorbing -- for exactly the reason spelled
// out on TableVal::kConflict. Bounds join by max, which is
// the only thing an upper bound can join by -- one path proving <= 4 and
// another <= 7 leaves <= 7 standing -- and kBoundTop being max's identity
// is what makes an unbounded path wipe out the other path's bound with no
// special case. The two are settled separately so that giving up on the
// identity does not silently keep a bound that only one path proved, and
// vice versa.
TableVal JoinTableValue(const TableVal& current, const TableVal& incoming) {
  TableVal merged;
  if (current.is_conflict() || incoming.is_conflict()) {
    merged = TableVal::Conflict();  // absorbing
  } else if (current.SameIdentity(incoming)) {
    merged = current;  // also covers two kNones, differing only in bounds
  } else if (current.is_none()) {
    merged = incoming;  // kNone is the identity element: adopt what is known
  } else if (incoming.is_none()) {
    merged = current;
  } else {
    // Two different resolved values. Giving up has to land on kConflict
    // rather than kNone, or a third predecessor would be adopted into the
    // identity element and resurrect a concrete answer -- see TableVal.
    merged = TableVal::Conflict();
  }
  merged.value_bound = std::max(current.value_bound, incoming.value_bound);
  merged.table_bound = std::max(current.table_bound, incoming.table_bound);
  return merged;
}

}  // namespace

AbsState AbsState::Entry() {
  AbsState s;
  for (int r = 0; r < kNumGPRs; r++) {
    s.gpr[r] = AbsVal::OrigReg(r);
  }
  s.gpr[kDWARFRsp] = AbsVal::CFARel(-8);
  s.slots[-8] = AbsVal::OrigReg(kDWARFRip);
  return s;
}

AbsState AbsState::SeedFromRow(const CFIRow& row, bool at_function_entry) {
  AbsState s;
  for (int r = 0; r < kNumGPRs; r++) {
    s.gpr[r] = AbsVal::OrigReg(r);
  }

  for (int r = 0; r < kNumDWARFRegs; r++) {
    const RegRule& rule = row.regs[r];
    switch (rule.kind) {
      case RegRule::Kind::kUnset:
        // Silence means "still the entry value" only when nothing has
        // run yet to make that untrue -- see the comment on the
        // declaration for the fragment/landing-pad case.
        if (!at_function_entry && r < kNumGPRs) {
          s.gpr[r] = AbsVal::Top();
        }
        break;
      case RegRule::Kind::kSameValue:
        break;  // an explicit CFI assertion, trusted wherever it appears
      case RegRule::Kind::kAtCFAOffset:
        s.slots[rule.offset] = AbsVal::OrigReg(r);
        break;
      case RegRule::Kind::kInRegister:
        if (rule.reg < kNumGPRs) {
          s.gpr[rule.reg] = AbsVal::OrigReg(r);
        }
        break;
      case RegRule::Kind::kValOffset:
        if (r < kNumGPRs) {
          s.gpr[r] = AbsVal::CFARel(rule.offset);
        }
        break;
      case RegRule::Kind::kUndefined:
      case RegRule::Kind::kExpression:
      case RegRule::Kind::kValExpression:
        if (r < kNumGPRs) {
          s.gpr[r] = AbsVal::Top();
        }
        break;
    }
  }

  // No usable CFA rule at the start: we cannot anchor anything, so rsp
  // is genuinely unknown (top) rather than assumed.
  s.gpr[kDWARFRsp] = AbsVal::Top();
  // Last, so that the CFA rule wins for its own register.
  if (row.cfa.kind == CFARule::Kind::kRegOffset && row.cfa.reg < kNumGPRs) {
    s.gpr[row.cfa.reg] = AbsVal::CFARel(-row.cfa.offset);
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
    return absl::StrFormat("stack slot CFA%+d is %v on one path and %v on another", static_cast<int>(offset), lhs, rhs);
  }
  return absl::StrFormat("%s is %v on one path and %v on another", DWARFRegName(reg), lhs, rhs);
}

bool Join(const AbsState& incoming, AbsState* state, std::vector<JoinConflict>* conflicts) {
  bool changed = false;

  for (int r = 0; r < kNumGPRs; r++) {
    JoinValueResult result = JoinValue(state->gpr[r], incoming.gpr[r]);
    if (result.real_conflict && conflicts != nullptr) {
      conflicts->push_back(JoinConflict{r, 0, state->gpr[r], incoming.gpr[r]});
    }
    if (result.changed) {
      state->gpr[r] = result.value;
      changed = true;
    }
    // The table half joins independently and reports nothing -- but it
    // still has to feed `changed`. A table join that widens a bound
    // without requeueing the successor would leave it holding a *tighter*
    // bound than the fixed point allows, which is the direction that sizes
    // a table too small and sends the walk to the wrong targets.
    TableVal merged_table = JoinTableValue(state->tbl[r], incoming.tbl[r]);
    if (merged_table != state->tbl[r]) {
      state->tbl[r] = merged_table;
      changed = true;
    }
  }

  // Stack slots go through the exact same per-value decision as registers
  // above (JoinValue) -- what differs is only how the pair to compare is
  // found: a slot's "top" is represented by absence from the map instead
  // of a stored AbsVal (Slot() already reads a missing key that way), so a
  // slot named by only one side is top on the other and needs no lookup
  // through JoinValue to know the identity-element answer (survives
  // verbatim either way). Slots carry no table half and so no bounds, which
  // is what makes that shortcut sound here.
  for (auto it = state->slots.begin(); it != state->slots.end();) {
    if (it->second.is_bottom()) {
      ++it;  // already absorbed; JoinValue would agree, no need to ask
      continue;
    }
    auto other = incoming.slots.find(it->first);
    if (other == incoming.slots.end()) {
      ++it;  // incoming is top here; JoinValue(cur, top) == cur, unchanged
      continue;
    }
    JoinValueResult result = JoinValue(it->second, other->second);
    if (result.real_conflict && conflicts != nullptr) {
      conflicts->push_back(JoinConflict{JoinConflict::kSlotConflict, it->first, it->second, other->second});
    }
    if (result.changed) {
      it->second = result.value;
      changed = true;
    }
    ++it;
  }
  for (const auto& [offset, val] : incoming.slots) {
    if (state->slots.find(offset) == state->slots.end()) {
      // state is top here; JoinValue(top, val) == val, changed.
      state->slots.emplace(offset, val);
      changed = true;
    }
  }

  // `last_cmp` is a single fact (there is exactly one EFLAGS), joined
  // equal-preserving-else-clear rather than by max the way the bounds are
  // -- it is not a bound but the raw comparison a guard branch has yet to
  // interpret, so there is nothing to widen, only to keep or drop. It
  // survives only where both sides agree, since disagreement means the
  // guard does not actually dominate this point -- some path reaching here
  // never ran it.
  // Never the reverse (nullopt adopting a value): `propagate`'s
  // first-sighting case is the only place a pc's *first* contribution is
  // ever recorded, so by the time Join runs here, an already-nullopt
  // `state->last_cmp` means either "no guard on the first path either" or
  // "an earlier disagreement already cleared it" -- both cases are
  // correctly final, absorbing, and never re-set.
  if (state->last_cmp.has_value() && state->last_cmp != incoming.last_cmp) {
    state->last_cmp = std::nullopt;
    changed = true;
  }

  return changed;
}

}  // namespace unwind_analysis

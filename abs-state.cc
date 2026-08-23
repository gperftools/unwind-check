/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include <algorithm>

#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

// The three switch-table-resolution kinds (see abs-state.h). A CFI row
// can never assert anything about a scratch register holding a
// `.rodata` pointer or table-derived offset, so a join disagreement
// between two of these is not the compiler-bug signal Join() exists to
// report -- it just means precision was lost. It still has to resolve to
// kBottom, not kTop, even though nothing gets reported: kTop is the
// identity element a later, third predecessor's value would be silently
// adopted into (see JoinValue below), which would resurrect a concrete
// answer after two paths already disagreed here -- order-dependent and
// exactly the non-monotonic "undo" Join exists to rule out. kBottom is
// absorbing, so once this has given up it stays given up regardless of
// how many more predecessors arrive.
bool IsTableResolutionKind(AbsVal::Kind k) {
  return k == AbsVal::Kind::kConst || k == AbsVal::Kind::kTableEntry || k == AbsVal::Kind::kJumpTarget;
}

// What Join() does to one pair of values, whether they are a register's
// contents or a stack slot's -- the two used to have separately-written,
// subtly different logic; this is now the single place that logic lives.
struct JoinValueResult {
  AbsVal value;
  bool changed;
  // Set only for a genuine CFI-relevant disagreement the caller should
  // report; the table-resolution carve-out and ordinary top/bottom
  // handling never set this.
  bool real_conflict;
};

JoinValueResult JoinValue(const AbsVal& current, const AbsVal& incoming) {
  if (current == incoming) {
    return {current, false, false};
  }

  // First decide what happens to the *identity* (kind/delta/reg/aux). The
  // bounds are settled separately below, because they join by a different
  // rule and have to join the same way no matter which branch the identity
  // took.
  AbsVal merged;
  bool real_conflict = false;
  if (current.is_bottom() || incoming.is_bottom()) {
    // kBottom absorbs: a value already flagged as conflicting stays that
    // way, and a value that only just learned of a conflict on the incoming
    // side adopts it. Neither is a fresh disagreement to report -- that
    // happened (or will happen) at the join that first produced the kBottom.
    merged = AbsVal::Bottom();
  } else if (current.SameIdentity(incoming)) {
    // Both sides name the same thing -- true of any two kTop values in
    // particular, since kTop's core is always {kTop,0,0,0} regardless of
    // what each side's bounds say -- so, per the equality check above, all
    // they can disagree about is the bounds. This has to be tested before
    // the kTop-as-identity-element handling below, or two differently
    // bounded kTops would take the "adopt whichever side is concrete"
    // branch and one side's bounds would be preferred outright instead of
    // joined.
    merged = current;
  } else if (current.is_top()) {
    // kTop is the identity element for the identity: take whatever the
    // other side knows. Only reached once SameIdentity has ruled out "both
    // sides are kTop", so this is a genuine difference in kind.
    merged = incoming;
  } else if (incoming.is_top()) {
    merged = current;
  } else {
    // A genuine identity disagreement -- ordinarily a real conflict, but
    // not when both sides are one of the switch-table resolution kinds,
    // which no CFI row can ever consult; see IsTableResolutionKind.
    merged = AbsVal::Bottom();
    real_conflict = !(IsTableResolutionKind(current.kind) && IsTableResolutionKind(incoming.kind));
  }

  // Bounds join by max, always, whatever the identity did. An upper bound
  // that holds on one incoming path and not the other holds nowhere, and
  // kBoundTop being max's identity is exactly what expresses that -- see
  // kBoundTop's comment. Doing this after the identity merge (rather than
  // letting each branch carry its own side's bounds along) is what stops an
  // adopted kTop or an adopted concrete value from smuggling a bound the
  // other path never proved.
  merged.value_bound = std::max(current.value_bound, incoming.value_bound);
  merged.table_bound = std::max(current.table_bound, incoming.table_bound);

  // Compare against `current` rather than trusting the branch taken: several
  // of them above can legitimately land back on exactly what was already
  // there (two kTops that differ only in a bound, say), and reporting that
  // as a change would requeue the successor for no new information.
  return {merged, merged != current, real_conflict};
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
  }

  // Stack slots go through the exact same per-value decision as registers
  // above (JoinValue) -- what differs is only how the pair to compare is
  // found: a slot's "top" is represented by absence from the map instead
  // of a stored AbsVal (Slot() already reads a missing key that way), so a
  // slot named by only one side needs no JoinValue call to know what
  // happens to its identity. Its *bounds* still have to be joined, which is
  // why that case is not a plain skip. A slot named by both goes through
  // JoinValue like any register.
  for (auto it = state->slots.begin(); it != state->slots.end();) {
    auto other = incoming.slots.find(it->first);
    if (other == incoming.slots.end()) {
      // Incoming is top here, so the identity survives (top is the identity
      // element) but the bounds do not: max against kBoundTop is kBoundTop.
      // Skipping this would let a bound proved on one path alone survive a
      // merge with a path that never proved it.
      if (it->second.value_bound != kBoundTop || it->second.table_bound != kBoundTop) {
        it->second.ClearBounds();
        changed = true;
      }
      ++it;
      continue;
    }
    if (it->second.is_bottom() && it->second.value_bound == kBoundTop && it->second.table_bound == kBoundTop) {
      ++it;  // already fully absorbed; JoinValue would agree, no need to ask
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
      // state is top here, so val's identity is adopted -- but, exactly as
      // above, not its bounds: this side never proved them.
      AbsVal adopted = val;
      adopted.ClearBounds();
      state->slots.emplace(offset, adopted);
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

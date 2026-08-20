/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

// --- AbsVal ---------------------------------------------------------

TEST(AbsValTest, TopIsTheDefaultAndIsNeitherBottomNorConcrete) {
  AbsVal v;
  EXPECT_TRUE(v.is_top());
  EXPECT_TRUE(v.is_unknown());
  EXPECT_FALSE(v.is_bottom());
  EXPECT_FALSE(v.IsCfaRel(0));
  EXPECT_FALSE(v.IsOrigReg(0));
  EXPECT_EQ(v, AbsVal::Top());
}

TEST(AbsValTest, BottomIsUnknownButDistinctFromTop) {
  AbsVal v = AbsVal::Bottom();
  EXPECT_TRUE(v.is_bottom());
  EXPECT_TRUE(v.is_unknown());
  EXPECT_FALSE(v.is_top());
  EXPECT_NE(v, AbsVal::Top());
}

TEST(AbsValTest, CfaRelAndOrigRegAreConcreteNotUnknown) {
  AbsVal cfa = AbsVal::CfaRel(-16);
  EXPECT_TRUE(cfa.IsCfaRel(-16));
  EXPECT_FALSE(cfa.IsCfaRel(-8));
  EXPECT_FALSE(cfa.is_unknown());

  AbsVal orig = AbsVal::OrigReg(kDwarfRbx);
  EXPECT_TRUE(orig.IsOrigReg(kDwarfRbx));
  EXPECT_FALSE(orig.IsOrigReg(kDwarfRax));
  EXPECT_FALSE(orig.is_unknown());
}

TEST(AbsValTest, EqualityDistinguishesEveryKind) {
  EXPECT_NE(AbsVal::Top(), AbsVal::Bottom());
  EXPECT_NE(AbsVal::Top(), AbsVal::CfaRel(0));
  EXPECT_NE(AbsVal::Bottom(), AbsVal::CfaRel(0));
  EXPECT_NE(AbsVal::CfaRel(8), AbsVal::CfaRel(-8));
  EXPECT_NE(AbsVal::OrigReg(kDwarfRax), AbsVal::OrigReg(kDwarfRbx));
  EXPECT_NE(AbsVal::CfaRel(0), AbsVal::OrigReg(kDwarfRax));
  EXPECT_EQ(AbsVal::Bottom(), AbsVal::Bottom());
}

TEST(AbsValTest, ToStringNamesTopAndBottomDistinctly) {
  EXPECT_EQ(AbsVal::Top().ToString(), "unknown");
  EXPECT_EQ(AbsVal::Bottom().ToString(), "conflict");
  EXPECT_EQ(AbsVal::CfaRel(8).ToString(), "CFA+8");
  EXPECT_EQ(AbsVal::CfaRel(-16).ToString(), "CFA-16");
  EXPECT_EQ(AbsVal::OrigReg(kDwarfRbx).ToString(), "entry rbx");
}

// --- AbsState::Entry --------------------------------------------------

TEST(AbsStateTest, EntryStateIsTheCanonicalCallFrame) {
  AbsState s = AbsState::Entry();
  EXPECT_TRUE(s.reg(kDwarfRsp).IsCfaRel(-8));
  EXPECT_TRUE(s.reg(kDwarfRbx).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDwarfRip));
  EXPECT_TRUE(s.Slot(-16).is_unknown());
}

TEST(AbsStateTest, EntryStateGivesEveryOtherGprItsOwnOriginalValue) {
  AbsState s = AbsState::Entry();
  for (int r = 0; r < kNumGpRegs; r++) {
    if (r == kDwarfRsp) {
      continue;
    }
    EXPECT_TRUE(s.reg(r).IsOrigReg(r)) << "register " << r;
  }
}

// --- Slot / SetSlot ---------------------------------------------------

TEST(AbsStateTest, SlotDefaultsToTopWhenNeverSet) {
  AbsState s;
  EXPECT_TRUE(s.Slot(-8).is_top());
}

TEST(AbsStateTest, SetSlotStoresAConcreteValueAndReadsItBack) {
  AbsState s;
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDwarfRbx));
}

TEST(AbsStateTest, SetSlotWithTopErasesRatherThanStoring) {
  // Slot() already reads an absent key as top, so a stored kTop entry
  // would be redundant -- SetSlot keeps the map from ever holding one.
  AbsState s;
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  s.SetSlot(-16, AbsVal::Top());
  EXPECT_TRUE(s.Slot(-16).is_top());
  EXPECT_EQ(s.slots.count(-16), 0u);
}

TEST(AbsStateTest, SetSlotWithBottomIsStoredExplicitly) {
  // Unlike top, bottom is a fact about the slot (a recorded conflict),
  // not the absence of one, so it must actually live in the map.
  AbsState s;
  s.SetSlot(-16, AbsVal::Bottom());
  EXPECT_TRUE(s.Slot(-16).is_bottom());
  EXPECT_EQ(s.slots.count(-16), 1u);
}

// --- ClobberReg ---------------------------------------------------------

TEST(AbsStateTest, ClobberRegDropsToTop) {
  AbsState s = AbsState::Entry();
  s.ClobberReg(kDwarfRax);
  EXPECT_TRUE(s.reg(kDwarfRax).is_top());
}

// --- DropSlotsBelow / DropDeadSlots --------------------------------------

TEST(AbsStateTest, DroppingDeadSlotsSparesTheRedZone) {
  // GCC leaves a register's DW_CFA_offset rule in force after the pop
  // that restored it. That is safe because the kernel honours the red
  // zone, and the checker has to agree or it flags every function.
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  s.SetSlot(-400, AbsVal::OrigReg(kDwarfRbp));
  s.DropDeadSlots(-8);
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDwarfRbx)) << "within the red zone, still readable";
  EXPECT_TRUE(s.Slot(-400).is_top()) << "far below the stack pointer, genuinely gone";
}

TEST(AbsStateTest, DropSlotsBelowIsExactForCalls) {
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  s.DropSlotsBelow(-8);
  EXPECT_TRUE(s.Slot(-16).is_top()) << "no red zone survives a call";
}

TEST(AbsStateTest, DropSlotsBelowKeepsTheBoundarySlot) {
  AbsState s;
  s.SetSlot(-8, AbsVal::OrigReg(kDwarfRbx));
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbp));
  s.DropSlotsBelow(-8);
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDwarfRbx)) << "exactly at the new rsp, not below it";
  EXPECT_TRUE(s.Slot(-16).is_top()) << "strictly below the new rsp";
}

TEST(AbsStateTest, DropDeadSlotsKeepsTheRedZoneBoundarySlot) {
  AbsState s;
  s.SetSlot(-8 - AbsState::kRedZoneBytes, AbsVal::OrigReg(kDwarfRbx));
  s.SetSlot(-9 - AbsState::kRedZoneBytes, AbsVal::OrigReg(kDwarfRbp));
  s.DropDeadSlots(-8);
  EXPECT_TRUE(s.Slot(-8 - AbsState::kRedZoneBytes).IsOrigReg(kDwarfRbx)) << "last byte the red zone still covers";
  EXPECT_TRUE(s.Slot(-9 - AbsState::kRedZoneBytes).is_top()) << "one byte past the red zone";
}

// --- Join: registers, one case per lattice combination -------------------

TEST(AbsStateTest, JoinKeepsAgreementAndDropsDisagreement) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  b.SetReg(kDwarfRbx, AbsVal::CfaRel(-32));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRbx).is_bottom());
  EXPECT_TRUE(a.reg(kDwarfRsp).IsCfaRel(-8)) << "agreeing components must survive";
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, kDwarfRbx);
}

TEST(AbsStateTest, JoinReportsRatherThanSilentlyWidening) {
  // The whole point of the merge operator: two paths computing different
  // stack pointers is the signal, so it must not be swallowed.
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  a.SetReg(kDwarfRsp, AbsVal::CfaRel(-16));
  b.SetReg(kDwarfRsp, AbsVal::CfaRel(-24));

  std::vector<JoinConflict> conflicts;
  Join(b, &a, &conflicts);
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, kDwarfRsp);
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("CFA-16"));
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("CFA-24"));
}

TEST(AbsStateTest, JoinIsIdempotentOnceWidened) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  b.SetReg(kDwarfRbx, AbsVal::CfaRel(-32));
  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  // Second time round nothing moves, which is what terminates the
  // worklist.
  EXPECT_FALSE(Join(b, &a, &conflicts));
}

TEST(AbsStateTest, JoinTopIsTheIdentityElementForRegisters) {
  AbsState a;  // every gpr defaults to top
  AbsState b;
  b.SetReg(kDwarfRax, AbsVal::CfaRel(8));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).IsCfaRel(8));
  EXPECT_TRUE(conflicts.empty()) << "top contributes no claim, so there is nothing to disagree about";
}

TEST(AbsStateTest, JoinLeavesAConcreteRegisterAloneWhenIncomingIsTop) {
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::CfaRel(8));
  AbsState b;  // top

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).IsCfaRel(8));
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinBottomRegisterAbsorbsAnIncomingTop) {
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::Bottom());
  AbsState b;  // top

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).is_bottom());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinBottomRegisterAbsorbsAnIncomingConcreteValue) {
  // Once a register is flagged as conflicting it must not be quietly
  // overwritten by whatever a later, unrelated predecessor claims.
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::Bottom());
  AbsState b;
  b.SetReg(kDwarfRax, AbsVal::CfaRel(8));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).is_bottom());
  EXPECT_TRUE(conflicts.empty()) << "not a fresh disagreement -- it was already recorded";
}

TEST(AbsStateTest, JoinPropagatesAnIncomingBottomRegisterWithoutReReporting) {
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::CfaRel(8));
  AbsState b;
  b.SetReg(kDwarfRax, AbsVal::Bottom());

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).is_bottom());
  EXPECT_TRUE(conflicts.empty()) << "the conflict was already reported at the join that produced the bottom";
}

TEST(AbsStateTest, JoinDoesNotReReportAFreshDisagreementAfterGoingBottom) {
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::CfaRel(8));
  AbsState b;
  b.SetReg(kDwarfRax, AbsVal::CfaRel(16));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_TRUE(a.reg(kDwarfRax).is_bottom());

  // A third, differently-concrete predecessor arrives at the same PC.
  AbsState c;
  c.SetReg(kDwarfRax, AbsVal::CfaRel(24));
  EXPECT_FALSE(Join(c, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRax).is_bottom());
  EXPECT_EQ(conflicts.size(), 1u) << "still just the first conflict -- bottom already said everything";
}

// --- Join: stack slots, one case per lattice combination -----------------

TEST(AbsStateTest, JoinSlotsAgreeAndSurvive) {
  AbsState a;
  AbsState b;
  a.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  b.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinKeepsASlotOnlyStateNames) {
  // Absent on the incoming side reads as that side's top, and top is
  // the meet's identity element.
  AbsState a;
  AbsState b;
  a.SetSlot(-24, AbsVal::OrigReg(kDwarfRbp));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-24).IsOrigReg(kDwarfRbp));
}

TEST(AbsStateTest, JoinImportsASlotOnlyIncomingNames) {
  AbsState a;
  AbsState b;
  b.SetSlot(-24, AbsVal::OrigReg(kDwarfRbp));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-24).IsOrigReg(kDwarfRbp));
}

TEST(AbsStateTest, JoinSlotsDisagreeAndDropToBottom) {
  AbsState a;
  AbsState b;
  a.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  b.SetSlot(-16, AbsVal::OrigReg(kDwarfRbp));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).is_bottom());
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, JoinConflict::kSlotConflict);
  EXPECT_EQ(conflicts[0].offset, -16);
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("stack slot"));
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("CFA-16"));
}

TEST(AbsStateTest, JoinBottomSlotAbsorbsAnIncomingConcreteValue) {
  AbsState a;
  a.SetSlot(-16, AbsVal::Bottom());
  AbsState b;
  b.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).is_bottom());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinBottomSlotSurvivesEvenWhenIncomingLacksIt) {
  // The bottom-stays-bottom check must run before the "only state names
  // it" survival check, or a later predecessor that never touched this
  // slot would look like it revives the slot to top.
  AbsState a;
  a.SetSlot(-16, AbsVal::Bottom());
  AbsState b;

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).is_bottom());
}

TEST(AbsStateTest, JoinPropagatesAnIncomingBottomSlotWithoutReReporting) {
  AbsState a;
  a.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  AbsState b;
  b.SetSlot(-16, AbsVal::Bottom());

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).is_bottom());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinImportsABottomSlotOnlyIncomingNames) {
  AbsState a;
  AbsState b;
  b.SetSlot(-16, AbsVal::Bottom());

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).is_bottom());
  EXPECT_TRUE(conflicts.empty());
}

// --- Join: order independence --------------------------------------------

TEST(AbsStateTest, JoinOrderDoesNotMatterForRegisters) {
  AbsState a;
  a.SetReg(kDwarfRax, AbsVal::CfaRel(8));                // concrete only on a
  a.SetReg(kDwarfRbx, AbsVal::Bottom());                 // already conflicting on a
  a.SetReg(kDwarfRcx, AbsVal::OrigReg(kDwarfRcx));       // agrees with b
  a.SetReg(kDwarfRdx, AbsVal::CfaRel(-16));              // disagrees with b
  // kDwarfRsi left at top on a.

  AbsState b;
  b.SetReg(kDwarfRbx, AbsVal::CfaRel(0));                // concrete meeting a's bottom
  b.SetReg(kDwarfRcx, AbsVal::OrigReg(kDwarfRcx));
  b.SetReg(kDwarfRdx, AbsVal::CfaRel(-24));
  b.SetReg(kDwarfRsi, AbsVal::CfaRel(32));               // concrete only on b

  AbsState merged_a_into_b = b;
  std::vector<JoinConflict> conflicts_a_into_b;
  Join(a, &merged_a_into_b, &conflicts_a_into_b);

  AbsState merged_b_into_a = a;
  std::vector<JoinConflict> conflicts_b_into_a;
  Join(b, &merged_b_into_a, &conflicts_b_into_a);

  EXPECT_EQ(merged_a_into_b, merged_b_into_a);
  EXPECT_EQ(conflicts_a_into_b.size(), conflicts_b_into_a.size());
}

TEST(AbsStateTest, JoinOrderDoesNotMatterForSlots) {
  AbsState a;
  a.SetSlot(-8, AbsVal::OrigReg(kDwarfRbx));    // only on a
  a.SetSlot(-16, AbsVal::Bottom());             // already conflicting on a
  a.SetSlot(-24, AbsVal::OrigReg(kDwarfRbp));   // agrees with b
  a.SetSlot(-32, AbsVal::CfaRel(-40));          // disagrees with b

  AbsState b;
  b.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));   // concrete meeting a's bottom
  b.SetSlot(-24, AbsVal::OrigReg(kDwarfRbp));
  b.SetSlot(-32, AbsVal::CfaRel(-48));
  b.SetSlot(-40, AbsVal::OrigReg(12));          // r12, only on b

  AbsState merged_a_into_b = b;
  std::vector<JoinConflict> conflicts_a_into_b;
  Join(a, &merged_a_into_b, &conflicts_a_into_b);

  AbsState merged_b_into_a = a;
  std::vector<JoinConflict> conflicts_b_into_a;
  Join(b, &merged_b_into_a, &conflicts_b_into_a);

  EXPECT_EQ(merged_a_into_b, merged_b_into_a);
  EXPECT_EQ(conflicts_a_into_b.size(), conflicts_b_into_a.size());
}

// --- SeedFromRow -----------------------------------------------------

TEST(AbsStateTest, SeedFromRowReproducesEntryForACanonicalRow) {
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 8};
  row.regs[kDwarfRip] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -8};
  EXPECT_EQ(AbsState::SeedFromRow(row, /*at_function_entry=*/true), AbsState::Entry());
}

TEST(AbsStateTest, SeedFromRowHandlesAFragmentStartingMidFrame) {
  // Cold fragments split out of a function get their own FDE, and it
  // starts with registers already spilled and rsp well below the CFA.
  // A `.cold` fragment is reached by a jump after the hot part has
  // already run, never by a call, so this is not function entry.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 32};
  row.regs[kDwarfRip] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -8};
  row.regs[kDwarfRbx] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -24};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRsp).IsCfaRel(-32));
  EXPECT_TRUE(s.Slot(-24).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDwarfRip));
  EXPECT_TRUE(s.reg(kDwarfRax).is_top())
      << "unmentioned mid-function: the CFI's silence about rax doesn't mean it still holds its entry value";
}

TEST(AbsStateTest, SeedFromRowAtEntryTrustsUnmentionedRegistersAsOriginal) {
  // At a genuine function entry nothing has executed yet, so a register
  // the row says nothing about trivially still holds what the caller
  // passed in -- the same fact Entry() assumes outright.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 8};
  row.regs[kDwarfRip] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -8};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/true);
  EXPECT_TRUE(s.reg(kDwarfRax).IsOrigReg(kDwarfRax));
  EXPECT_TRUE(s.reg(kDwarfRbx).IsOrigReg(kDwarfRbx));
}

TEST(AbsStateTest, SeedFromRowAwayFromEntryTrustsAnExplicitSameValueRule) {
  // RegRule::Kind::kSameValue is a real CFI assertion (DW_CFA_same_value),
  // not silence, so it is trusted even off the entry path -- e.g. a
  // landing pad whose CFI says a callee-saved register never moved.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 32};
  row.regs[kDwarfRbx] = RegRule{RegRule::Kind::kSameValue, 0, 0};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRbx).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(s.reg(kDwarfRax).is_top()) << "rax is merely unmentioned, not asserted same-value";
}

TEST(AbsStateTest, SeedFromRowHandlesAValOffsetRule) {
  // kValOffset means the register's value *is* CFA+offset -- the DRAP
  // pattern, among others -- distinct from kAtCfaOffset, where the
  // register is merely *saved* there.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 16};
  row.regs[kDwarfRax] = RegRule{RegRule::Kind::kValOffset, 0, -16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRax).IsCfaRel(-16));
}

TEST(AbsStateTest, SeedFromRowHandlesAnInRegisterRule) {
  // DW_CFA_register: rbp's caller-entry value was moved into rax.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 16};
  row.regs[kDwarfRbp] = RegRule{RegRule::Kind::kInRegister, kDwarfRax, 0};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRax).IsOrigReg(kDwarfRbp));
}

TEST(AbsStateTest, SeedFromRowTreatsUndefinedAndExpressionRulesAsTopRegardlessOfEntry) {
  for (bool at_entry : {true, false}) {
    CfiRow row;
    row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 16};
    row.regs[kDwarfRax] = RegRule{RegRule::Kind::kUndefined, 0, 0};
    row.regs[kDwarfRbx] = RegRule{RegRule::Kind::kExpression, 0, 0};
    row.regs[kDwarfRcx] = RegRule{RegRule::Kind::kValExpression, 0, 0};

    AbsState s = AbsState::SeedFromRow(row, at_entry);
    EXPECT_TRUE(s.reg(kDwarfRax).is_top()) << "at_function_entry=" << at_entry;
    EXPECT_TRUE(s.reg(kDwarfRbx).is_top()) << "at_function_entry=" << at_entry;
    EXPECT_TRUE(s.reg(kDwarfRcx).is_top()) << "at_function_entry=" << at_entry;
  }
}

TEST(AbsStateTest, SeedFromRowLetsTheCfaRuleOverrideAnUnmentionedRegister) {
  // The CFA rule is applied last precisely so it wins for its own
  // register, even though that register's own RegRule (if any) is
  // processed earlier in the same loop.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRbp, 16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRbp).IsCfaRel(-16)) << "the CFA rule, not the (absent) per-register rule, wins";
}

TEST(AbsStateTest, SeedFromRowLeavesRspTopWhenTheCfaIsNotRspBased) {
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRbp, 16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDwarfRsp).is_top()) << "nothing anchors rsp when the CFA is based on another register";
}

TEST(AbsStateTest, SeedFromRowRefusesToGuessWhenTheCfaIsAnExpression) {
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kExpression, 0, 0};
  EXPECT_TRUE(AbsState::SeedFromRow(row, /*at_function_entry=*/true).reg(kDwarfRsp).is_top());
}

}  // namespace
}  // namespace unwind_analysis

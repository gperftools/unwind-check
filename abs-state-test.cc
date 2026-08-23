/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include <optional>
#include <vector>

#include "absl/strings/str_cat.h"
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
  EXPECT_FALSE(v.IsCFARel(0));
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

TEST(AbsValTest, CFARelAndOrigRegAreConcreteNotUnknown) {
  AbsVal cfa = AbsVal::CFARel(-16);
  EXPECT_TRUE(cfa.IsCFARel(-16));
  EXPECT_FALSE(cfa.IsCFARel(-8));
  EXPECT_FALSE(cfa.is_unknown());

  AbsVal orig = AbsVal::OrigReg(kDWARFRbx);
  EXPECT_TRUE(orig.IsOrigReg(kDWARFRbx));
  EXPECT_FALSE(orig.IsOrigReg(kDWARFRax));
  EXPECT_FALSE(orig.is_unknown());
}

TEST(AbsValTest, EqualityDistinguishesEveryKind) {
  EXPECT_NE(AbsVal::Top(), AbsVal::Bottom());
  EXPECT_NE(AbsVal::Top(), AbsVal::CFARel(0));
  EXPECT_NE(AbsVal::Bottom(), AbsVal::CFARel(0));
  EXPECT_NE(AbsVal::CFARel(8), AbsVal::CFARel(-8));
  EXPECT_NE(AbsVal::OrigReg(kDWARFRax), AbsVal::OrigReg(kDWARFRbx));
  EXPECT_NE(AbsVal::CFARel(0), AbsVal::OrigReg(kDWARFRax));
  EXPECT_EQ(AbsVal::Bottom(), AbsVal::Bottom());
}

TEST(AbsValTest, StringifyNamesTopAndBottomDistinctly) {
  EXPECT_EQ(absl::StrCat(AbsVal::Top()), "unknown");
  EXPECT_EQ(absl::StrCat(AbsVal::Bottom()), "conflict");
  EXPECT_EQ(absl::StrCat(AbsVal::CFARel(8)), "CFA+8");
  EXPECT_EQ(absl::StrCat(AbsVal::CFARel(-16)), "CFA-16");
  EXPECT_EQ(absl::StrCat(AbsVal::OrigReg(kDWARFRbx)), "entry rbx");
  EXPECT_EQ(absl::StrCat(AbsVal::Other()), "an unrelated value");
}

// --- AbsState::Entry --------------------------------------------------

TEST(AbsStateTest, EntryStateIsTheCanonicalCallFrame) {
  AbsState s = AbsState::Entry();
  EXPECT_TRUE(s.reg(kDWARFRsp).IsCFARel(-8));
  EXPECT_TRUE(s.reg(kDWARFRbx).IsOrigReg(kDWARFRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDWARFRip));
  EXPECT_TRUE(s.Slot(-16).is_unknown());
}

TEST(AbsStateTest, EntryStateGivesEveryOtherGprItsOwnOriginalValue) {
  AbsState s = AbsState::Entry();
  for (int r = 0; r < kNumGPRs; r++) {
    if (r == kDWARFRsp) {
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
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDWARFRbx));
}

TEST(AbsStateTest, SetSlotWithTopErasesRatherThanStoring) {
  // Slot() already reads an absent key as top, so a stored kTop entry
  // would be redundant -- SetSlot keeps the map from ever holding one.
  AbsState s;
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
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
  s.ClobberReg(kDWARFRax);
  EXPECT_TRUE(s.reg(kDWARFRax).is_top());
}

// --- DropSlotsBelow / DropDeadSlots --------------------------------------

TEST(AbsStateTest, DroppingDeadSlotsSparesTheRedZone) {
  // GCC leaves a register's DW_CFA_offset rule in force after the pop
  // that restored it. That is safe because the kernel honours the red
  // zone, and the checker has to agree or it flags every function.
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  s.SetSlot(-400, AbsVal::OrigReg(kDWARFRbp));
  s.DropDeadSlots(-8);
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDWARFRbx)) << "within the red zone, still readable";
  EXPECT_TRUE(s.Slot(-400).is_top()) << "far below the stack pointer, genuinely gone";
}

TEST(AbsStateTest, DropSlotsBelowIsExactForCalls) {
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  s.DropSlotsBelow(-8);
  EXPECT_TRUE(s.Slot(-16).is_top()) << "no red zone survives a call";
}

TEST(AbsStateTest, DropSlotsBelowKeepsTheBoundarySlot) {
  AbsState s;
  s.SetSlot(-8, AbsVal::OrigReg(kDWARFRbx));
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbp));
  s.DropSlotsBelow(-8);
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDWARFRbx)) << "exactly at the new rsp, not below it";
  EXPECT_TRUE(s.Slot(-16).is_top()) << "strictly below the new rsp";
}

TEST(AbsStateTest, DropDeadSlotsKeepsTheRedZoneBoundarySlot) {
  AbsState s;
  s.SetSlot(-8 - AbsState::kRedZoneBytes, AbsVal::OrigReg(kDWARFRbx));
  s.SetSlot(-9 - AbsState::kRedZoneBytes, AbsVal::OrigReg(kDWARFRbp));
  s.DropDeadSlots(-8);
  EXPECT_TRUE(s.Slot(-8 - AbsState::kRedZoneBytes).IsOrigReg(kDWARFRbx)) << "last byte the red zone still covers";
  EXPECT_TRUE(s.Slot(-9 - AbsState::kRedZoneBytes).is_top()) << "one byte past the red zone";
}

TEST(AbsStateTest, SetRegRspAutomaticallyDropsDeadSlots) {
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  s.SetSlot(-400, AbsVal::OrigReg(kDWARFRbp));
  s.SetReg(kDWARFRsp, AbsVal::CFARel(-8));
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDWARFRbx));
  EXPECT_TRUE(s.Slot(-400).is_top());
}

// --- Join: registers, one case per lattice combination -------------------

TEST(AbsStateTest, JoinKeepsAgreementAndDropsDisagreement) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  b.SetReg(kDWARFRbx, AbsVal::CFARel(-32));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRbx).is_bottom());
  EXPECT_TRUE(a.reg(kDWARFRsp).IsCFARel(-8)) << "agreeing components must survive";
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, kDWARFRbx);
}

TEST(AbsStateTest, JoinReportsRatherThanSilentlyWidening) {
  // The whole point of the merge operator: two paths computing different
  // stack pointers is the signal, so it must not be swallowed.
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  a.SetReg(kDWARFRsp, AbsVal::CFARel(-16));
  b.SetReg(kDWARFRsp, AbsVal::CFARel(-24));

  std::vector<JoinConflict> conflicts;
  Join(b, &a, &conflicts);
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, kDWARFRsp);
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("CFA-16"));
  EXPECT_THAT(conflicts[0].Describe(), testing::HasSubstr("CFA-24"));
}

TEST(AbsStateTest, JoinIsIdempotentOnceWidened) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  b.SetReg(kDWARFRbx, AbsVal::CFARel(-32));
  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  // Second time round nothing moves, which is what terminates the
  // worklist.
  EXPECT_FALSE(Join(b, &a, &conflicts));
}

TEST(AbsStateTest, JoinTopIsTheIdentityElementForRegisters) {
  AbsState a;  // every gpr defaults to top
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::CFARel(8));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).IsCFARel(8));
  EXPECT_TRUE(conflicts.empty()) << "top contributes no claim, so there is nothing to disagree about";
}

TEST(AbsStateTest, JoinLeavesAConcreteRegisterAloneWhenIncomingIsTop) {
  AbsState a;
  a.SetReg(kDWARFRax, AbsVal::CFARel(8));
  AbsState b;  // top

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).IsCFARel(8));
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinBottomRegisterAbsorbsAnIncomingTop) {
  AbsState a;
  a.SetReg(kDWARFRax, AbsVal::Bottom());
  AbsState b;  // top

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinBottomRegisterAbsorbsAnIncomingConcreteValue) {
  // Once a register is flagged as conflicting it must not be quietly
  // overwritten by whatever a later, unrelated predecessor claims.
  AbsState a;
  a.SetReg(kDWARFRax, AbsVal::Bottom());
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::CFARel(8));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());
  EXPECT_TRUE(conflicts.empty()) << "not a fresh disagreement -- it was already recorded";
}

TEST(AbsStateTest, JoinPropagatesAnIncomingBottomRegisterWithoutReReporting) {
  AbsState a;
  a.SetReg(kDWARFRax, AbsVal::CFARel(8));
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::Bottom());

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());
  EXPECT_TRUE(conflicts.empty()) << "the conflict was already reported at the join that produced the bottom";
}

TEST(AbsStateTest, JoinDoesNotReReportAFreshDisagreementAfterGoingBottom) {
  AbsState a;
  a.SetReg(kDWARFRax, AbsVal::CFARel(8));
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::CFARel(16));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());

  // A third, differently-concrete predecessor arrives at the same PC.
  AbsState c;
  c.SetReg(kDWARFRax, AbsVal::CFARel(24));
  EXPECT_FALSE(Join(c, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());
  EXPECT_EQ(conflicts.size(), 1u) << "still just the first conflict -- bottom already said everything";
}

// --- Join: stack slots, one case per lattice combination -----------------

TEST(AbsStateTest, JoinSlotsAgreeAndSurvive) {
  AbsState a;
  AbsState b;
  a.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  b.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-16).IsOrigReg(kDWARFRbx));
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinKeepsASlotOnlyStateNames) {
  // Absent on the incoming side reads as that side's top, and top is
  // the meet's identity element.
  AbsState a;
  AbsState b;
  a.SetSlot(-24, AbsVal::OrigReg(kDWARFRbp));

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-24).IsOrigReg(kDWARFRbp));
}

TEST(AbsStateTest, JoinImportsASlotOnlyIncomingNames) {
  AbsState a;
  AbsState b;
  b.SetSlot(-24, AbsVal::OrigReg(kDWARFRbp));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.Slot(-24).IsOrigReg(kDWARFRbp));
}

TEST(AbsStateTest, JoinSlotsDisagreeAndDropToBottom) {
  AbsState a;
  AbsState b;
  a.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  b.SetSlot(-16, AbsVal::OrigReg(kDWARFRbp));

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
  b.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));

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
  a.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
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
  a.SetReg(kDWARFRax, AbsVal::CFARel(8));           // concrete only on a
  a.SetReg(kDWARFRbx, AbsVal::Bottom());            // already conflicting on a
  a.SetReg(kDWARFRcx, AbsVal::OrigReg(kDWARFRcx));  // agrees with b
  a.SetReg(kDWARFRdx, AbsVal::CFARel(-16));         // disagrees with b
  // kDWARFRsi left at top on a.

  AbsState b;
  b.SetReg(kDWARFRbx, AbsVal::CFARel(0));  // concrete meeting a's bottom
  b.SetReg(kDWARFRcx, AbsVal::OrigReg(kDWARFRcx));
  b.SetReg(kDWARFRdx, AbsVal::CFARel(-24));
  b.SetReg(kDWARFRsi, AbsVal::CFARel(32));  // concrete only on b

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
  a.SetSlot(-8, AbsVal::OrigReg(kDWARFRbx));   // only on a
  a.SetSlot(-16, AbsVal::Bottom());            // already conflicting on a
  a.SetSlot(-24, AbsVal::OrigReg(kDWARFRbp));  // agrees with b
  a.SetSlot(-32, AbsVal::CFARel(-40));         // disagrees with b

  AbsState b;
  b.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));  // concrete meeting a's bottom
  b.SetSlot(-24, AbsVal::OrigReg(kDWARFRbp));
  b.SetSlot(-32, AbsVal::CFARel(-48));
  b.SetSlot(-40, AbsVal::OrigReg(12));  // r12, only on b

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
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 8};
  row.regs[kDWARFRip] = RegRule{RegRule::Kind::kAtCFAOffset, 0, -8};
  EXPECT_EQ(AbsState::SeedFromRow(row, /*at_function_entry=*/true), AbsState::Entry());
}

TEST(AbsStateTest, SeedFromRowHandlesAFragmentStartingMidFrame) {
  // Cold fragments split out of a function get their own FDE, and it
  // starts with registers already spilled and rsp well below the CFA.
  // A `.cold` fragment is reached by a jump after the hot part has
  // already run, never by a call, so this is not function entry.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 32};
  row.regs[kDWARFRip] = RegRule{RegRule::Kind::kAtCFAOffset, 0, -8};
  row.regs[kDWARFRbx] = RegRule{RegRule::Kind::kAtCFAOffset, 0, -24};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRsp).IsCFARel(-32));
  EXPECT_TRUE(s.Slot(-24).IsOrigReg(kDWARFRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDWARFRip));
  EXPECT_TRUE(s.reg(kDWARFRax).is_top())
      << "unmentioned mid-function: the CFI's silence about rax doesn't mean it still holds its entry value";
}

TEST(AbsStateTest, SeedFromRowAtEntryTrustsUnmentionedRegistersAsOriginal) {
  // At a genuine function entry nothing has executed yet, so a register
  // the row says nothing about trivially still holds what the caller
  // passed in -- the same fact Entry() assumes outright.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 8};
  row.regs[kDWARFRip] = RegRule{RegRule::Kind::kAtCFAOffset, 0, -8};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/true);
  EXPECT_TRUE(s.reg(kDWARFRax).IsOrigReg(kDWARFRax));
  EXPECT_TRUE(s.reg(kDWARFRbx).IsOrigReg(kDWARFRbx));
}

TEST(AbsStateTest, SeedFromRowAwayFromEntryTrustsAnExplicitSameValueRule) {
  // RegRule::Kind::kSameValue is a real CFI assertion (DW_CFA_same_value),
  // not silence, so it is trusted even off the entry path -- e.g. a
  // landing pad whose CFI says a callee-saved register never moved.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 32};
  row.regs[kDWARFRbx] = RegRule{RegRule::Kind::kSameValue, 0, 0};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRbx).IsOrigReg(kDWARFRbx));
  EXPECT_TRUE(s.reg(kDWARFRax).is_top()) << "rax is merely unmentioned, not asserted same-value";
}

TEST(AbsStateTest, SeedFromRowHandlesAValOffsetRule) {
  // kValOffset means the register's value *is* CFA+offset -- the DRAP
  // pattern, among others -- distinct from kAtCFAOffset, where the
  // register is merely *saved* there.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 16};
  row.regs[kDWARFRax] = RegRule{RegRule::Kind::kValOffset, 0, -16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRax).IsCFARel(-16));
}

TEST(AbsStateTest, SeedFromRowHandlesAnInRegisterRule) {
  // DW_CFA_register: rbp's caller-entry value was moved into rax.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 16};
  row.regs[kDWARFRbp] = RegRule{RegRule::Kind::kInRegister, kDWARFRax, 0};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRax).IsOrigReg(kDWARFRbp));
}

TEST(AbsStateTest, SeedFromRowTreatsUndefinedAndExpressionRulesAsTopRegardlessOfEntry) {
  for (bool at_entry : {true, false}) {
    CFIRow row;
    row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRsp, 16};
    row.regs[kDWARFRax] = RegRule{RegRule::Kind::kUndefined, 0, 0};
    row.regs[kDWARFRbx] = RegRule{RegRule::Kind::kExpression, 0, 0};
    row.regs[kDWARFRcx] = RegRule{RegRule::Kind::kValExpression, 0, 0};

    AbsState s = AbsState::SeedFromRow(row, at_entry);
    EXPECT_TRUE(s.reg(kDWARFRax).is_top()) << "at_function_entry=" << at_entry;
    EXPECT_TRUE(s.reg(kDWARFRbx).is_top()) << "at_function_entry=" << at_entry;
    EXPECT_TRUE(s.reg(kDWARFRcx).is_top()) << "at_function_entry=" << at_entry;
  }
}

TEST(AbsStateTest, SeedFromRowLetsTheCFARuleOverrideAnUnmentionedRegister) {
  // The CFA rule is applied last precisely so it wins for its own
  // register, even though that register's own RegRule (if any) is
  // processed earlier in the same loop.
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRbp, 16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRbp).IsCFARel(-16)) << "the CFA rule, not the (absent) per-register rule, wins";
}

TEST(AbsStateTest, SeedFromRowLeavesRspTopWhenTheCFAIsNotRspBased) {
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kRegOffset, kDWARFRbp, 16};

  AbsState s = AbsState::SeedFromRow(row, /*at_function_entry=*/false);
  EXPECT_TRUE(s.reg(kDWARFRsp).is_top()) << "nothing anchors rsp when the CFA is based on another register";
}

// --- Join: the table lattice ----------------------------------------------

TEST(AbsStateTest, JoinOfDifferingTableValuesGivesUpWithoutAConflict) {
  // No CFI row ever asserts anything about a scratch register holding a
  // .rodata pointer, so two paths disagreeing about one is lost precision,
  // not the compiler-bug signal Join() otherwise reports.
  //
  // Note what makes that true now: on the CFI side both are kOther, which
  // compares *equal*, so there is nothing to disagree about and no
  // carve-out is needed to suppress a report. Only the table half gives up.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  AbsState b;
  b.SetTableReg(kDWARFRax, TableVal::Const(0x2000));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_EQ(a.reg(kDWARFRax).kind, AbsVal::Kind::kOther) << "still definitely not an entry value";
  EXPECT_TRUE(a.table(kDWARFRax).is_conflict()) << "not kNone: that is the identity element, see the next test";
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinOfATableEntryAndAJumpTargetAlsoGivesUpWithoutAConflict) {
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::TableEntry(0x1000, kDWARFRcx, 0x1000, kBoundTop));
  AbsState b;
  b.SetTableReg(kDWARFRax, TableVal::JumpTarget(0x2000, kDWARFRcx, kBoundTop));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.table(kDWARFRax).is_conflict());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, ATableValueSurvivesAPathThatKnowsNothingAboutIt) {
  // kNone is the identity element, so a predecessor carrying no table
  // information must leave a resolved dispatch standing rather than
  // destroying it. Getting this wrong loses real switch tables: /bin/ls's
  // main dispatch has a predecessor that never touched the index register.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::JumpTarget(0x1000, kDWARFRcx, 9));
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::Other());  // kOther on the CFI side, nothing on the table side

  std::vector<JoinConflict> conflicts;
  Join(b, &a, &conflicts);
  EXPECT_TRUE(a.table(kDWARFRax).IsJumpTarget()) << "the identity survives the identity element";
  EXPECT_EQ(a.table(kDWARFRax).table_bound, kBoundTop)
      << "the bound does not: the other path proved none, and bounds join by max";
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, ATableValueGivenUpOnIsNotResurrectedByAThirdPredecessor) {
  // The bug this guards against: if giving up landed on a state that then
  // acted as an identity element ("nothing known yet, adopt whatever
  // arrives"), a third predecessor showing up after the first two already
  // disagreed would be silently adopted, resurrecting a concrete value
  // after a real disagreement -- order-dependent and unsound.
  //
  // Which is why giving up lands on kConflict and not on kNone: kNone is
  // the identity element (see the test above), so a disagreement resolving
  // to it would be adopted right back out of. kConflict is absorbing.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  AbsState b;
  b.SetTableReg(kDWARFRax, TableVal::Const(0x2000));
  std::vector<JoinConflict> conflicts;
  ASSERT_TRUE(Join(b, &a, &conflicts));
  ASSERT_TRUE(a.table(kDWARFRax).is_conflict());

  AbsState c;
  c.SetTableReg(kDWARFRax, TableVal::Const(0x3000));
  EXPECT_FALSE(Join(c, &a, &conflicts));
  EXPECT_TRUE(a.table(kDWARFRax).is_conflict());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinOfATableValueAndAnUnrelatedConcreteValueStillConflicts) {
  // A table value meeting a kCFARel or kOrigReg is a normal disagreement
  // about something a CFI row may well consult, and must still be
  // reported -- the suppression above is only for two table values meeting
  // each other.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  AbsState b;
  b.SetReg(kDWARFRax, AbsVal::CFARel(-8));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDWARFRax).is_bottom());
  ASSERT_EQ(conflicts.size(), 1u);
  EXPECT_EQ(conflicts[0].reg, kDWARFRax);
}

TEST(AbsStateTest, JoinOfTwoJumpTargetsWithTheSameIdentityMergesJustTheBound) {
  // Same table, same index register, differing only in whether one side
  // also proved a numeric bound: this is the same fact, not a
  // disagreement, so the kJumpTarget identity must survive with the bound
  // widened to top.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::JumpTarget(0x1000, kDWARFRcx, 9));
  AbsState b;
  b.SetTableReg(kDWARFRax, TableVal::JumpTarget(0x1000, kDWARFRcx, kBoundTop));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.table(kDWARFRax).IsJumpTarget());
  EXPECT_EQ(a.table(kDWARFRax).TableAddr(), 0x1000u);
  EXPECT_FALSE(a.table(kDWARFRax).HasTableBound());
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, ATableHalfChangeAloneStillReportsTheJoinAsChanged) {
  // A table join that widens a bound without the successor being requeued
  // would leave it holding a *tighter* bound than the fixed point allows --
  // the direction that sizes a table too small and walks to wrong targets.
  AbsState a;
  a.ApplyGuardBound(kDWARFRax, 4);
  AbsState b;  // identical CFI half, no bound

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts)) << "the only difference is in the table half";
  EXPECT_EQ(a.table(kDWARFRax).value_bound, kBoundTop);
}

TEST(AbsStateTest, WritingARegisterClearsItsTableHalf) {
  // The invariant that makes the split safe to write against: a register
  // that gets a new value cannot keep a stale table identity or a bound
  // that described what used to be there.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  a.ApplyGuardBound(kDWARFRax, 4);
  a.SetReg(kDWARFRax, AbsVal::CFARel(-8));
  EXPECT_EQ(a.table(kDWARFRax).kind, TableVal::Kind::kNone);
  EXPECT_EQ(a.table(kDWARFRax).value_bound, kBoundTop);
}

TEST(AbsStateTest, CopyRegCarriesBothHalves) {
  // The one case where a value keeps its identity *and* its bounds: a
  // full-width register-to-register move.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  a.ApplyGuardBound(kDWARFRax, 4);
  a.CopyReg(kDWARFRcx, kDWARFRax);
  EXPECT_EQ(a.reg(kDWARFRcx).kind, AbsVal::Kind::kOther);
  EXPECT_TRUE(a.table(kDWARFRcx).IsConst());
  EXPECT_EQ(a.table(kDWARFRcx).table_bound, 4u);
}

// --- Join: per-value switch-table bounds (§3.2) ---------------------------

TEST(AbsStateTest, JoinKeepsABoundBothSidesAgreeOn) {
  AbsState a;
  a.ApplyGuardBound(kDWARFRax, 4);
  AbsState b;
  b.ApplyGuardBound(kDWARFRax, 4);

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_EQ(a.table(kDWARFRax).table_bound, 4u);
  EXPECT_EQ(a.table(kDWARFRax).value_bound, 4u);
}

TEST(AbsStateTest, JoinTakesTheWeakerOfTwoDisagreeingBoundsWithoutReportingAConflict) {
  // Two paths proving different bounds is not a conflict: it is two true
  // statements, and what survives the merge is the weaker one. Anything
  // tighter would claim a bound one incoming path never established.
  AbsState a;
  a.ApplyGuardBound(kDWARFRax, 4);
  AbsState b;
  b.ApplyGuardBound(kDWARFRax, 7);

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_EQ(a.table(kDWARFRax).table_bound, 7u);
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, JoinDropsABoundOnlyOneSideRecorded) {
  // A register bounded on only one incoming path is not really bounded
  // at the merged point: some other path reaches the same PC with no
  // guard at all. That is the same max rule as above -- the unbounded
  // side is kBoundTop, which max absorbs everything into.
  AbsState a;
  a.ApplyGuardBound(kDWARFRax, 4);
  AbsState b;  // no bound

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_FALSE(a.table(kDWARFRax).HasTableBound());
  EXPECT_EQ(a.table(kDWARFRax).value_bound, kBoundTop);
}

TEST(AbsStateTest, JoinReportsNoChangeWhenTwoBoundedTopsAlreadyAgreeOnTop) {
  // A join that lands back on exactly what was already there must not
  // report a change: `changed` requeues the successor, and a value that
  // reports one on every visit spins the worklist toward its iteration
  // cap for no new information.
  AbsState a;  // rax is an unbounded kTop
  AbsState b;
  b.ApplyValueBound(kDWARFRax, 4);  // a bounded kTop

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  EXPECT_EQ(a.table(kDWARFRax).value_bound, kBoundTop);
}

TEST(AbsStateTest, TwoDifferentSpilledTableValuesDoNotConflictInASlot) {
  // A dispatch scratch value that gets spilled must not produce a
  // spurious, CFI-irrelevant conflict just because it went through the
  // stack instead of staying in a register. This used to need a carve-out
  // in the join; now the two values are simply both kOther by the time
  // they reach a slot, so they compare equal and there is nothing to
  // suppress -- and the slot keeps a real fact ("not any entry value")
  // rather than degrading to kBottom.
  AbsState a;
  a.SetTableReg(kDWARFRax, TableVal::Const(0x1000));
  a.SetSlot(-24, a.reg(kDWARFRax));
  a.ClobberReg(kDWARFRax);  // the scratch register gets reused, as it would
  AbsState b;
  b.SetTableReg(kDWARFRax, TableVal::Const(0x2000));
  b.SetSlot(-24, b.reg(kDWARFRax));
  b.ClobberReg(kDWARFRax);

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts)) << "the spilled halves are indistinguishable, so nothing changes";
  EXPECT_EQ(a.Slot(-24).kind, AbsVal::Kind::kOther);
  EXPECT_TRUE(conflicts.empty());
}

TEST(AbsStateTest, ClobberRegClearsAPreviouslySetBound) {
  AbsState a;
  a.ApplyGuardBound(kDWARFRax, 4);
  a.ClobberReg(kDWARFRax);
  EXPECT_FALSE(a.table(kDWARFRax).HasTableBound());
  EXPECT_EQ(a.table(kDWARFRax).value_bound, kBoundTop);
}

TEST(AbsStateTest, WritingTheComparedRegisterInvalidatesLastCmp) {
  // `cmp $5,%eax; mov (%rbx),%rax; ja default` compares one rax and
  // branches on a different one. last_cmp names a register number, so
  // without this the guard would bound whatever landed there instead.
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 5};
  a.SetReg(kDWARFRax, AbsVal::CFARel(-8));
  EXPECT_FALSE(a.last_cmp.has_value());

  AbsState b;
  b.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 5};
  b.ClobberReg(kDWARFRax);
  EXPECT_FALSE(b.last_cmp.has_value());
}

TEST(AbsStateTest, WritingAnUnrelatedRegisterLeavesLastCmpAlone) {
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 5};
  a.SetReg(kDWARFRcx, AbsVal::CFARel(-8));
  ASSERT_TRUE(a.last_cmp.has_value());
  EXPECT_EQ(a.last_cmp->imm, 5u);
}

TEST(AbsStateTest, ApplyingABoundDoesNotInvalidateLastCmp) {
  // A bound update is not a value write: the guard conversion tightens
  // the very register last_cmp names, and must not shoot itself.
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 5};
  a.ApplyGuardBound(kDWARFRax, 5);
  EXPECT_TRUE(a.last_cmp.has_value());
}

// --- Join: last_cmp (§3.2) -------------------------------------------------

TEST(AbsStateTest, JoinKeepsLastCmpOnlyWhenBothSidesAgree) {
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 9};
  AbsState b;
  b.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 9};

  std::vector<JoinConflict> conflicts;
  EXPECT_FALSE(Join(b, &a, &conflicts));
  ASSERT_TRUE(a.last_cmp.has_value());
  EXPECT_EQ(a.last_cmp->width_bits, 32u);
  EXPECT_EQ(a.last_cmp->imm, 9u);
}

TEST(AbsStateTest, JoinDropsADisagreeingLastCmp) {
  // A bypassing predecessor that never ran the guard (last_cmp unset)
  // must clear it at the merge point: the guard does not dominate here,
  // so trusting it would be unsound, not merely imprecise.
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 9};
  AbsState b;  // no cmp on this path

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_FALSE(a.last_cmp.has_value());
}

TEST(AbsStateTest, JoinNeverResurrectsAnAlreadyClearedLastCmp) {
  AbsState a;
  a.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 9};
  AbsState b;
  std::vector<JoinConflict> conflicts;
  ASSERT_TRUE(Join(b, &a, &conflicts));
  ASSERT_FALSE(a.last_cmp.has_value());

  AbsState c;
  c.last_cmp = AbsState::FlagsGuard{kDWARFRax, 32, 9};  // even the same guard
  EXPECT_FALSE(Join(c, &a, &conflicts));
  EXPECT_FALSE(a.last_cmp.has_value());
}

TEST(AbsStateTest, SeedFromRowRefusesToGuessWhenTheCFAIsAnExpression) {
  CFIRow row;
  row.cfa = CFARule{CFARule::Kind::kExpression, 0, 0};
  EXPECT_TRUE(AbsState::SeedFromRow(row, /*at_function_entry=*/true).reg(kDWARFRsp).is_top());
}

}  // namespace
}  // namespace unwind_analysis

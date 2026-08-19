/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "abs-state.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

TEST(AbsStateTest, EntryStateIsTheCanonicalCallFrame) {
  AbsState s = AbsState::Entry();
  EXPECT_TRUE(s.reg(kDwarfRsp).IsCfaRel(-8));
  EXPECT_TRUE(s.reg(kDwarfRbx).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDwarfRip));
  EXPECT_TRUE(s.Slot(-16).is_unknown());
}

TEST(AbsStateTest, JoinKeepsAgreementAndDropsDisagreement) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  b.SetReg(kDwarfRbx, AbsVal::CfaRel(-32));

  std::vector<JoinConflict> conflicts;
  EXPECT_TRUE(Join(b, &a, &conflicts));
  EXPECT_TRUE(a.reg(kDwarfRbx).is_unknown());
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

TEST(AbsStateTest, JoinIntersectsSlots) {
  AbsState a = AbsState::Entry();
  AbsState b = AbsState::Entry();
  a.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  b.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  a.SetSlot(-24, AbsVal::OrigReg(kDwarfRbp));  // only on one side

  std::vector<JoinConflict> conflicts;
  Join(b, &a, &conflicts);
  EXPECT_TRUE(a.Slot(-16).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(a.Slot(-24).is_unknown());
}

TEST(AbsStateTest, DroppingDeadSlotsSparesTheRedZone) {
  // GCC leaves a register's DW_CFA_offset rule in force after the pop
  // that restored it. That is safe because the kernel honours the red
  // zone, and the checker has to agree or it flags every function.
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  s.SetSlot(-400, AbsVal::OrigReg(kDwarfRbp));
  s.DropDeadSlots(-8);
  EXPECT_TRUE(s.Slot(-16).IsOrigReg(kDwarfRbx)) << "within the red zone, still readable";
  EXPECT_TRUE(s.Slot(-400).is_unknown()) << "far below the stack pointer, genuinely gone";
}

TEST(AbsStateTest, DropSlotsBelowIsExactForCalls) {
  AbsState s = AbsState::Entry();
  s.SetSlot(-16, AbsVal::OrigReg(kDwarfRbx));
  s.DropSlotsBelow(-8);
  EXPECT_TRUE(s.Slot(-16).is_unknown()) << "no red zone survives a call";
}

TEST(AbsStateTest, SeedFromRowReproducesEntryForACanonicalRow) {
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 8};
  row.regs[kDwarfRip] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -8};
  EXPECT_EQ(AbsState::SeedFromRow(row), AbsState::Entry());
}

TEST(AbsStateTest, SeedFromRowHandlesAFragmentStartingMidFrame) {
  // Cold fragments split out of a function get their own FDE, and it
  // starts with registers already spilled and rsp well below the CFA.
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kRegOffset, kDwarfRsp, 32};
  row.regs[kDwarfRip] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -8};
  row.regs[kDwarfRbx] = RegRule{RegRule::Kind::kAtCfaOffset, 0, -24};

  AbsState s = AbsState::SeedFromRow(row);
  EXPECT_TRUE(s.reg(kDwarfRsp).IsCfaRel(-32));
  EXPECT_TRUE(s.Slot(-24).IsOrigReg(kDwarfRbx));
  EXPECT_TRUE(s.Slot(-8).IsOrigReg(kDwarfRip));
}

TEST(AbsStateTest, SeedFromRowRefusesToGuessWhenTheCfaIsAnExpression) {
  CfiRow row;
  row.cfa = CfaRule{CfaRule::Kind::kExpression, 0, 0};
  EXPECT_TRUE(AbsState::SeedFromRow(row).reg(kDwarfRsp).is_unknown());
}

}  // namespace
}  // namespace unwind_analysis

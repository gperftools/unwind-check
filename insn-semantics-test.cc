/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "insn-semantics.h"

#include <initializer_list>
#include <vector>

#include "disasm.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

constexpr uint64_t kBase = 0x1000;

class SemanticsTest : public testing::Test {
 protected:
  void SetUp() override {
    absl::StatusOr<std::unique_ptr<Disassembler>> d = Disassembler::Create();
    ASSERT_TRUE(d.ok()) << d.status();
    disasm_ = std::move(*d);
    state_ = AbsState::Entry();
  }

  // Runs a literal instruction encoding through the transfer function.
  TransferOutcome Run(std::initializer_list<uint8_t> bytes) {
    std::vector<uint8_t> code{bytes};
    const Instruction* insn = disasm_->DecodeOne(code.data(), code.size(), kBase);
    EXPECT_NE(insn, nullptr) << "Zydis could not decode the test encoding";
    if (insn == nullptr) {
      return TransferOutcome{};
    }
    EXPECT_EQ(insn->size, code.size())
        << "test encoding is not exactly one instruction: " << Disassembler::Text(*insn);
    InsnSemantics semantics;
    return semantics.Transfer(*insn, &state_);
  }

  std::unique_ptr<Disassembler> disasm_;
  AbsState state_;
};

TEST_F(SemanticsTest, PushMovesTheStackPointerAndRecordsWhatWentThere) {
  Run({0x53});  // push %rbx
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-16));
  EXPECT_TRUE(state_.Slot(-16).IsOrigReg(kDWARFRbx));
}

TEST_F(SemanticsTest, PopRestoresTheRegisterItPushed) {
  Run({0x53});  // push %rbx
  state_.ClobberReg(kDWARFRbx);
  Run({0x5b});  // pop %rbx
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8));
  EXPECT_TRUE(state_.reg(kDWARFRbx).IsOrigReg(kDWARFRbx));
}

TEST_F(SemanticsTest, SubAndAddOnRspTrackTheFrame) {
  Run({0x48, 0x83, 0xec, 0x18});  // sub $0x18, %rsp
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-32));
  Run({0x48, 0x83, 0xc4, 0x18});  // add $0x18, %rsp
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8));
}

TEST_F(SemanticsTest, FramePointerSetupAndTeardown) {
  Run({0x55});              // push %rbp
  Run({0x48, 0x89, 0xe5});  // mov %rsp, %rbp
  EXPECT_TRUE(state_.reg(kDWARFRbp).IsCFARel(-16));
  Run({0x48, 0x83, 0xec, 0x20});  // sub $0x20, %rsp
  Run({0xc9});                    // leave
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8));
  EXPECT_TRUE(state_.reg(kDWARFRbp).IsOrigReg(kDWARFRbp));
}

TEST_F(SemanticsTest, MovSpillAndReloadThroughRsp) {
  Run({0x48, 0x83, 0xec, 0x18});        // sub $0x18, %rsp   -> rsp = CFA-32
  Run({0x48, 0x89, 0x5c, 0x24, 0x08});  // mov %rbx, 0x8(%rsp)
  EXPECT_TRUE(state_.Slot(-24).IsOrigReg(kDWARFRbx));
  state_.ClobberReg(kDWARFRbx);
  Run({0x48, 0x8b, 0x5c, 0x24, 0x08});  // mov 0x8(%rsp), %rbx
  EXPECT_TRUE(state_.reg(kDWARFRbx).IsOrigReg(kDWARFRbx));
}

TEST_F(SemanticsTest, LeaComputesAStackAddress) {
  Run({0x4c, 0x8d, 0x54, 0x24, 0x08});  // lea 0x8(%rsp), %r10
  EXPECT_TRUE(state_.reg(10).IsCFARel(0));
}

TEST_F(SemanticsTest, WritingASubRegisterUntracksTheWholeRegister) {
  Run({0x48, 0x89, 0xe3});  // mov %rsp, %rbx
  ASSERT_TRUE(state_.reg(kDWARFRbx).IsCFARel(-8));
  Run({0x31, 0xdb});  // xor %ebx, %ebx
  EXPECT_TRUE(state_.reg(kDWARFRbx).is_unknown());
}

TEST_F(SemanticsTest, StackRealignmentUntracksRspWithoutGuessing) {
  Run({0x55});                    // push %rbp
  Run({0x48, 0x89, 0xe5});        // mov %rsp, %rbp
  Run({0x48, 0x83, 0xe4, 0xf0});  // and $-16, %rsp
  EXPECT_TRUE(state_.reg(kDWARFRsp).is_unknown()) << "rsp is no longer CFA-relative";
  EXPECT_TRUE(state_.reg(kDWARFRbp).IsCFARel(-16)) << "an rbp-based CFA rule stays checkable";
}

TEST_F(SemanticsTest, CallClobbersCallerSavedRegistersAndTheStackBelowRsp) {
  Run({0x48, 0x83, 0xec, 0x08});  // sub $8, %rsp -> rsp = CFA-16
  state_.SetSlot(-24, AbsVal::OrigReg(kDWARFRbx));
  TransferOutcome out = Run({0xe8, 0x00, 0x00, 0x00, 0x00});  // call .+0
  EXPECT_TRUE(out.is_call);
  EXPECT_TRUE(out.falls_through);
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-16)) << "a call leaves rsp where it found it";
  EXPECT_TRUE(state_.reg(kDWARFRax).is_unknown());
  EXPECT_TRUE(state_.reg(kDWARFRbx).IsOrigReg(kDWARFRbx)) << "callee-saved survives";
  EXPECT_TRUE(state_.Slot(-24).is_unknown()) << "no red zone survives a call";
}

TEST_F(SemanticsTest, ClassifiesControlFlow) {
  {
    TransferOutcome out = Run({0xc3});  // ret
    EXPECT_TRUE(out.is_return);
    EXPECT_FALSE(out.falls_through);
  }
  {
    TransferOutcome out = Run({0xeb, 0x05});  // jmp .+7
    EXPECT_FALSE(out.falls_through);
    EXPECT_TRUE(out.has_direct_target);
    EXPECT_EQ(out.direct_target, kBase + 7);
  }
  {
    TransferOutcome out = Run({0x74, 0x05});  // je .+7
    EXPECT_TRUE(out.falls_through) << "a conditional branch also falls through";
    EXPECT_TRUE(out.has_direct_target);
    EXPECT_EQ(out.direct_target, kBase + 7);
  }
  {
    TransferOutcome out = Run({0xff, 0xe0});  // jmp *%rax
    EXPECT_TRUE(out.indirect_branch);
    EXPECT_FALSE(out.has_direct_target);
  }
}

TEST_F(SemanticsTest, UnmodelledInstructionsLoseTrackRatherThanLie) {
  Run({0x48, 0x89, 0xe3});  // mov %rsp, %rbx
  ASSERT_TRUE(state_.reg(kDWARFRbx).IsCFARel(-8));
  Run({0x48, 0x0f, 0xaf, 0xd8});  // imul %rax, %rbx -- not modelled
  EXPECT_TRUE(state_.reg(kDWARFRbx).is_unknown());
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8)) << "and leaves everything else alone";
}

// --- Switch-table resolution transfer rules -------------------------------

TEST_F(SemanticsTest, RipRelativeLeaProducesAConstant) {
  // lea 0x10(%rip),%rcx -- the table-base load. The target is relative
  // to the end of this instruction, not its start.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});
  ASSERT_TRUE(state_.reg(kDWARFRcx).IsConst());
  EXPECT_EQ(state_.reg(kDWARFRcx).ConstValue(), static_cast<int64_t>(kBase + 7 + 0x10));
}

TEST_F(SemanticsTest, MovslqWithScale4FromAConstantBaseProducesATableEntry) {
  // lea 0x10(%rip),%rcx ; movslq (%rcx,%rax,4),%rdx
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});
  int64_t table = state_.reg(kDWARFRcx).ConstValue();
  Run({0x48, 0x63, 0x14, 0x81});
  ASSERT_TRUE(state_.reg(kDWARFRdx).IsTableEntry());
  EXPECT_EQ(state_.reg(kDWARFRdx).TableAddr(), static_cast<uint64_t>(table));
  EXPECT_EQ(state_.reg(kDWARFRdx).IndexReg(), kDWARFRax);
  EXPECT_EQ(state_.reg(kDWARFRdx).TableBaseConst(), static_cast<uint64_t>(table));
}

TEST_F(SemanticsTest, AddResolvesATableEntryToAJumpTargetRegardlessOfOperandOrder) {
  // lea 0x10(%rip),%rcx ; movslq (%rcx,%rax,4),%rdx ; add %rcx,%rdx
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});
  int64_t table = state_.reg(kDWARFRcx).ConstValue();
  Run({0x48, 0x63, 0x14, 0x81});
  Run({0x48, 0x01, 0xca});  // add %rcx,%rdx
  ASSERT_TRUE(state_.reg(kDWARFRdx).IsJumpTarget());
  EXPECT_EQ(state_.reg(kDWARFRdx).TableAddr(), static_cast<uint64_t>(table));
  EXPECT_EQ(state_.reg(kDWARFRdx).IndexReg(), kDWARFRax);
}

TEST_F(SemanticsTest, AddDoesNotResolveWhenTheConstantDoesNotMatchTheTablesBase) {
  // A constant that was never the base the table entry was computed from
  // must not resolve -- this is the equality check the `add` handler
  // makes against kTableEntry's remembered base.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  Run({0x48, 0x63, 0x14, 0x81});                    // rdx = table_entry(table, index=rax)
  Run({0x48, 0xc7, 0xc3, 0x00, 0x10, 0x00, 0x00});  // mov $0x1000,%rbx -- unrelated constant
  Run({0x48, 0x01, 0xda});                          // add %rbx,%rdx
  EXPECT_FALSE(state_.reg(kDWARFRdx).IsJumpTarget());
}

TEST_F(SemanticsTest, IndirectJumpThroughAJumpTargetResolvesOnlyWithAKnownBound) {
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  Run({0x48, 0x63, 0x14, 0x81});                    // rdx = table_entry(table, index=rax)
  Run({0x48, 0x01, 0xca});                          // rdx = jump_target(table, index=rax)
  {
    TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx -- no bound on rax yet
    EXPECT_FALSE(out.has_jump_table);
    EXPECT_TRUE(out.indirect_branch);
  }
}

TEST_F(SemanticsTest, IndirectJumpResolvesOnceTheIndexRegisterHasAKnownBound) {
  // The bound is snapshotted at movslq-time (switch-table-amend-plan.md
  // §2), so it must be set on the index register before that instruction
  // runs -- a bound set afterwards, as this test used to do, is no longer
  // picked up, on purpose: the whole point is to stop the resolver from
  // re-reading AbsState::Bound live at the `jmp`.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  int64_t table = state_.reg(kDWARFRcx).ConstValue();
  state_.SetBound(kDWARFRax, 4);
  Run({0x48, 0x63, 0x14, 0x81});            // rdx = table_entry(table, index=rax), captures bound(rax)=4
  Run({0x48, 0x01, 0xca});                  // rdx = jump_target(table, index=rax), carries the captured bound
  TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx
  EXPECT_TRUE(out.has_jump_table);
  EXPECT_EQ(out.jump_table_addr, static_cast<uint64_t>(table));
  EXPECT_EQ(out.jump_table_entries, 5u);
}

TEST_F(SemanticsTest, IndirectJumpDoesNotResolveFromABoundSetAfterTheTableLoad) {
  // The mirror image of the test above: a live AbsState::Bound at the
  // `jmp` is deliberately no longer consulted, so a bound that only shows
  // up after the movslq/add sequence (e.g. from an unrelated guard that
  // happens to reuse the index register) must not resolve the table.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  Run({0x48, 0x63, 0x14, 0x81});                    // rdx = table_entry(table, index=rax), no bound yet
  Run({0x48, 0x01, 0xca});                          // rdx = jump_target(table, index=rax), still no bound
  state_.SetBound(kDWARFRax, 4);
  TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx
  EXPECT_FALSE(out.has_jump_table);
  EXPECT_TRUE(out.indirect_branch);
}

TEST_F(SemanticsTest, CmpWithANonNegativeImmediateSetsLastCmp) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->reg, kDWARFRax);
  EXPECT_EQ(state_.last_cmp->imm, 9u);
}

TEST_F(SemanticsTest, LastCmpIsClearedByALaterFlagsWritingInstruction) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  Run({0x83, 0xc0, 0x01});  // add $1,%eax -- also sets flags, but is not a guard
  EXPECT_FALSE(state_.last_cmp.has_value());
}

TEST_F(SemanticsTest, LastCmpSurvivesAnInstructionThatDoesNotTouchFlags) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  Run({0x89, 0xc1});  // mov %eax,%ecx -- does not write EFLAGS
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->imm, 9u);
}

TEST_F(SemanticsTest, MovzxCarriesTheSourcesBoundAcrossATruncatingWiden) {
  state_.SetBound(kDWARFRax, 9);
  Run({0x0f, 0xb6, 0xc8});  // movzbl %al,%ecx
  EXPECT_TRUE(state_.reg(kDWARFRcx).is_top()) << "the widened value's own identity does not survive the truncation";
  ASSERT_TRUE(state_.reg(kDWARFRcx).Bound().has_value());
  EXPECT_EQ(*state_.reg(kDWARFRcx).Bound(), 9u);
  EXPECT_EQ(state_.reg(kDWARFRax).Bound(), 9u) << "the source's own bound is untouched by a read";
}

TEST_F(SemanticsTest, NarrowCmpAndMovzxPropagatesBound) {
  Run({0x3c, 0x09});        // cmp $9, %al
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->reg, kDWARFRax);
  EXPECT_EQ(state_.last_cmp->width_bits, 8u);
  EXPECT_EQ(state_.last_cmp->imm, 9u);

  Run({0x0f, 0xb6, 0xc8});  // movzbl %al, %ecx
  ASSERT_TRUE(state_.reg(kDWARFRcx).Bound().has_value());
  EXPECT_EQ(*state_.reg(kDWARFRcx).Bound(), 9u);
}

TEST_F(SemanticsTest, NarrowCmpAndMovsxPropagatesBoundWhenSignBitIsZero) {
  Run({0x3c, 0x09});        // cmp $9, %al
  Run({0x0f, 0xbe, 0xc8});  // movsbl %al, %ecx
  ASSERT_TRUE(state_.reg(kDWARFRcx).Bound().has_value());
  EXPECT_EQ(*state_.reg(kDWARFRcx).Bound(), 9u);
}

TEST_F(SemanticsTest, NarrowCmpAndMovsxRejectsBoundWhenSignBitCanBeOne) {
  Run({0x3c, 0xc8});        // cmp $200, %al
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->imm, 200u);

  Run({0x0f, 0xbe, 0xc8});  // movsbl %al, %ecx
  EXPECT_FALSE(state_.reg(kDWARFRcx).Bound().has_value())
      << "sign extension from 200 (negative signed byte) must not propagate bound";
}

TEST_F(SemanticsTest, MovsxdCarriesBoundFrom32BitRegWhenNonNegative) {
  Run({0x83, 0xf8, 0x09});        // cmp $9, %eax
  Run({0x48, 0x63, 0xc8});        // movsxd %eax, %rcx
  ASSERT_TRUE(state_.reg(kDWARFRcx).Bound().has_value());
  EXPECT_EQ(*state_.reg(kDWARFRcx).Bound(), 9u);
}

TEST_F(SemanticsTest, LeaOnRspDropsDeadSlotsWhenMovingUp) {
  Run({0x48, 0x83, 0xec, 0x80});  // sub $128, %rsp
  state_.SetSlot(-300, AbsVal::OrigReg(kDWARFRbx));
  EXPECT_TRUE(state_.Slot(-300).IsOrigReg(kDWARFRbx));
  Run({0x48, 0x8d, 0x64, 0x24, 0x20});  // lea 0x20(%rsp), %rsp (moves rsp up by 32 bytes)
  EXPECT_TRUE(state_.Slot(-300).is_top()) << "slot far below red zone is dropped";
}

TEST_F(SemanticsTest, StoresThroughAnUntrackedPointerDoNotWipeTheFrame) {
  Run({0x53});  // push %rbx
  ASSERT_TRUE(state_.Slot(-16).IsOrigReg(kDWARFRbx));
  Run({0x48, 0x89, 0x07});  // mov %rax, (%rdi)
  EXPECT_TRUE(state_.Slot(-16).IsOrigReg(kDWARFRbx));
}

}  // namespace
}  // namespace unwind_analysis

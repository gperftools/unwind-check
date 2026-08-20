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
    const cs_insn* insn = disasm_->DecodeOne(code.data(), code.size(), kBase);
    EXPECT_NE(insn, nullptr) << "capstone could not decode the test encoding";
    if (insn == nullptr) {
      return TransferOutcome{};
    }
    EXPECT_EQ(insn->size, code.size()) << "test encoding is not exactly one instruction: " << insn->mnemonic;
    InsnSemantics semantics{disasm_->handle()};
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

TEST_F(SemanticsTest, StoresThroughAnUntrackedPointerDoNotWipeTheFrame) {
  Run({0x53});  // push %rbx
  ASSERT_TRUE(state_.Slot(-16).IsOrigReg(kDWARFRbx));
  Run({0x48, 0x89, 0x07});  // mov %rax, (%rdi)
  EXPECT_TRUE(state_.Slot(-16).IsOrigReg(kDWARFRbx));
}

}  // namespace
}  // namespace unwind_analysis

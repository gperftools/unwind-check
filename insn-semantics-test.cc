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
    Instruction insn;
    bool ok = disasm_->Decode(code.data(), code.size(), kBase, &insn);
    EXPECT_TRUE(ok) << "Zydis could not decode the test encoding";
    if (!ok) {
      return TransferOutcome{};
    }
    EXPECT_EQ(insn.size, code.size()) << "test encoding is not exactly one instruction: "
                                      << Disassembler::Text(insn).value_or("<cannot format>");
    InsnSemantics semantics;
    return semantics.Transfer(insn, &state_);
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

TEST_F(SemanticsTest, WideVectorStoreClobbersMultipleSlots) {
  // Set up rbp = CFA-16
  Run({0x55});              // push %rbp
  Run({0x48, 0x89, 0xe5});  // mov %rsp, %rbp
  state_.SetSlot(-24, AbsVal::OrigReg(kDWARFRbx));
  state_.SetSlot(-32, AbsVal::OrigReg(12));
  state_.SetSlot(-40, AbsVal::OrigReg(13));
  state_.SetSlot(-48, AbsVal::OrigReg(14));
  state_.SetSlot(-56, AbsVal::OrigReg(15));

  // movaps %xmm0, -0x10(%rbp) writes 16 bytes at CFA-32 to CFA-16 (covering -32 and -24)
  Run({0x0f, 0x29, 0x45, 0xf0});
  EXPECT_TRUE(state_.Slot(-24).is_top());
  EXPECT_TRUE(state_.Slot(-32).is_top());
  EXPECT_TRUE(state_.Slot(-40).IsOrigReg(13));
  EXPECT_TRUE(state_.Slot(-48).IsOrigReg(14));
  EXPECT_TRUE(state_.Slot(-56).IsOrigReg(15));

  // vmovups %ymm0, -0x28(%rbp) writes 32 bytes at CFA-56 to CFA-24 (covering -56, -48, -40, -32)
  state_.SetSlot(-32, AbsVal::OrigReg(12));
  Run({0xc5, 0xfd, 0x11, 0x45, 0xd8});
  EXPECT_TRUE(state_.Slot(-32).is_top());
  EXPECT_TRUE(state_.Slot(-40).is_top());
  EXPECT_TRUE(state_.Slot(-48).is_top());
  EXPECT_TRUE(state_.Slot(-56).is_top());
}

TEST_F(SemanticsTest, NarrowStoreClobbersEnclosingSlot) {
  // Set up rbp = CFA-16
  Run({0x55});              // push %rbp
  Run({0x48, 0x89, 0xe5});  // mov %rsp, %rbp
  state_.SetSlot(-24, AbsVal::OrigReg(kDWARFRbx));
  // movl %eax, -0x8(%rbp) -> 32-bit store at CFA-24
  Run({0x89, 0x45, 0xf8});
  EXPECT_TRUE(state_.Slot(-24).is_top());
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
  // The bound is snapshotted at movslq-time, so it must be set on the index
  // register before that instruction runs -- a bound set afterwards, as this
  // test used to do, is no longer picked up, on purpose: the whole point is to
  // stop the resolver from re-reading the index's bound live at the `jmp`.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  int64_t table = state_.reg(kDWARFRcx).ConstValue();
  state_.ApplyGuardBound(kDWARFRax, 4);
  Run({0x48, 0x63, 0x14, 0x81});            // rdx = table_entry(table, index=rax), captures bound(rax)=4
  Run({0x48, 0x01, 0xca});                  // rdx = jump_target(table, index=rax), carries the captured bound
  TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx
  EXPECT_TRUE(out.has_jump_table);
  EXPECT_EQ(out.jump_table_addr, static_cast<uint64_t>(table));
  EXPECT_EQ(out.jump_table_entries, 5u);
}

TEST_F(SemanticsTest, IndirectJumpDoesNotResolveFromAWidthFactAlone) {
  // A width fact bounds the index honestly -- `movzbl` really does prove
  // it is at most 255 -- but it is not a size the compiler declared, and
  // resolving a 256-entry table from it would read whatever .rodata
  // happens to follow the real one. Only a guard may size a table.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  Run({0x0f, 0xb6, 0xc0});                          // movzbl %al,%eax -- rax <= 255, no guard
  ASSERT_EQ(state_.reg(kDWARFRax).value_bound, 255u);
  ASSERT_FALSE(state_.reg(kDWARFRax).HasTableBound());
  Run({0x48, 0x63, 0x14, 0x81});            // rdx = table_entry(table, index=rax)
  Run({0x48, 0x01, 0xca});                  // rdx = jump_target(table, index=rax)
  TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx
  EXPECT_FALSE(out.has_jump_table);
  EXPECT_TRUE(out.has_unbounded_jump_target) << "the table shape resolved; only its size is missing";
}

TEST_F(SemanticsTest, IndirectJumpDoesNotResolveFromABoundSetAfterTheTableLoad) {
  // The mirror image of the test above: a live bound lookup at the `jmp`
  // is deliberately not done, so a bound that only shows up after the
  // movslq/add sequence (e.g. from an unrelated guard that happens to
  // reuse the index register) must not resolve the table.
  Run({0x48, 0x8d, 0x0d, 0x10, 0x00, 0x00, 0x00});  // rcx = const(table)
  Run({0x48, 0x63, 0x14, 0x81});                    // rdx = table_entry(table, index=rax), no bound yet
  Run({0x48, 0x01, 0xca});                          // rdx = jump_target(table, index=rax), still no bound
  state_.ApplyGuardBound(kDWARFRax, 4);
  TransferOutcome out = Run({0xff, 0xe2});  // jmp *%rdx
  EXPECT_FALSE(out.has_jump_table);
}

TEST_F(SemanticsTest, CmpWithANonNegativeImmediateSetsLastCmp) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->reg, kDWARFRax);
  EXPECT_EQ(state_.last_cmp->width_bits, 32u);
  EXPECT_EQ(state_.last_cmp->imm, 9u);
}

TEST_F(SemanticsTest, CmpOnItsOwnEstablishesNoBound) {
  // A comparison sets flags and nothing else. It is the branch that picks
  // a side and turns it into a fact -- deriving one here would invent a
  // bound on the taken edge, or with no branch at all.
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, kBoundTop);
  EXPECT_FALSE(state_.reg(kDWARFRax).HasTableBound());
}

TEST_F(SemanticsTest, LastCmpIsClearedByALaterFlagsWritingInstruction) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  Run({0x83, 0xc0, 0x01});  // add $1,%eax -- also sets flags, but is not a guard
  EXPECT_FALSE(state_.last_cmp.has_value());
}

TEST_F(SemanticsTest, LastCmpIsClearedByAWriteToTheComparedRegister) {
  // `cmp $9,%eax; mov (%rbx),%rax` leaves the flags alone but replaces the
  // very value they describe.
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  Run({0x48, 0x8b, 0x03});  // mov (%rbx),%rax -- no flags written
  EXPECT_FALSE(state_.last_cmp.has_value());
}

TEST_F(SemanticsTest, LastCmpSurvivesAnInstructionThatDoesNotTouchFlagsOrTheReg) {
  Run({0x83, 0xf8, 0x09});  // cmp $9,%eax
  ASSERT_TRUE(state_.last_cmp.has_value());
  Run({0x89, 0xc1});  // mov %eax,%ecx -- writes neither EFLAGS nor rax
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_EQ(state_.last_cmp->imm, 9u);
}

// --- width facts ----------------------------------------------------------

TEST_F(SemanticsTest, AnyWriteToA32BitRegisterProvesTheFullRegisterIsZeroExtended) {
  // Not about what was computed -- x86-64 zero-extends every 32-bit
  // destination write, so the mere occurrence of one bounds the register.
  // This is what later lets a `cmp $imm,%eax` guard bound *rax*.
  Run({0x01, 0xc8});  // add %ecx,%eax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, 0xffffffffu);
  EXPECT_FALSE(state_.reg(kDWARFRax).HasTableBound()) << "a width fact is never a table size";
}

TEST_F(SemanticsTest, AWriteToA64BitRegisterProvesNoWidthFact) {
  Run({0x48, 0x01, 0xc8});  // add %rcx,%rax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, kBoundTop);
}

TEST_F(SemanticsTest, AWriteToAnEightBitRegisterProvesNothingAboutTheParent) {
  // `mov %sil,%al` leaves bits 8..63 of rax untouched, so however tightly
  // bounded %sil was, rax is not bounded at all.
  state_.ApplyGuardBound(kDWARFRsi, 9);
  Run({0x40, 0x88, 0xf0});  // mov %sil,%al
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, kBoundTop);
  EXPECT_FALSE(state_.reg(kDWARFRax).HasTableBound());
}

TEST_F(SemanticsTest, MovzxIntoASixteenBitRegisterProvesNothingAboutTheParent) {
  // Same reason: a 16-bit destination does not zero-extend into the
  // upper half the way a 32-bit one does.
  state_.ApplyGuardBound(kDWARFRax, 9);
  Run({0x66, 0x0f, 0xb6, 0xc8});  // movzbw %al,%cx
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, kBoundTop);
}

TEST_F(SemanticsTest, MovzxFromMemoryProvesTheLoadWidth) {
  // Where a byte-wide index usually comes from, and the fact that makes a
  // later `cmp $imm,%al` guard able to say anything about rax at all.
  Run({0x0f, 0xb6, 0x07});  // movzbl (%rdi),%eax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, 255u);
}

TEST_F(SemanticsTest, MovsxFromMemoryProvesOnlyTheDestinationWidth) {
  // Sign extension of unknown memory can produce a huge unsigned value,
  // so only the 32-bit destination write itself proves anything.
  Run({0x0f, 0xbe, 0x07});  // movsbl (%rdi),%eax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, 0xffffffffu);
}

// --- proven guards --------------------------------------------------------
//
// A guard becomes "proven" on the one branch edge where the compared value
// is in range (fde-checker.cc's ApplyInRangeGuard). These tests set that up
// by hand; what they cover is the consumption side.

TEST_F(SemanticsTest, AProvenGuardIsCashedInByAWiden) {
  // `cmp $9,%al; ja default` on a register nothing proved zero-extended:
  // the guard bounds only the low 8 bits, and `movzbl %al,%ecx` is what
  // turns that into a bound on all of rcx.
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/9};
  Run({0x0f, 0xb6, 0xc8});  // movzbl %al,%ecx
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 9u);
  EXPECT_EQ(state_.reg(kDWARFRcx).table_bound, 9u) << "a guard is compiler-declared, so it may size a table";
}

TEST_F(SemanticsTest, AProvenGuardIsCashedInWhenSourceAndDestinationAreTheSameRegister) {
  // `movzbl %al,%eax` is the commonest spelling of the widen, and reads the
  // register it also writes -- so the source and the guard both have to be
  // read before the destination is clobbered.
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/9};
  Run({0x0f, 0xb6, 0xc0});  // movzbl %al,%eax
  EXPECT_EQ(state_.reg(kDWARFRax).table_bound, 9u);
  EXPECT_FALSE(state_.last_cmp.has_value()) << "the write to rax retires the guard once it has been collected";
}

TEST_F(SemanticsTest, AnUnprovenGuardIsNotCashedIn) {
  // The same shape with no branch having selected an edge. This is the
  // fabrication the old fallback committed.
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/kBoundTop};
  Run({0x0f, 0xb6, 0xc8});  // movzbl %al,%ecx
  EXPECT_FALSE(state_.reg(kDWARFRcx).HasTableBound());
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 255u) << "only the load width itself survives";
}

TEST_F(SemanticsTest, AProvenGuardIsNotCashedInByAWiderRead) {
  // A guard on the low 8 bits says nothing about bits 8..31, so a 32-bit
  // read reaches past what was compared.
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/9};
  Run({0x48, 0x63, 0xc8});  // movsxd %eax,%rcx
  EXPECT_FALSE(state_.reg(kDWARFRcx).HasTableBound());
}

TEST_F(SemanticsTest, AProvenGuardSurvivesAFlagsWritingInstruction) {
  // Once the branch has picked a side, "the low 8 bits of rax are at most 9"
  // is a fact about rax, not about EFLAGS -- and the instructions between
  // the branch and the widen are ordinary code that may well set flags.
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/9};
  Run({0x83, 0xc1, 0x01});  // add $1,%ecx -- writes EFLAGS, not rax
  ASSERT_TRUE(state_.last_cmp.has_value());
  EXPECT_TRUE(state_.last_cmp->proven());
}

TEST_F(SemanticsTest, AProvenGuardDoesNotSurviveAWriteToItsOwnRegister) {
  state_.last_cmp = AbsState::FlagsGuard{kDWARFRax, 8, /*imm=*/9, /*proven_bound=*/9};
  Run({0x48, 0x8b, 0x03});  // mov (%rbx),%rax
  EXPECT_FALSE(state_.last_cmp.has_value());
}

// --- carrying bounds across widens ----------------------------------------

TEST_F(SemanticsTest, MovzxCarriesTheSourcesBoundsAcrossATruncatingWiden) {
  state_.ApplyGuardBound(kDWARFRax, 9);
  Run({0x0f, 0xb6, 0xc8});  // movzbl %al,%ecx
  EXPECT_TRUE(state_.reg(kDWARFRcx).is_top()) << "the widened value's own identity does not survive the truncation";
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 9u);
  EXPECT_EQ(state_.reg(kDWARFRcx).table_bound, 9u) << "a guard's bound stays usable as a table size across a widen";
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, 9u) << "the source's own bounds are untouched by a read";
}

TEST_F(SemanticsTest, NarrowMovCarriesBoundsWhenTheDestinationIs32Bit) {
  // GCC routinely widens a guarded index into whatever register the table
  // load reads; a plain `mov %esi,%eax` is one of the spellings it uses.
  state_.ApplyGuardBound(kDWARFRsi, 9);
  Run({0x89, 0xf0});  // mov %esi,%eax
  EXPECT_EQ(state_.reg(kDWARFRax).value_bound, 9u);
  EXPECT_EQ(state_.reg(kDWARFRax).table_bound, 9u);
}

TEST_F(SemanticsTest, MovsxCarriesBoundsWhenTheSignBitIsProvenClear) {
  state_.ApplyGuardBound(kDWARFRax, 9);
  Run({0x0f, 0xbe, 0xc8});  // movsbl %al,%ecx
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 9u);
  EXPECT_EQ(state_.reg(kDWARFRcx).table_bound, 9u);
}

TEST_F(SemanticsTest, MovsxRejectsBoundsWhenTheSignBitCanBeOne) {
  state_.ApplyGuardBound(kDWARFRax, 200);
  Run({0x0f, 0xbe, 0xc8});  // movsbl %al,%ecx -- 200 is a negative signed byte
  EXPECT_FALSE(state_.reg(kDWARFRcx).HasTableBound());
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 0xffffffffu) << "only the 32-bit destination write itself survives";
}

TEST_F(SemanticsTest, MovsxdCarriesBoundsFrom32BitRegWhenNonNegative) {
  state_.ApplyGuardBound(kDWARFRax, 9);
  Run({0x48, 0x63, 0xc8});  // movsxd %eax,%rcx
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, 9u);
  EXPECT_EQ(state_.reg(kDWARFRcx).table_bound, 9u);
}

TEST_F(SemanticsTest, MovsxdRejectsBoundsWhenTheSignBitCanBeOne) {
  state_.ApplyValueBound(kDWARFRax, 0xffffffffu);
  Run({0x48, 0x63, 0xc8});  // movsxd %eax,%rcx
  EXPECT_EQ(state_.reg(kDWARFRcx).value_bound, kBoundTop) << "a 64-bit destination proves no width fact of its own";
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

TEST_F(SemanticsTest, SyscallClobbersCallerSavedRegistersAndRedZone) {
  state_.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  state_.SetReg(kDWARFRax, AbsVal::Const(1));
  state_.SetReg(kDWARFRbx, AbsVal::Const(2));
  state_.SetReg(kDWARFRbp, AbsVal::CFARel(-8));

  TransferOutcome out = Run({0x0f, 0x05});  // syscall
  EXPECT_FALSE(out.is_call);
  EXPECT_TRUE(out.falls_through);
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8)) << "rsp is preserved across syscall";
  EXPECT_TRUE(state_.reg(kDWARFRbp).IsCFARel(-8)) << "rbp is callee-saved across syscall";
  EXPECT_TRUE(state_.reg(kDWARFRbx).IsConst()) << "rbx is callee-saved across syscall";
  EXPECT_EQ(state_.reg(kDWARFRbx).ConstValue(), 2);
  EXPECT_TRUE(state_.reg(kDWARFRax).is_top()) << "rax is caller-saved / clobbered by syscall";
  EXPECT_TRUE(state_.reg(kDWARFRcx).is_top()) << "rcx is clobbered by syscall";
  EXPECT_TRUE(state_.reg(kDWARFRdi).is_top()) << "rdi is caller-saved / clobbered by syscall";
  EXPECT_TRUE(state_.Slot(-16).is_top()) << "red zone slots do not survive syscall";
}

TEST_F(SemanticsTest, Int80ClobbersCallerSavedRegistersAndRedZone) {
  state_.SetSlot(-16, AbsVal::OrigReg(kDWARFRbx));
  state_.SetReg(kDWARFRax, AbsVal::Const(1));
  state_.SetReg(kDWARFRbx, AbsVal::Const(2));

  TransferOutcome out = Run({0xcd, 0x80});  // int $0x80
  EXPECT_FALSE(out.is_call);
  EXPECT_TRUE(out.falls_through);
  EXPECT_TRUE(state_.reg(kDWARFRsp).IsCFARel(-8));
  EXPECT_TRUE(state_.reg(kDWARFRbx).IsConst());
  EXPECT_TRUE(state_.reg(kDWARFRax).is_top());
  EXPECT_TRUE(state_.Slot(-16).is_top());
}

}  // namespace
}  // namespace unwind_analysis

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
//
// End-to-end test for LightCheck over the same hand-written fixtures
// fixtures-test.cc uses for FDEChecker. The light checker's scope is
// deliberately narrower -- it never resolves switch tables and never
// checks the return convention at `ret` -- so a fixture named for what the
// *full* checker should conclude is not automatically right for this one.
// Each assertion below states, and justifies, what LightCheck actually
// should find for a given fixture, rather than assuming parity.

#include "light-checker.h"

#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "cfi-table.h"
#include "disasm.h"
#include "eh-frame-reader.h"
#include "elf-image.h"
#include "fde-checker.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "symbolizer.h"

namespace unwind_analysis {
namespace {

using ::testing::Contains;
using ::testing::HasSubstr;

const char* FixturePath() {
  return "testdata/libfixtures.so";
}

struct Checked {
  FDEResult result;
  std::vector<std::string> messages;
};

class LightCheckerTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    absl::StatusOr<std::unique_ptr<ELFImage>> image = ELFImage::Open(FixturePath());
    ASSERT_TRUE(image.ok()) << image.status();
    image_ = image->release();

    absl::StatusOr<std::unique_ptr<Disassembler>> disasm = Disassembler::Create();
    ASSERT_TRUE(disasm.ok()) << disasm.status();
    disasm_ = disasm->release();

    symbolizer_ = new Symbolizer(*image_, Symbolizer::Addr2LineMode::kOff, "");

    absl::flat_hash_set<uint64_t> starts;
    for (const FuncSymbol& sym : image_->func_symbols()) {
      starts.insert(sym.vaddr);
    }

    std::vector<CFI> all_cfis;
    EnumerateFDEs(static_cast<uintptr_t>(image_->eh_frame_start()) + image_->bias(),
                  static_cast<uintptr_t>(image_->eh_frame_end()) + image_->bias(), [&](uintptr_t fde_addr) {
                    all_cfis.push_back(ReadFDE(image_->ToVaddr(fde_addr), image_->eh_frame_start(),
                                               image_->eh_frame_end(), image_->bias()));
                  });
    std::vector<std::pair<std::pair<uint64_t, uint64_t>, const CFI*>> cfi_index;
    cfi_index.reserve(all_cfis.size());
    for (const CFI& cfi : all_cfis) {
      cfi_index.emplace_back(std::make_pair(cfi.pc_begin, cfi.pc_end), &cfi);
    }
    absl::c_sort(cfi_index);

    FDECheckerOptions options;
    options.image = image_;
    options.disasm = disasm_;
    options.all_cfis = cfi_index;
    by_name_ = new std::map<std::string, Checked>();
    for (const CFI& cfi : all_cfis) {
      std::string name = symbolizer_->Name(cfi.pc_begin);
      if (name.empty()) {
        continue;
      }
      Checked c;
      c.result = LightCheck(options, cfi, starts.contains(cfi.pc_begin));
      for (const Finding& f : c.result.findings) {
        c.messages.push_back(f.message);
      }
      by_name_->emplace(name, std::move(c));
    }
  }

  static const Checked& Get(std::string_view name) {
    auto it = by_name_->find(std::string(name));
    EXPECT_NE(it, by_name_->end()) << "no FDE for " << name;
    return it->second;
  }

  static ELFImage* image_;
  static Disassembler* disasm_;
  static Symbolizer* symbolizer_;
  static std::map<std::string, Checked>* by_name_;
};

ELFImage* LightCheckerTest::image_ = nullptr;
Disassembler* LightCheckerTest::disasm_ = nullptr;
Symbolizer* LightCheckerTest::symbolizer_ = nullptr;
std::map<std::string, Checked>* LightCheckerTest::by_name_ = nullptr;

// Straightforward rsp-based frames: the light checker's core CFA-delta
// check and its positional saved-register check both apply throughout, and
// both hold, so these must come out fully clean.
TEST_F(LightCheckerTest, StraightforwardGoodFunctionsAreBlessed) {
  for (const char* name : {"good_leaf", "good_callee_saved", "good_call", "good_shared_epilogue"}) {
    const Checked& c = Get(name);
    EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << name << ": " << testing::PrintToString(c.messages);
    EXPECT_TRUE(c.messages.empty()) << name << ": " << testing::PrintToString(c.messages);
  }
}

// good_frame_pointer switches its CFA anchor from rsp to rbp partway
// through, and back at the final `popq %rbp`. The switch to rbp and the
// push that precedes it are both rsp-anchored at the time, so they are
// fully verified; the final `popq %rbp` runs with rsp untracked (CFA is
// rbp-anchored, and DWARF does not say where rsp is once it stops being
// the CFA register), so that one transition is silently unverifiable
// rather than checked. Either way, nothing here is provably wrong, so the
// verdict is still BLESSED.
TEST_F(LightCheckerTest, FramePointerSwitchIsBlessedWithASilentGap) {
  const Checked& c = Get("good_frame_pointer");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << testing::PrintToString(c.messages);
}

// `leave` reconstructs rsp from rbp directly (insn-semantics.cc), so unlike
// a raw `popq %rbp` it does not depend on rsp already being tracked. The
// final CFA transition back to rsp+8 is therefore actually verified here,
// not just silently skipped.
TEST_F(LightCheckerTest, LeaveIsFullyVerified) {
  const Checked& c = Get("good_leave");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << testing::PrintToString(c.messages);
}

// The generalization this checker exists to demonstrate: a `mov` spill
// into a frame carved out by `sub` is checked the same way a `push` is,
// via the same slots-diff, with no separate code path.
TEST_F(LightCheckerTest, MovSpillPositionIsVerified) {
  const Checked& c = Get("good_mov_spill");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << testing::PrintToString(c.messages);
}

// clang bug shape #1 (spec/README): a stack adjustment hoisted above a
// branch without its CFI update following it. The CFA-delta check catches
// it regardless of which exact instruction the finding is pinned to -- this
// checker attributes it to the instruction whose transfer produced the
// disagreement, not (as the full checker does) to the row where it is
// merely still wrong, so pc/message details deliberately are not asserted
// to match fixtures-test.cc's expectations for this same fixture.
TEST_F(LightCheckerTest, HoistedStackAdjustmentIsCaught) {
  const Checked& c = Get("bad_hoisted_add");
  EXPECT_EQ(c.result.verdict, Verdict::kMismatch);
  EXPECT_THAT(c.messages, Contains(HasSubstr("declared CFA is")));
}

// clang bug shape #2: the CFI for a push lands one instruction late.
TEST_F(LightCheckerTest, LatePushCFIIsCaught) {
  const Checked& c = Get("bad_late_push_cfi");
  EXPECT_EQ(c.result.verdict, Verdict::kMismatch);
  EXPECT_THAT(c.messages, Contains(HasSubstr("declared CFA is")));
}

// Cross-FDE tail-call / jump-target checking: still exactly the CFA-only
// comparison, so still catches a real mismatch and still blesses a
// legitimately different-looking-but-consistent target state.
TEST_F(LightCheckerTest, JumpIntoColdFragmentIsCheckedAgainstItsOwnDeclaredRow) {
  const Checked& c = Get("good_jump_to_cold_fragment");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << testing::PrintToString(c.messages);
}

TEST_F(LightCheckerTest, JumpIntoColdFragmentWithWrongStateIsAMismatch) {
  const Checked& c = Get("bad_jump_to_cold_fragment");
  EXPECT_EQ(c.result.verdict, Verdict::kMismatch);
  EXPECT_THAT(c.messages, Contains(HasSubstr("jump to")));
}

// review_cfa_expression is the one REVIEW trigger this checker keeps: a
// CFA rule it cannot evaluate at all (DW_CFA_def_cfa_expression, DRAP-style
// frames and some hand-realigned asm) is loudly flagged rather than
// silently skipped.
TEST_F(LightCheckerTest, CFAExpressionIsReviewNotSilentlySkipped) {
  const Checked& c = Get("review_cfa_expression");
  EXPECT_EQ(c.result.verdict, Verdict::kReview);
  EXPECT_THAT(c.messages, Contains(HasSubstr("CFA is given by a DWARF expression")));
}

// This checker makes no attempt to resolve a switch table's dispatch, so
// the indirect jmp itself is silent (not even a REVIEW -- unlike the full
// checker, which names it). What matters here is that the case bodies,
// reachable only through that dispatch in the full checker's CFG walk, are
// still decoded and checked on their own, since address-order decoding
// does not depend on the dispatch resolving at all.
TEST_F(LightCheckerTest, SwitchTableCaseBodiesAreStillWalkedWithoutResolvingTheDispatch) {
  const Checked& c = Get("good_switch_table");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed) << testing::PrintToString(c.messages);
  EXPECT_GE(c.result.instructions_checked, 8u);
}

TEST_F(LightCheckerTest, StaleCFIInASwitchCaseBodyIsStillCaught) {
  const Checked& c = Get("bad_switch_table_case");
  EXPECT_EQ(c.result.verdict, Verdict::kMismatch);
  EXPECT_THAT(c.messages, Contains(HasSubstr("declared CFA is")));
}

// Neither guessable_jump_pc nor guessed_jump_tables is ever populated: this
// checker never attempts the guessing recovery FDEChecker::CheckWithGuessing
// does, on any fixture.
TEST_F(LightCheckerTest, NeverPopulatesGuessingFields) {
  for (const auto& [name, checked] : *by_name_) {
    EXPECT_FALSE(checked.result.guessable_jump_pc.has_value()) << name;
    EXPECT_TRUE(checked.result.guessed_jump_tables.empty()) << name;
    EXPECT_NE(checked.result.verdict, Verdict::kReviewLight) << name;
  }
}

// A blessed verdict is only worth something if the walk actually reached
// the code.
TEST_F(LightCheckerTest, BlessedFunctionsActuallyGotWalked) {
  for (const auto& [name, checked] : *by_name_) {
    if (checked.result.verdict != Verdict::kBlessed) {
      continue;
    }
    EXPECT_GE(checked.result.instructions_checked, 2u) << name;
  }
}

}  // namespace
}  // namespace unwind_analysis

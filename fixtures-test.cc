/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
//
// End-to-end test: run the checker over testdata/fixtures.S, whose CFI
// is hand-written so that the right answer is fixed by the fixture and
// not by whatever compiler happened to build it.

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/match.h"
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

class FixturesTest : public testing::Test {
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
    std::sort(cfi_index.begin(), cfi_index.end());

    FDEChecker checker{*image_, disasm_, FDEChecker::Options{}, cfi_index};
    by_name_ = new std::map<std::string, Checked>();
    for (const CFI& cfi : all_cfis) {
      std::string name = symbolizer_->Name(cfi.pc_begin);
      if (name.empty()) {
        continue;
      }
      Checked c;
      c.result = checker.Check(cfi, starts.contains(cfi.pc_begin));
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

  // Address of the n-th instruction of a function, counting from zero.
  static uint64_t InstructionAt(std::string_view name, int index) {
    const FDEResult& r = Get(name).result;
    uint64_t pc = r.pc_begin;
    for (int i = 0; i < index; i++) {
      std::span<const uint8_t> bytes = image_->BytesAt(pc, 16);
      const Instruction* insn = disasm_->DecodeOne(bytes.data(), bytes.size(), pc);
      EXPECT_NE(insn, nullptr);
      pc += insn->size;
    }
    return pc;
  }

  static ELFImage* image_;
  static Disassembler* disasm_;
  static Symbolizer* symbolizer_;
  static std::map<std::string, Checked>* by_name_;
};

ELFImage* FixturesTest::image_ = nullptr;
Disassembler* FixturesTest::disasm_ = nullptr;
Symbolizer* FixturesTest::symbolizer_ = nullptr;
std::map<std::string, Checked>* FixturesTest::by_name_ = nullptr;

TEST_F(FixturesTest, EveryFixtureIsPresent) {
  // Named one by one, so that a fixture silently dropping out of
  // .eh_frame is a failure rather than a quietly smaller test.
  for (const char* name : {"good_leaf",
                           "good_frame_pointer",
                           "good_callee_saved",
                           "good_leave",
                           "good_shared_epilogue",
                           "good_mov_spill",
                           "good_call",
                           "good_tail_call",
                           "good_indirect_tail_call",
                           "bad_hoisted_add",
                           "bad_late_push_cfi",
                           "review_unusual_entry_row",
                           "bad_wrong_register_saved",
                           "bad_ret_stack_not_restored",
                           "bad_ret_wrong_reg_restored",
                           "bad_tail_call_wrong_reg_restored",
                           "review_ret_callee_saved_untracked",
                           "review_indirect_jump",
                           "review_cfa_expression",
                           "good_switch_table",
                           "bad_switch_table_case",
                           "review_switch_table_unguarded",
                           "good_jump_to_cold_fragment",
                           "bad_jump_to_cold_fragment",
                           "review_tail_call_no_target_fde",
                           "good_switch_table_into_cold",
                           "bad_switch_table_into_cold"}) {
    EXPECT_TRUE(by_name_->contains(name)) << name << " has no FDE";
  }
}

// The names in the fixture file carry the expectation, so hold every
// function in it to what its prefix promises.
TEST_F(FixturesTest, NamesMatchVerdicts) {
  for (const auto& [name, checked] : *by_name_) {
    Verdict expected;
    if (absl::StartsWith(name, "good_")) {
      expected = Verdict::kBlessed;
    } else if (absl::StartsWith(name, "bad_")) {
      expected = Verdict::kMismatch;
    } else {
      ASSERT_TRUE(absl::StartsWith(name, "review_")) << name;
      expected = Verdict::kReview;
    }
    std::string findings;
    for (const std::string& m : checked.messages) {
      findings += "\n    " + m;
    }
    EXPECT_EQ(checked.result.verdict, expected)
        << name << " came out " << VerdictName(checked.result.verdict) << findings;
  }
}

TEST_F(FixturesTest, HoistedStackAdjustmentIsCaughtAtTheRightInstruction) {
  const Checked& c = Get("bad_hoisted_add");
  ASSERT_FALSE(c.result.findings.empty());
  const Finding& f = c.result.findings.front();
  EXPECT_EQ(f.severity, Finding::Severity::kMismatch);
  // push, sub, add, testl -- the table is stale from the testl onwards.
  EXPECT_EQ(f.pc, InstructionAt("bad_hoisted_add", 3));
  EXPECT_THAT(f.message, HasSubstr("declared CFA is rsp+24"));
  EXPECT_THAT(f.message, HasSubstr("rsp is CFA-16"));
}

TEST_F(FixturesTest, LatePushCFIIsCaughtAtTheInstructionInBetween) {
  const Checked& c = Get("bad_late_push_cfi");
  ASSERT_FALSE(c.result.findings.empty());
  const Finding& f = c.result.findings.front();
  EXPECT_EQ(f.severity, Finding::Severity::kMismatch);
  EXPECT_EQ(f.pc, InstructionAt("bad_late_push_cfi", 1));  // the movq after the push
  EXPECT_THAT(f.message, HasSubstr("declared CFA is rsp+8"));
}

TEST_F(FixturesTest, UnusualEntryRowIsFlaggedButNotCalledABug) {
  EXPECT_THAT(Get("review_unusual_entry_row").messages,
              Contains(HasSubstr("a function symbol starts here, so the CFA should be rsp+8")));
}

TEST_F(FixturesTest, SlotHoldingTheWrongRegisterIsCaught) {
  EXPECT_THAT(Get("bad_wrong_register_saved").messages,
              Contains(HasSubstr("CFI says rbx is saved at [CFA-16], but that slot holds entry rbp")));
}

TEST_F(FixturesTest, ReturnWithUnrestoredStackIsCaught) {
  EXPECT_THAT(Get("bad_ret_stack_not_restored").messages,
              Contains(HasSubstr("return with rsp at CFA-16 (should be CFA-8)")));
}

TEST_F(FixturesTest, ReturnWithWrongCalleeSavedRegisterIsCaught) {
  EXPECT_THAT(Get("bad_ret_wrong_reg_restored").messages,
              Contains(HasSubstr("return with callee-saved register rbx holding entry r12")));
}

TEST_F(FixturesTest, TailCallWithWrongCalleeSavedRegisterIsCaught) {
  // good_leaf, the tail-call target, has an FDE of its own, so this is now
  // checked against its declared (canonical) entry row rather than the
  // generic tail-call-ABI fallback -- same verdict, different message.
  EXPECT_THAT(Get("bad_tail_call_wrong_reg_restored").messages,
              Contains(HasSubstr("CFI says rbx still holds its entry value, but it holds entry r12")));
}

TEST_F(FixturesTest, ReturnWithUntrackedCalleeSavedIsReview) {
  EXPECT_THAT(Get("review_ret_callee_saved_untracked").messages,
              Contains(HasSubstr("return with untracked callee-saved register rbx")));
}

TEST_F(FixturesTest, IndirectJumpIsFlaggedNotGuessed) {
  EXPECT_THAT(Get("review_indirect_jump").messages, Contains(HasSubstr("unresolved indirect jump")));
}

TEST_F(FixturesTest, SwitchTableCasesGetWalked) {
  // A blessed verdict on the dispatcher is only worth something if the
  // case bodies -- reachable only through the resolved table -- were
  // actually checked rather than silently skipped.
  const Checked& c = Get("good_switch_table");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed);
  EXPECT_GE(c.result.instructions_checked, 8u);
}

TEST_F(FixturesTest, StaleCFIInASwitchCaseBodyIsCaught) {
  EXPECT_THAT(Get("bad_switch_table_case").messages, Contains(HasSubstr("declared CFA is")));
}

TEST_F(FixturesTest, UnguardedIndirectJumpStaysReviewRatherThanBeingResolvedOnAGuess) {
  EXPECT_THAT(Get("review_switch_table_unguarded").messages, Contains(HasSubstr("unresolved indirect jump")));
}

TEST_F(FixturesTest, JumpIntoColdFragmentIsCheckedAgainstItsOwnDeclaredRow) {
  // Not tail-call-ABI-compliant (rsp isn't at CFA-8), but it matches
  // exactly what the target FDE declares, so this must go fully blessed
  // rather than earning the old heuristic's REVIEW.
  const Checked& c = Get("good_jump_to_cold_fragment");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed);
  EXPECT_TRUE(c.messages.empty()) << testing::PrintToString(c.messages);
}

TEST_F(FixturesTest, JumpIntoColdFragmentWithWrongStateIsAMismatch) {
  const Checked& c = Get("bad_jump_to_cold_fragment");
  ASSERT_FALSE(c.result.findings.empty());
  const Finding& f = c.result.findings.front();
  EXPECT_EQ(f.severity, Finding::Severity::kMismatch);
  EXPECT_EQ(f.pc, InstructionAt("bad_jump_to_cold_fragment", 1));  // the jmp
  EXPECT_THAT(f.message, HasSubstr("jump to"));
  EXPECT_THAT(f.message, HasSubstr("declared CFA is rsp+16"));
}

TEST_F(FixturesTest, TailCallToAnAddressWithNoFDEStillUsesTheABIFallback) {
  EXPECT_THAT(Get("review_tail_call_no_target_fde").messages, Contains(HasSubstr("no covering FDE")));
}

TEST_F(FixturesTest, SwitchTableCaseInAnotherFDEIsCheckedAgainstItsDeclaredRow) {
  const Checked& c = Get("good_switch_table_into_cold");
  EXPECT_EQ(c.result.verdict, Verdict::kBlessed);
  EXPECT_TRUE(c.messages.empty()) << testing::PrintToString(c.messages);
}

TEST_F(FixturesTest, SwitchTableCaseInAnotherFDEWithWrongStateIsAMismatch) {
  EXPECT_THAT(Get("bad_switch_table_into_cold").messages, Contains(HasSubstr("declared CFA is rsp+16")));
}

TEST_F(FixturesTest, CFAExpressionIsFlaggedNotEvaluated) {
  EXPECT_THAT(Get("review_cfa_expression").messages, Contains(HasSubstr("CFA is given by a DWARF expression")));
}

TEST_F(FixturesTest, BlessedFunctionsActuallyGotWalked) {
  // A blessed verdict is only worth something if the walk reached the
  // code: an FDE we never decoded would also produce no findings.
  for (const auto& [name, checked] : *by_name_) {
    if (checked.result.verdict != Verdict::kBlessed) {
      continue;
    }
    EXPECT_GE(checked.result.instructions_checked, 2u) << name;
  }
}

}  // namespace
}  // namespace unwind_analysis

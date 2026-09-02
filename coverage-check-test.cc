/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
//
// Exercises CheckUncoveredSymbols against testdata/libfixtures.so, whose
// uncovered_no_cfi fixture (testdata/fixtures.S) is deliberately built
// without .cfi_startproc/.cfi_endproc, so the assembler never emits an
// FDE for it -- the one case this check exists to catch.

#include "coverage-check.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "eh-frame-reader.h"
#include "elf-image.h"
#include "fde-checker.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "symbolizer.h"

namespace unwind_analysis {
namespace {

using ::testing::HasSubstr;

class CoverageCheckTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    absl::StatusOr<std::unique_ptr<ELFImage>> image = ELFImage::Open("testdata/libfixtures.so");
    ASSERT_TRUE(image.ok()) << image.status();
    image_ = image->release();
    symbolizer_ = new Symbolizer(*image_, Symbolizer::Addr2LineMode::kOff, "");

    std::vector<std::pair<uint64_t, uint64_t>> fde_ranges;
    EnumerateFDEs(static_cast<uintptr_t>(image_->eh_frame_start()) + image_->bias(),
                  static_cast<uintptr_t>(image_->eh_frame_end()) + image_->bias(), [&](uintptr_t fde_addr) {
                    CFI cfi = ReadFDE(image_->ToVaddr(fde_addr), image_->eh_frame_start(), image_->eh_frame_end(),
                                      image_->bias());
                    if (cfi.pc_end > cfi.pc_begin) {
                      fde_ranges.emplace_back(cfi.pc_begin, cfi.pc_end);
                    }
                  });

    results_ = new std::vector<FDEResult>(CheckUncoveredSymbols(*image_, fde_ranges));
  }

  static const FDEResult* FindByName(std::string_view name) {
    for (const FDEResult& r : *results_) {
      if (symbolizer_->Name(r.pc_begin) == name) {
        return &r;
      }
    }
    return nullptr;
  }

  static ELFImage* image_;
  static Symbolizer* symbolizer_;
  static std::vector<FDEResult>* results_;
};

ELFImage* CoverageCheckTest::image_ = nullptr;
Symbolizer* CoverageCheckTest::symbolizer_ = nullptr;
std::vector<FDEResult>* CoverageCheckTest::results_ = nullptr;

TEST_F(CoverageCheckTest, SymbolWithNoFDEIsFlaggedReview) {
  const FDEResult* found = FindByName("uncovered_no_cfi");
  ASSERT_NE(found, nullptr) << "uncovered_no_cfi should have been flagged as uncovered";
  EXPECT_EQ(found->verdict, Verdict::kReview);
  ASSERT_FALSE(found->findings.empty());
  EXPECT_EQ(found->findings.front().severity, Finding::Severity::kReview);
  EXPECT_THAT(found->findings.front().message, HasSubstr("no FDE covers this symbol at all"));
}

TEST_F(CoverageCheckTest, FixturesWithCFIAreNotFlagged) {
  // Every good_/bad_/review_ fixture has a real .cfi_startproc/.cfi_endproc
  // pair and so a real FDE -- none of them should show up here, whatever
  // toolchain boilerplate (frame_dummy and friends) the shared-library
  // build happens to add around them.
  for (const FDEResult& r : *results_) {
    std::string name = symbolizer_->Name(r.pc_begin);
    EXPECT_FALSE(absl::StartsWith(name, "good_") || absl::StartsWith(name, "bad_") || absl::StartsWith(name, "review_"))
        << name << " has CFI but was flagged as uncovered";
  }
}

}  // namespace
}  // namespace unwind_analysis

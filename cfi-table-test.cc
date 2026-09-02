/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
//
// Decodes the fixture binary's .eh_frame and checks the rows against the
// .cfi_* directives that were written by hand in testdata/fixtures.S.
//
// This is the test for the riskiest part of the port: the reader was
// written to walk live process memory, and here it walks a file mapped
// at a made-up bias instead.

#include "cfi-table.h"

#include <ios>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "eh-frame-reader.h"
#include "elf-image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

class CFITableTest : public testing::Test {
 protected:
  void SetUp() override {
    absl::StatusOr<std::unique_ptr<ELFImage>> image = ELFImage::Open("testdata/libfixtures.so");
    ASSERT_TRUE(image.ok()) << image.status();
    image_ = std::move(*image);

    for (const FuncSymbol& sym : image_->func_symbols()) {
      symbols_[sym.name] = sym.vaddr;
    }
    EnumerateFDEs(static_cast<uintptr_t>(image_->eh_frame_start()) + image_->bias(),
                  static_cast<uintptr_t>(image_->eh_frame_end()) + image_->bias(), [&](uintptr_t addr) {
                    CFI cfi = ReadFDE(image_->ToVaddr(addr), image_->eh_frame_start(), image_->eh_frame_end(),
                                      image_->bias());
                    fdes_[cfi.pc_begin] = std::move(cfi);
                  });
  }

  const CFI& FDEFor(const std::string& name) {
    auto sym = symbols_.find(name);
    EXPECT_NE(sym, symbols_.end()) << name;
    auto fde = fdes_.find(sym->second);
    EXPECT_NE(fde, fdes_.end()) << name;
    return fde->second;
  }

  std::unique_ptr<ELFImage> image_;
  std::map<std::string, uint64_t> symbols_;
  std::map<uint64_t, CFI> fdes_;
};

// Only the fixtures: the CRT glue the linker adds (__do_global_dtors_aux
// and friends) legitimately has no unwind info at all.
TEST_F(CFITableTest, FDERangesMatchTheSymbolTable) {
  for (const auto& [name, vaddr] : symbols_) {
    if (name.rfind("good_", 0) != 0 && name.rfind("bad_", 0) != 0 && name.rfind("review_", 0) != 0) {
      continue;
    }
    auto it = fdes_.find(vaddr);
    ASSERT_NE(it, fdes_.end()) << name << " has no FDE";
    EXPECT_EQ(it->second.pc_begin, vaddr) << name;
    EXPECT_GT(it->second.pc_end, it->second.pc_begin) << name;
  }
}

TEST_F(CFITableTest, EveryFDEStartsWithTheCIEsReturnAddressRule) {
  for (const auto& [pc, cfi] : fdes_) {
    EXPECT_EQ(cfi.return_reg, kDWARFRip) << "at 0x" << std::hex << pc;
    ASSERT_FALSE(cfi.rows.empty());
    EXPECT_EQ(cfi.rows.front().pc_start, cfi.pc_begin);
  }
}

// good_callee_saved is written as:
//   push %rbx        .cfi_def_cfa_offset 16 / .cfi_offset %rbx, -16
//   push %r12        .cfi_def_cfa_offset 24 / .cfi_offset %r12, -24
//   sub  $8, %rsp    .cfi_def_cfa_offset 32
//   mov  %edi, %eax
//   add  $8, %rsp    .cfi_def_cfa_offset 24
//   pop  %r12        .cfi_def_cfa_offset 16
//   pop  %rbx        .cfi_def_cfa_offset 8
//   ret
TEST_F(CFITableTest, DecodesTheHandWrittenRowsOfGoodCalleeSaved) {
  const CFI& cfi = FDEFor("good_callee_saved");
  std::vector<int> offsets;
  for (const CFIRow& row : cfi.rows) {
    ASSERT_EQ(row.cfa.kind, CFARule::Kind::kRegOffset);
    EXPECT_EQ(row.cfa.reg, kDWARFRsp);
    offsets.push_back(static_cast<int>(row.cfa.offset));
  }
  EXPECT_THAT(offsets, testing::ElementsAre(8, 16, 24, 32, 24, 16, 8));

  // The saves are declared where the directives put them, and the
  // .cfi_restore in the epilogue puts the rules back to the CIE's.
  const CFIRow* mid = cfi.RowAt(cfi.rows[3].pc_start);
  ASSERT_NE(mid, nullptr);
  EXPECT_EQ(mid->regs[kDWARFRbx].kind, RegRule::Kind::kAtCFAOffset);
  EXPECT_EQ(mid->regs[kDWARFRbx].offset, -16);
  EXPECT_EQ(mid->regs[12].kind, RegRule::Kind::kAtCFAOffset);
  EXPECT_EQ(mid->regs[12].offset, -24);
  EXPECT_EQ(mid->regs[kDWARFRip].kind, RegRule::Kind::kAtCFAOffset);
  EXPECT_EQ(mid->regs[kDWARFRip].offset, -8);
}

TEST_F(CFITableTest, TracksTheFramePointerBecomingTheCFARegister) {
  const CFI& cfi = FDEFor("good_frame_pointer");
  ASSERT_GE(cfi.rows.size(), 3u);
  EXPECT_EQ(cfi.rows.front().cfa.reg, kDWARFRsp);
  bool saw_rbp_cfa = false;
  for (const CFIRow& row : cfi.rows) {
    if (row.cfa.reg == kDWARFRbp && row.cfa.kind == CFARule::Kind::kRegOffset) {
      saw_rbp_cfa = true;
      EXPECT_EQ(row.cfa.offset, 16);
    }
  }
  EXPECT_TRUE(saw_rbp_cfa);
  EXPECT_EQ(cfi.rows.back().cfa.reg, kDWARFRsp) << "and back to rsp after the pop";
  EXPECT_EQ(cfi.rows.back().cfa.offset, 8);
}

TEST_F(CFITableTest, RecordsDWARFExpressionsWithoutEvaluatingThem) {
  const CFI& cfi = FDEFor("review_cfa_expression");
  ASSERT_GE(cfi.rows.size(), 2u);
  EXPECT_EQ(cfi.rows.back().cfa.kind, CFARule::Kind::kExpression);
}

TEST_F(CFITableTest, RowLookupIsBoundedByTheFDERange) {
  const CFI& cfi = FDEFor("good_leaf");
  EXPECT_NE(cfi.RowAt(cfi.pc_begin), nullptr);
  EXPECT_NE(cfi.RowAt(cfi.pc_end - 1), nullptr);
  EXPECT_EQ(cfi.RowAt(cfi.pc_end), nullptr);
  EXPECT_EQ(cfi.RowAt(cfi.pc_begin - 1), nullptr);
}

TEST_F(CFITableTest, MalformedFDEAddressThrowsRatherThanCrashing) {
  EXPECT_THROW(
      ReadFDE(image_->eh_frame_end() + 0x1000, image_->eh_frame_start(), image_->eh_frame_end(), image_->bias()),
      EHFrameError);
}

TEST(CFIRuleTest, StringifyFormatsRulesCorrectly) {
  CFARule undefined{CFARule::Kind::kUndefined, 0, 0};
  EXPECT_EQ(absl::StrCat(undefined), "<no CFA rule>");

  CFARule reg_offset{CFARule::Kind::kRegOffset, kDWARFRsp, 8};
  EXPECT_EQ(absl::StrCat(reg_offset), "rsp+8");

  CFARule expr{CFARule::Kind::kExpression, 0, 0};
  EXPECT_EQ(absl::StrCat(expr), "<DWARF expression>");
}

TEST(RegRuleTest, StringifyFormatsRulesCorrectly) {
  RegRule unset{RegRule::Kind::kUnset, 0, 0};
  EXPECT_EQ(absl::StrCat(unset), "<no rule>");

  RegRule undefined{RegRule::Kind::kUndefined, 0, 0};
  EXPECT_EQ(absl::StrCat(undefined), "undefined");

  RegRule same_val{RegRule::Kind::kSameValue, 0, 0};
  EXPECT_EQ(absl::StrCat(same_val), "same_value");

  RegRule at_cfa{RegRule::Kind::kAtCFAOffset, 0, -8};
  EXPECT_EQ(absl::StrCat(at_cfa), "[CFA-8]");

  RegRule val_offset{RegRule::Kind::kValOffset, 0, 16};
  EXPECT_EQ(absl::StrCat(val_offset), "CFA+16");

  RegRule in_reg{RegRule::Kind::kInRegister, kDWARFRbp, 0};
  EXPECT_EQ(absl::StrCat(in_reg), "in rbp");

  RegRule expr{RegRule::Kind::kExpression, 0, 0};
  EXPECT_EQ(absl::StrCat(expr), "<DWARF expression>");

  RegRule val_expr{RegRule::Kind::kValExpression, 0, 0};
  EXPECT_EQ(absl::StrCat(val_expr), "<DWARF val expression>");
}

TEST(DWARFRegNameTest, BASIC) {
  EXPECT_EQ(DWARFRegName(7), "rsp");
  EXPECT_EQ(DWARFRegName(-1), "r{-1}");
}

}  // namespace
}  // namespace unwind_analysis

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
//
// Decodes the fixture binary's .eh_frame and checks the rows against the
// .cfi_* directives that were written by hand in testdata/fixtures.S.
//
// This is the test for the riskiest part of the port: the reader was
// written to walk live process memory, and here it walks a file mapped
// at a made-up bias instead.

#include "cfi-table.h"

#include <map>
#include <string>

#include "eh-frame-reader.h"
#include "elf-image.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

class CfiTableTest : public testing::Test {
 protected:
  void SetUp() override {
    absl::StatusOr<std::unique_ptr<ElfImage>> image = ElfImage::Open("testdata/libfixtures.so");
    ASSERT_TRUE(image.ok()) << image.status();
    image_ = std::move(*image);

    for (const FuncSymbol& sym : image_->func_symbols()) {
      symbols_[sym.name] = sym.vaddr;
    }
    EnumerateFDEs(static_cast<uintptr_t>(image_->eh_frame_start()) + image_->bias(),
                  static_cast<uintptr_t>(image_->eh_frame_end()) + image_->bias(), [&](uintptr_t addr) {
                    FdeCfi cfi = ReadFde(image_->ToVaddr(addr), image_->eh_frame_start(), image_->eh_frame_end(),
                                         image_->bias());
                    fdes_[cfi.pc_begin] = std::move(cfi);
                  });
  }

  const FdeCfi& FdeFor(const std::string& name) {
    auto sym = symbols_.find(name);
    EXPECT_NE(sym, symbols_.end()) << name;
    auto fde = fdes_.find(sym->second);
    EXPECT_NE(fde, fdes_.end()) << name;
    return fde->second;
  }

  std::unique_ptr<ElfImage> image_;
  std::map<std::string, uint64_t> symbols_;
  std::map<uint64_t, FdeCfi> fdes_;
};

// Only the fixtures: the CRT glue the linker adds (__do_global_dtors_aux
// and friends) legitimately has no unwind info at all.
TEST_F(CfiTableTest, FdeRangesMatchTheSymbolTable) {
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

TEST_F(CfiTableTest, EveryFdeStartsWithTheCiesReturnAddressRule) {
  for (const auto& [pc, cfi] : fdes_) {
    EXPECT_EQ(cfi.return_reg, kDwarfRip) << "at 0x" << std::hex << pc;
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
TEST_F(CfiTableTest, DecodesTheHandWrittenRowsOfGoodCalleeSaved) {
  const FdeCfi& cfi = FdeFor("good_callee_saved");
  std::vector<int> offsets;
  for (const CfiRow& row : cfi.rows) {
    ASSERT_EQ(row.cfa.kind, CfaRule::Kind::kRegOffset);
    EXPECT_EQ(row.cfa.reg, kDwarfRsp);
    offsets.push_back(static_cast<int>(row.cfa.offset));
  }
  EXPECT_THAT(offsets, testing::ElementsAre(8, 16, 24, 32, 24, 16, 8));

  // The saves are declared where the directives put them, and the
  // .cfi_restore in the epilogue puts the rules back to the CIE's.
  const CfiRow* mid = cfi.RowAt(cfi.rows[3].pc_start);
  ASSERT_NE(mid, nullptr);
  EXPECT_EQ(mid->regs[kDwarfRbx].kind, RegRule::Kind::kAtCfaOffset);
  EXPECT_EQ(mid->regs[kDwarfRbx].offset, -16);
  EXPECT_EQ(mid->regs[12].kind, RegRule::Kind::kAtCfaOffset);
  EXPECT_EQ(mid->regs[12].offset, -24);
  EXPECT_EQ(mid->regs[kDwarfRip].kind, RegRule::Kind::kAtCfaOffset);
  EXPECT_EQ(mid->regs[kDwarfRip].offset, -8);
}

TEST_F(CfiTableTest, TracksTheFramePointerBecomingTheCfaRegister) {
  const FdeCfi& cfi = FdeFor("good_frame_pointer");
  ASSERT_GE(cfi.rows.size(), 3u);
  EXPECT_EQ(cfi.rows.front().cfa.reg, kDwarfRsp);
  bool saw_rbp_cfa = false;
  for (const CfiRow& row : cfi.rows) {
    if (row.cfa.reg == kDwarfRbp && row.cfa.kind == CfaRule::Kind::kRegOffset) {
      saw_rbp_cfa = true;
      EXPECT_EQ(row.cfa.offset, 16);
    }
  }
  EXPECT_TRUE(saw_rbp_cfa);
  EXPECT_EQ(cfi.rows.back().cfa.reg, kDwarfRsp) << "and back to rsp after the pop";
  EXPECT_EQ(cfi.rows.back().cfa.offset, 8);
}

TEST_F(CfiTableTest, RecordsDwarfExpressionsWithoutEvaluatingThem) {
  const FdeCfi& cfi = FdeFor("review_cfa_expression");
  ASSERT_GE(cfi.rows.size(), 2u);
  EXPECT_EQ(cfi.rows.back().cfa.kind, CfaRule::Kind::kExpression);
}

TEST_F(CfiTableTest, RowLookupIsBoundedByTheFdeRange) {
  const FdeCfi& cfi = FdeFor("good_leaf");
  EXPECT_NE(cfi.RowAt(cfi.pc_begin), nullptr);
  EXPECT_NE(cfi.RowAt(cfi.pc_end - 1), nullptr);
  EXPECT_EQ(cfi.RowAt(cfi.pc_end), nullptr);
  EXPECT_EQ(cfi.RowAt(cfi.pc_begin - 1), nullptr);
}

TEST_F(CfiTableTest, MalformedFdeAddressThrowsRatherThanCrashing) {
  EXPECT_THROW(
      ReadFde(image_->eh_frame_end() + 0x1000, image_->eh_frame_start(), image_->eh_frame_end(), image_->bias()),
      EhFrameError);
}

}  // namespace
}  // namespace unwind_analysis

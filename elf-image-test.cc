/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "elf-image.h"

#include <algorithm>
#include <memory>
#include <span>
#include <vector>

#include "absl/algorithm/container.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace unwind_analysis {
namespace {

using ::testing::Contains;
using ::testing::Field;

const char* FixturePath() {
  return "testdata/libfixtures.so";
}

class ELFImageTest : public testing::Test {
 protected:
  void SetUp() override {
    absl::StatusOr<std::unique_ptr<ELFImage>> image = ELFImage::Open(FixturePath());
    ASSERT_TRUE(image.ok()) << image.status();
    image_ = std::move(*image);
  }

  std::unique_ptr<ELFImage> image_;
};

TEST_F(ELFImageTest, FindsEHFrame) {
  EXPECT_TRUE(image_->has_eh_frame());
  EXPECT_GT(image_->eh_frame_end(), image_->eh_frame_start());
  EXPECT_NE(image_->eh_frame_hdr(), 0u);
}

TEST_F(ELFImageTest, BiasRoundTrips) {
  uint64_t vaddr = image_->eh_frame_start();
  EXPECT_EQ(image_->ToVaddr(image_->ToImage(vaddr)), vaddr);
}

// The fake load exists so that the vaddr distance between two sections
// is preserved in the mapping. If it were not, every pcrel pointer in
// .eh_frame would decode to the wrong place.
TEST_F(ELFImageTest, PreservesVaddrDistancesAcrossSections) {
  ASSERT_FALSE(image_->func_symbols().empty());
  uint64_t code = image_->func_symbols().front().vaddr;
  uint64_t eh_frame = image_->eh_frame_start();
  int64_t vaddr_delta = static_cast<int64_t>(eh_frame) - static_cast<int64_t>(code);
  int64_t image_delta = static_cast<int64_t>(image_->ToImage(eh_frame)) - static_cast<int64_t>(image_->ToImage(code));
  EXPECT_EQ(vaddr_delta, image_delta);
}

TEST_F(ELFImageTest, MapsCodeBytesThatMatchTheFile) {
  ASSERT_FALSE(image_->func_symbols().empty());
  const FuncSymbol& sym = image_->func_symbols().front();
  std::span<const uint8_t> bytes = image_->BytesAt(sym.vaddr, 8);
  ASSERT_EQ(bytes.size(), 8u);
  // good_leaf starts with `mov %edi, %eax`; whichever symbol sorts first,
  // executable code is never all zeroes.
  EXPECT_NE(absl::c_count(bytes, 0), 8);
}

TEST_F(ELFImageTest, KnowsWhichAddressesAreExecutable) {
  ASSERT_FALSE(image_->func_symbols().empty());
  EXPECT_TRUE(image_->IsExecutable(image_->func_symbols().front().vaddr, 1));
  EXPECT_FALSE(image_->IsExecutable(image_->eh_frame_start(), 1)) << ".eh_frame is read-only data";
  EXPECT_FALSE(image_->IsExecutable(0, 1));
}

TEST_F(ELFImageTest, ReadsFunctionSymbolsSortedByAddress) {
  const std::vector<FuncSymbol>& syms = image_->func_symbols();
  ASSERT_FALSE(syms.empty());
  EXPECT_TRUE(std::is_sorted(syms.begin(), syms.end(),
                             [](const FuncSymbol& a, const FuncSymbol& b) { return a.vaddr < b.vaddr; }));
  EXPECT_THAT(syms, Contains(Field(&FuncSymbol::name, "good_leaf")));
  EXPECT_THAT(syms, Contains(Field(&FuncSymbol::name, "bad_hoisted_add")));
}

TEST_F(ELFImageTest, RejectsThingsThatAreNotX8664ELF) {
  EXPECT_FALSE(ELFImage::Open("/nonexistent/definitely-not-here").ok());
  EXPECT_FALSE(ELFImage::Open("testdata/fixtures.S").ok()) << "a text file is not an ELF";
}

}  // namespace
}  // namespace unwind_analysis

/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "cfi-table.h"

#include <algorithm>

#include "absl/strings/str_format.h"
#include "eh-frame-reader.h"

namespace unwind_analysis {

namespace {

constexpr const char* kRegNames[] = {"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8",
                                     "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "ra"};

// Turns the CFI opcode stream of one FDE into a row table.
//
// Everything policy-shaped lives here, per the reader's decoder/visitor
// split: the decoder hands us already-scaled offsets and a final
// HandleSetLoc(function_end) that closes the last row like any other.
class TableBuilder : public UnwindVisitor {
 public:
  explicit TableBuilder(uint64_t fde_vaddr) {
    result_.fde_addr = fde_vaddr;
  }

  FdeCfi TakeResult() {
    return std::move(result_);
  }

  bool StartFDE(uintptr_t return_reg, uintptr_t pc_start, uintptr_t pc_end) {
    result_.return_reg = static_cast<int>(return_reg);
    result_.pc_begin = pc_start - bias_;
    result_.pc_end = pc_end - bias_;
    row_pc_ = result_.pc_begin;
    return true;
  }

  void set_bias(uintptr_t bias) {
    bias_ = bias;
  }

  bool HandleAugS() {
    result_.signal_frame = true;
    return true;
  }

  bool AfterCIE() {
    std::copy(std::begin(cur_regs_), std::end(cur_regs_), std::begin(cie_regs_));
    return true;
  }

  bool HandleSetLoc(uintptr_t new_pc) {
    uint64_t pc = new_pc - bias_;
    // Zero-width rows happen whenever two advances land on the same PC;
    // the later rules win and there is nothing to record for the first.
    if (pc > row_pc_) {
      CfiRow row;
      row.pc_start = row_pc_;
      row.cfa = cur_cfa_;
      std::copy(std::begin(cur_regs_), std::end(cur_regs_), std::begin(row.regs));
      result_.rows.push_back(row);
    }
    row_pc_ = pc;
    return true;
  }

  bool HandleDefCFA(uintptr_t reg, uintptr_t offset) {
    cur_cfa_ = CfaRule{CfaRule::Kind::kRegOffset, static_cast<uint8_t>(reg), static_cast<int64_t>(offset)};
    return true;
  }

  bool HandleDefCFAReg(uintptr_t reg) {
    cur_cfa_.kind = CfaRule::Kind::kRegOffset;
    cur_cfa_.reg = static_cast<uint8_t>(reg);
    return true;
  }

  bool HandleDefCFAOffset(uintptr_t offset) {
    cur_cfa_.kind = CfaRule::Kind::kRegOffset;
    cur_cfa_.offset = static_cast<int64_t>(offset);
    return true;
  }

  bool HandleDefCFAExpression(std::span<const uint8_t> expr) {
    (void)expr;
    cur_cfa_ = CfaRule{CfaRule::Kind::kExpression, 0, 0};
    return true;
  }

  bool HandleOffset(uintptr_t reg, uintptr_t new_offset) {
    return SetRule(reg, RegRule{RegRule::Kind::kAtCfaOffset, 0, static_cast<int64_t>(new_offset)});
  }

  bool HandleRegister(uintptr_t reg, uintptr_t stored_in_reg) {
    return SetRule(reg, RegRule{RegRule::Kind::kInRegister, static_cast<uint8_t>(stored_in_reg), 0});
  }

  bool HandleRestore(uintptr_t reg) {
    if (reg >= kNumDwarfRegs) {
      result_.has_exotic_regs = true;
      return true;
    }
    cur_regs_[reg] = cie_regs_[reg];
    return true;
  }

  bool HandleSameValue(uintptr_t reg) {
    return SetRule(reg, RegRule{RegRule::Kind::kSameValue, 0, 0});
  }

  bool HandleUndefined(uintptr_t reg) {
    return SetRule(reg, RegRule{RegRule::Kind::kUndefined, 0, 0});
  }

  bool HandleValOffset(uintptr_t reg, uintptr_t offset) {
    return SetRule(reg, RegRule{RegRule::Kind::kValOffset, 0, static_cast<int64_t>(offset)});
  }

  bool HandleExpression(uintptr_t reg, std::span<const uint8_t> expr) {
    (void)expr;
    return SetRule(reg, RegRule{RegRule::Kind::kExpression, 0, 0});
  }

  bool HandleValExpression(uintptr_t reg, std::span<const uint8_t> expr) {
    (void)expr;
    return SetRule(reg, RegRule{RegRule::Kind::kValExpression, 0, 0});
  }

  bool HandleRememberState() {
    if (stack_.size() >= kMaxRememberDepth) {
      throw EhFrameError("DW_CFA_remember_state nested deeper than 32 levels");
    }
    Saved s;
    s.cfa = cur_cfa_;
    std::copy(std::begin(cur_regs_), std::end(cur_regs_), std::begin(s.regs));
    stack_.push_back(s);
    return true;
  }

  bool HandleRestoreState() {
    if (stack_.empty()) {
      throw EhFrameError("DW_CFA_restore_state with nothing remembered");
    }
    cur_cfa_ = stack_.back().cfa;
    std::copy(std::begin(stack_.back().regs), std::end(stack_.back().regs), std::begin(cur_regs_));
    stack_.pop_back();
    return true;
  }

 private:
  static constexpr size_t kMaxRememberDepth = 32;

  struct Saved {
    CfaRule cfa;
    RegRule regs[kNumDwarfRegs];
  };

  bool SetRule(uintptr_t reg, const RegRule& rule) {
    if (reg >= kNumDwarfRegs) {
      // SSE and friends. Real code does describe them occasionally; we
      // note it and move on rather than refusing the whole FDE.
      result_.has_exotic_regs = true;
      return true;
    }
    cur_regs_[reg] = rule;
    return true;
  }

  FdeCfi result_;
  uintptr_t bias_ = 0;
  uint64_t row_pc_ = 0;
  CfaRule cur_cfa_;
  RegRule cur_regs_[kNumDwarfRegs];
  RegRule cie_regs_[kNumDwarfRegs];
  std::vector<Saved> stack_;
};

}  // namespace

const char* DwarfRegName(int reg) {
  if (reg < 0 || reg >= kNumDwarfRegs) {
    return "r?";
  }
  return kRegNames[reg];
}

std::string CfaRule::ToString() const {
  switch (kind) {
    case Kind::kUndefined:
      return "<no CFA rule>";
    case Kind::kRegOffset:
      return absl::StrFormat("%s%+d", DwarfRegName(reg), static_cast<int>(offset));
    case Kind::kExpression:
      return "<DWARF expression>";
  }
  return "<?>";
}

std::string RegRule::ToString() const {
  switch (kind) {
    case Kind::kUnset:
      return "<no rule>";
    case Kind::kUndefined:
      return "undefined";
    case Kind::kSameValue:
      return "same_value";
    case Kind::kAtCfaOffset:
      return absl::StrFormat("[CFA%+d]", static_cast<int>(offset));
    case Kind::kValOffset:
      return absl::StrFormat("CFA%+d", static_cast<int>(offset));
    case Kind::kInRegister:
      return absl::StrFormat("in %s", DwarfRegName(reg));
    case Kind::kExpression:
      return "<DWARF expression>";
    case Kind::kValExpression:
      return "<DWARF val expression>";
  }
  return "<?>";
}

const CfiRow* FdeCfi::RowAt(uint64_t pc) const {
  if (pc < pc_begin || pc >= pc_end || rows.empty()) {
    return nullptr;
  }
  // Last row whose pc_start <= pc.
  auto it =
      std::upper_bound(rows.begin(), rows.end(), pc, [](uint64_t v, const CfiRow& row) { return v < row.pc_start; });
  if (it == rows.begin()) {
    return nullptr;
  }
  return &*(it - 1);
}

FdeCfi ReadFde(uint64_t fde_vaddr, uint64_t eh_frame_start, uint64_t eh_frame_end, uintptr_t bias) {
  TableBuilder builder{fde_vaddr};
  builder.set_bias(bias);
  EHReaderInputs inputs{};
  inputs.lookup_pc = 0;
  inputs.eh_frame_hdr = 0;
  inputs.eh_frame_start = static_cast<uintptr_t>(eh_frame_start) + bias;
  inputs.eh_frame_end = static_cast<uintptr_t>(eh_frame_end) + bias;
  DecodeFDEAt(inputs, static_cast<uintptr_t>(fde_vaddr) + bias, &builder);
  FdeCfi result = builder.TakeResult();
  if (result.rows.empty() && result.pc_end > result.pc_begin) {
    throw EhFrameError(absl::StrFormat("FDE at 0x%016zx produced no rows", fde_vaddr));
  }
  return result;
}

}  // namespace unwind_analysis

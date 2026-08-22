/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef CFI_TABLE_H_
#define CFI_TABLE_H_

#include <stdint.h>

#include <string_view>
#include <vector>

#include "absl/strings/str_format.h"

namespace unwind_analysis {

// DWARF register numbers 0..15 are the GPRs; 16 is RIP, which is how the
// return address is named in the x86-64 psABI.
inline constexpr int kNumGPRs = 16;
inline constexpr int kDWARFRip = 16;
inline constexpr int kNumDWARFRegs = 17;

inline constexpr int kDWARFRax = 0;
inline constexpr int kDWARFRdx = 1;
inline constexpr int kDWARFRcx = 2;
inline constexpr int kDWARFRbx = 3;
inline constexpr int kDWARFRsi = 4;
inline constexpr int kDWARFRdi = 5;
inline constexpr int kDWARFRbp = 6;
inline constexpr int kDWARFRsp = 7;

// Name of a DWARF register number, for diagnostics ("rbp", "r12", "ra").
std::string_view DWARFRegName(int reg);

// How the CFI says the CFA is computed at some PC.
struct CFARule {
  enum class Kind : uint8_t {
    kUndefined,   // never stated
    kRegOffset,   // CFA = reg + offset
    kExpression,  // DW_CFA_def_cfa_expression; not evaluated here
  };

  Kind kind = Kind::kUndefined;
  uint8_t reg = 0;
  int64_t offset = 0;

  bool operator==(const CFARule&) const = default;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const CFARule& rule) {
    switch (rule.kind) {
      case Kind::kUndefined:
        sink.Append("<no CFA rule>");
        return;
      case Kind::kRegOffset:
        absl::Format(&sink, "%s%+d", DWARFRegName(rule.reg), static_cast<int>(rule.offset));
        return;
      case Kind::kExpression:
        sink.Append("<DWARF expression>");
        return;
    }
    sink.Append("<?>");
  }
};

// How the CFI says one register's caller value is recovered at some PC.
struct RegRule {
  enum class Kind : uint8_t {
    kUnset,          // no rule; the caller decides what that means
    kUndefined,      // DW_CFA_undefined: not recoverable (legitimately, at _start)
    kSameValue,      // still holds the caller's value
    kAtCFAOffset,    // saved in memory at CFA + offset
    kValOffset,      // the value *is* CFA + offset
    kInRegister,     // moved into another register
    kExpression,     // DW_CFA_expression; not evaluated here
    kValExpression,  // DW_CFA_val_expression; not evaluated here
  };

  Kind kind = Kind::kUnset;
  uint8_t reg = 0;
  int64_t offset = 0;

  bool operator==(const RegRule&) const = default;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const RegRule& rule) {
    switch (rule.kind) {
      case Kind::kUnset:
        sink.Append("<no rule>");
        return;
      case Kind::kUndefined:
        sink.Append("undefined");
        return;
      case Kind::kSameValue:
        sink.Append("same_value");
        return;
      case Kind::kAtCFAOffset:
        absl::Format(&sink, "[CFA%+d]", static_cast<int>(rule.offset));
        return;
      case Kind::kValOffset:
        absl::Format(&sink, "CFA%+d", static_cast<int>(rule.offset));
        return;
      case Kind::kInRegister:
        absl::Format(&sink, "in %s", DWARFRegName(rule.reg));
        return;
      case Kind::kExpression:
        sink.Append("<DWARF expression>");
        return;
      case Kind::kValExpression:
        sink.Append("<DWARF val expression>");
        return;
    }
    sink.Append("<?>");
  }
};

// One row of the FDE's virtual unwind table: the rules in force from
// pc_start until the next row's pc_start.
struct CFIRow {
  uint64_t pc_start = 0;
  CFARule cfa;
  RegRule regs[kNumDWARFRegs];

  // Whether this row describes the canonical x86-64 state on entry from a
  // `call`: CFA = rsp+8, with the return address at [CFA-8]. True of a
  // genuine function entry; false of e.g. a PLT trampoline's target or a
  // `.cold` fragment reached mid-function.
  bool IsCanonicalEntry() const;
};

// One decoded FDE.
struct CFI {
  uint64_t fde_addr = 0;  // vaddr of the FDE record itself, for diagnostics
  uint64_t pc_begin = 0;
  uint64_t pc_end = 0;
  int return_reg = kDWARFRip;
  bool signal_frame = false;
  // vaddr of this FDE's LSDA (.gcc_except_table entry), or 0 when the FDE
  // carries none. Landing pads named in it are code the CFG walk cannot
  // otherwise reach, since nothing in the function body branches there.
  uint64_t lsda_addr = 0;
  // True when the CFI mentioned a register outside 0..16 (SSE registers
  // and the like). Recorded, not checked.
  bool has_exotic_regs = false;
  std::vector<CFIRow> rows;  // sorted by pc_start; rows[0].pc_start == pc_begin

  // The row in force at pc, or nullptr if pc is outside [pc_begin, pc_end).
  const CFIRow* RowAt(uint64_t pc) const;
};

// Decodes the FDE record living at fde_vaddr. eh_frame_start/end bound
// the section, both as vaddrs; bias converts a vaddr to the address the
// bytes actually live at (see ELFImage). Throws EHFrameError.
CFI ReadFDE(uint64_t fde_vaddr, uint64_t eh_frame_start, uint64_t eh_frame_end, uintptr_t bias);

}  // namespace unwind_analysis

#endif  // CFI_TABLE_H_

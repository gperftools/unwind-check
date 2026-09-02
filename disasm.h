/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#ifndef DISASM_H_
#define DISASM_H_

#include <Zydis/Zydis.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "absl/status/statusor.h"

namespace unwind_analysis {

// One decoded instruction. Zydis's own decode result (ZydisDecodedInstruction
// plus its operand array) carries no runtime address -- unlike Capstone's
// cs_insn, which bakes the address passed to the decode call into the
// result -- so this struct pairs the two back together the way every call
// site here expects.
struct Instruction {
  uint64_t address = 0;
  uint32_t size = 0;  // insn.length, in bytes
  ZydisMnemonic id = ZYDIS_MNEMONIC_INVALID;
  uint8_t op_count = 0;  // explicit operands only (operand_count_visible)
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
  ZydisDecodedInstruction insn{};  // the full decode: meta.category, cpu_flags, etc.
};

// Thin wrapper over one Zydis x86-64 decoder and formatter.
class Disassembler {
 public:
  Disassembler(const Disassembler&) = delete;
  Disassembler& operator=(const Disassembler&) = delete;

  static absl::StatusOr<std::unique_ptr<Disassembler>> Create();

  // Decodes one instruction at address, out of at most size bytes of
  // code into `out`. Returns true on success, or false when Zydis cannot decode it.
  bool Decode(const uint8_t* code, size_t size, uint64_t address, Instruction* out);

  // "add $0x8,%rsp", for diagnostics -- always AT&T syntax. Unlike
  // Capstone, where explicitly selecting AT&T syntax is known to also
  // reorder the *structured* operand array (silently breaking any code
  // that assumes operands[0] is the destination), Zydis's formatter is a
  // pure text-rendering pass over the already-decoded operands: the style
  // picked here has no effect on what Transfer() sees.
  static absl::StatusOr<std::string> Text(const Instruction& insn);

 private:
  Disassembler() = default;

  ZydisDecoder decoder_{};
};

}  // namespace unwind_analysis

#endif  // DISASM_H_

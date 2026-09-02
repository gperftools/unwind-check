/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#include "disasm.h"

#include "absl/status/status.h"
#include "absl/strings/str_format.h"

namespace unwind_analysis {

absl::StatusOr<std::unique_ptr<Disassembler>> Disassembler::Create() {
  std::unique_ptr<Disassembler> d{new Disassembler()};
  if (!ZYAN_SUCCESS(ZydisDecoderInit(&d->decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
    return absl::InternalError("ZydisDecoderInit failed");
  }
  return d;
}

bool Disassembler::Decode(const uint8_t* code, size_t size, uint64_t address, Instruction* out) {
  if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, code, size, &out->insn, out->operands))) {
    return false;
  }
  out->address = address;
  out->size = out->insn.length;
  out->id = out->insn.mnemonic;
  out->op_count = out->insn.operand_count_visible;
  return true;
}

static const ZydisFormatter* GetFormatter() {
  static const ZydisFormatter* formatter = []() {
    auto* f = new ZydisFormatter();
    if (!ZYAN_SUCCESS(ZydisFormatterInit(f, ZYDIS_FORMATTER_STYLE_ATT))) {
      return static_cast<ZydisFormatter*>(nullptr);
    }
    ZydisFormatterSetProperty(f, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
    return f;
  }();
  return formatter;
}

absl::StatusOr<std::string> Disassembler::Text(const Instruction& insn) {
  const ZydisFormatter* formatter = GetFormatter();
  if (formatter == nullptr) {
    return absl::InternalError("ZydisFormatterInit failed");
  }
  char buffer[256];
  if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(formatter, &insn.insn, insn.operands,
                                                    insn.insn.operand_count_visible, buffer, sizeof(buffer),
                                                    insn.address, nullptr))) {
    return absl::InternalError(absl::StrFormat("cannot format instruction at 0x%x", insn.address));
  }
  return std::string(buffer);
}

}  // namespace unwind_analysis

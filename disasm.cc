/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
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

const Instruction* Disassembler::DecodeOne(const uint8_t* code, size_t size, uint64_t address) {
  if (size == 0) {
    return nullptr;
  }
  if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, code, size, &insn_.insn, insn_.operands))) {
    return nullptr;
  }
  insn_.address = address;
  insn_.size = insn_.insn.length;
  insn_.id = insn_.insn.mnemonic;
  insn_.op_count = insn_.insn.operand_count_visible;
  return &insn_;
}

absl::StatusOr<std::string> Disassembler::Text(const Instruction& insn) {
  ZydisFormatter formatter;
  if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_ATT))) {
    return absl::InternalError("ZydisFormatterInit failed");
  }
  ZydisFormatterSetProperty(&formatter,
                            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL,
                            ZYAN_TRUE);
  char buffer[256];
  if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &insn.insn, insn.operands,
                                                     insn.insn.operand_count_visible, buffer, sizeof(buffer),
                                                     insn.address, nullptr))) {
    return absl::InternalError(absl::StrFormat("cannot format instruction at 0x%llx", (unsigned long long)insn.address));
  }
  return std::string(buffer);
}

}  // namespace unwind_analysis

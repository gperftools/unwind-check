/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "disasm.h"

#include "absl/status/status.h"
#include "absl/strings/str_format.h"

namespace unwind_analysis {

Disassembler::~Disassembler() {
  if (insn_ != nullptr) {
    cs_free(insn_, 1);
  }
  if (handle_ != 0) {
    cs_close(&handle_);
  }
}

absl::StatusOr<std::unique_ptr<Disassembler>> Disassembler::Create() {
  std::unique_ptr<Disassembler> d{new Disassembler()};
  cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &d->handle_);
  if (err != CS_ERR_OK) {
    return absl::InternalError(absl::StrFormat("cs_open failed: %s", cs_strerror(err)));
  }
  // Detail carries the operands and the implicit register reads/writes.
  // Both are load-bearing: operands drive the instructions we model
  // exactly, and register accesses are how everything else degrades
  // safely to "this register is now unknown".
  err = cs_option(d->handle_, CS_OPT_DETAIL, CS_OPT_ON);
  if (err != CS_ERR_OK) {
    return absl::InternalError(absl::StrFormat("cs_option(CS_OPT_DETAIL) failed: %s", cs_strerror(err)));
  }
  d->insn_ = cs_malloc(d->handle_);
  if (d->insn_ == nullptr) {
    return absl::ResourceExhaustedError("cs_malloc failed");
  }
  return d;
}

const cs_insn* Disassembler::DecodeOne(const uint8_t* code, size_t size, uint64_t address) {
  if (size == 0) {
    return nullptr;
  }
  const uint8_t* cursor = code;
  size_t remaining = size;
  uint64_t addr = address;
  if (!cs_disasm_iter(handle_, &cursor, &remaining, &addr, insn_)) {
    return nullptr;
  }
  return insn_;
}

std::string Disassembler::Text(const cs_insn& insn) {
  if (insn.op_str[0] == '\0') {
    return insn.mnemonic;
  }
  return absl::StrFormat("%s %s", insn.mnemonic, insn.op_str);
}

}  // namespace unwind_analysis

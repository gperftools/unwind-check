/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef DISASM_H_
#define DISASM_H_

#include <capstone/capstone.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "absl/status/statusor.h"

namespace unwind_analysis {

// Thin RAII wrapper over one Capstone x86-64 handle, with detail (and so
// operand and register-access information) turned on.
class Disassembler {
 public:
  Disassembler(const Disassembler&) = delete;
  Disassembler& operator=(const Disassembler&) = delete;
  ~Disassembler();

  static absl::StatusOr<std::unique_ptr<Disassembler>> Create();

  csh handle() const {
    return handle_;
  }

  // Decodes one instruction at address, out of at most size bytes of
  // code. Returns nullptr when Capstone cannot decode it. The result is
  // owned by this object and is valid only until the next call.
  const cs_insn* DecodeOne(const uint8_t* code, size_t size, uint64_t address);

  // "add $0x8, %rsp", for diagnostics.
  static std::string Text(const cs_insn& insn);

 private:
  Disassembler() = default;

  csh handle_ = 0;
  cs_insn* insn_ = nullptr;
};

}  // namespace unwind_analysis

#endif  // DISASM_H_

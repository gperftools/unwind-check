/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "eh-frame-reader.h"

#include <string.h>

#include "absl/strings/str_format.h"

namespace unwind_analysis {

namespace {

// Reads one little-endian uint32 at addr, bounds-checked against end.
uint32_t ReadU32(uintptr_t addr, uintptr_t end, const char* what) {
  if (addr + sizeof(uint32_t) > end || addr + sizeof(uint32_t) < addr) {
    throw EhFrameError(absl::StrFormat("truncated .eh_frame while reading %s at 0x%016zx", what, addr));
  }
  uint32_t rv;
  memcpy(&rv, reinterpret_cast<const void*>(addr), sizeof(rv));
  return rv;
}

}  // namespace

void EnumerateFDEs(uintptr_t eh_frame_start, uintptr_t eh_frame_end,
                   absl::FunctionRef<void(uintptr_t fde_addr)> callback) {
  uintptr_t pos = eh_frame_start;
  // Every record is <u32 length><u32 cie_id_or_backref><payload>. A
  // zero length is the section terminator; cie_id == 0 means the record
  // is a CIE, anything else means it is an FDE whose value is the
  // backwards distance to its CIE.
  while (pos + 2 * sizeof(uint32_t) <= eh_frame_end) {
    uint32_t len = ReadU32(pos, eh_frame_end, "record length");
    if (len == 0) {
      return;  // terminator
    }
    if (len == 0xffffffff) {
      throw EhFrameError(absl::StrFormat("64-bit DWARF length at 0x%016zx is not supported", pos));
    }
    uintptr_t payload = pos + sizeof(uint32_t);
    uintptr_t next = payload + len;
    if (next <= pos || next > eh_frame_end) {
      throw EhFrameError(absl::StrFormat("record at 0x%016zx claims length %u, overrunning the section", pos, len));
    }
    if (ReadU32(payload, eh_frame_end, "CIE id") != 0) {
      callback(pos);
    }
    pos = next;
  }
}

}  // namespace unwind_analysis

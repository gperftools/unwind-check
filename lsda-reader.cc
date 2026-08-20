/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "lsda-reader.h"

#include <string.h>

#include <algorithm>

#include "absl/strings/str_format.h"
#include "dwarf-constants.h"
#include "eh-frame-reader.h"  // EhFrameError

namespace unwind_analysis {

namespace {

// A byte cursor over the LSDA, working in plain vaddr arithmetic via
// ElfImage::BytesAt. Unlike eh-frame-reader.h's Decoder, this has no
// need for live pointers and their bias -- that reader is shared with an
// online unwinder that only ever sees live memory, but nothing here is,
// so vaddrs are simplest.
class LsdaCursor {
 public:
  LsdaCursor(const ElfImage& image, uint64_t vaddr) : image_(image), vaddr_(vaddr) {
  }

  uint64_t vaddr() const {
    return vaddr_;
  }

  uint8_t ReadU8() {
    std::span<const uint8_t> b = image_.BytesAt(vaddr_, 1);
    if (b.empty()) {
      throw EhFrameError("gcc_except_table: read past mapped data");
    }
    vaddr_ += 1;
    return b[0];
  }

  uint64_t ReadUleb128() {
    uint64_t result = 0;
    unsigned shift = 0;
    while (true) {
      if (shift >= 64) {
        throw EhFrameError("gcc_except_table: uleb128 overflow");
      }
      uint8_t byte = ReadU8();
      result |= static_cast<uint64_t>(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) {
        break;
      }
      shift += 7;
    }
    return result;
  }

  // Reads a fixed-width little-endian field, optionally pc-relative.
  uint64_t ReadFixed(size_t size, bool is_signed, bool pcrel) {
    uint64_t base = pcrel ? vaddr_ : 0;
    std::span<const uint8_t> b = image_.BytesAt(vaddr_, size);
    if (b.size() < size) {
      throw EhFrameError("gcc_except_table: truncated data");
    }
    uint64_t raw = 0;
    memcpy(&raw, b.data(), size);
    vaddr_ += size;
    if (is_signed && size < 8) {
      uint64_t sign_bit = uint64_t{1} << (size * 8 - 1);
      if (raw & sign_bit) {
        raw |= ~((sign_bit << 1) - 1);
      }
    }
    return base + raw;
  }

  // Reads one field of the call-site table (start / length / landing
  // pad), whose encoding is call_site_encoding. In practice gcc and
  // clang always use DW_EH_PE_uleb128 here; the fixed-width forms are
  // supported defensively, in the same vaddr-relative sense
  // eh-frame-reader.h's ReadEncodedPtr uses for live pointers.
  uint64_t ReadEncoded(uint8_t encoding) {
    uint8_t lo = encoding & 0x0f;
    uint8_t hi = encoding & 0xf0;
    if (lo == DW_EH_PE_uleb128) {
      return ReadUleb128();
    }
    bool pcrel = false;
    if (hi == DW_EH_PE_pcrel) {
      pcrel = true;
    } else if (hi != 0) {
      throw EhFrameError(absl::StrFormat("gcc_except_table: unsupported encoding 0x%02x", encoding));
    }
    switch (lo) {
      case DW_EH_PE_udata2:
        return ReadFixed(2, false, pcrel);
      case DW_EH_PE_sdata4:
        return ReadFixed(4, true, pcrel);
      case DW_EH_PE_udata4:
        return ReadFixed(4, false, pcrel);
      case DW_EH_PE_sdata8:
      case DW_EH_PE_udata8:
      case DW_EH_PE_absptr:
        return ReadFixed(8, false, pcrel);
      default:
        throw EhFrameError(absl::StrFormat("gcc_except_table: unsupported encoding 0x%02x", encoding));
    }
  }

 private:
  const ElfImage& image_;
  uint64_t vaddr_;
};

}  // namespace

std::vector<uint64_t> ReadLsdaLandingPads(const ElfImage& image, uint64_t lsda_vaddr, uint64_t fde_pc_begin) {
  LsdaCursor cur(image, lsda_vaddr);

  uint8_t start_encoding = cur.ReadU8();
  uint64_t lpstart = fde_pc_begin;
  if (start_encoding != DW_EH_PE_omitted) {
    lpstart = cur.ReadEncoded(start_encoding);
  }

  uint8_t type_encoding = cur.ReadU8();
  if (type_encoding != DW_EH_PE_omitted) {
    cur.ReadUleb128();  // ttype_offset; the type table itself is never needed here
  }

  uint8_t call_site_encoding = cur.ReadU8();
  uint64_t call_site_table_length = cur.ReadUleb128();
  uint64_t call_site_table_end = cur.vaddr() + call_site_table_length;

  std::vector<uint64_t> landing_pads;
  while (cur.vaddr() < call_site_table_end) {
    cur.ReadEncoded(call_site_encoding);                          // call-site start; unused
    cur.ReadEncoded(call_site_encoding);                          // call-site length; unused
    uint64_t landing_pad_offset = cur.ReadEncoded(call_site_encoding);
    cur.ReadUleb128();                                            // action table index; unused

    if (landing_pad_offset != 0) {
      landing_pads.push_back(lpstart + landing_pad_offset);
    }
  }

  std::sort(landing_pads.begin(), landing_pads.end());
  landing_pads.erase(std::unique(landing_pads.begin(), landing_pads.end()), landing_pads.end());
  return landing_pads;
}

}  // namespace unwind_analysis

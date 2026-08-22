/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef EH_FRAME_READER_H_
#define EH_FRAME_READER_H_
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <concepts>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/base/optimization.h"
#include "absl/functional/function_ref.h"
#include "dwarf-constants.h"

// Decoding half of the .eh_frame/.eh_frame_hdr machinery: finding the
// FDE that covers a PC, parsing the CIE/FDE headers and interpreting
// the CFI instruction stream. Everything policy-shaped -- what the
// rows mean, which registers matter, which unsupported constructs may
// be pattern-matched anyways -- lives in the visitor.
//
// Adapted from backtrace-test's runtime unwinder. Two changes, both
// enabled by this tool being offline rather than async-signal-safe:
//
//  * failures throw EHFrameError instead of taking a non-local exit
//    that runs no destructors, so one malformed FDE costs one report
//    line rather than the process;
//  * FDEs can be enumerated linearly over the whole section, not just
//    looked up one-at-a-time through .eh_frame_hdr's binary search.

namespace unwind_analysis {

// Thrown on any malformed or unsupported .eh_frame construct. Callers
// catch it per-FDE and turn it into a diagnostic.
class EHFrameError : public std::runtime_error {
 public:
  explicit EHFrameError(std::string what) : std::runtime_error(std::move(what)) {
  }
};

struct EHReaderInputs {
  uintptr_t lookup_pc;
  uintptr_t eh_frame_hdr;  // address of header of .eh_frame_hdr

  // conservative bounds. Usually larger than actual .eh_frame{,_hdr} stuff
  uintptr_t eh_frame_start;
  uintptr_t eh_frame_end;
};

// NOTE: Visitor callbacks can return false if they want decoding loop to exit.
//
// Sequence: StartFDE -> HandleXYZ (*) -> AfterCIE -> HandleXYZ (*)
//
// Note, if no FDE covers lookup_pc (or the .eh_frame_hdr search finds
// nothing at all), no callback is invoked at all. That, and only that,
// is how "not found" is signalled.
//
// Note also, all offsets and locations are given to the visitor
// already multiplied by the CIE's code/data alignment factors. Offsets
// that the spec doesn't scale (DW_CFA_def_cfa{,_offset}) aren't
// scaled. Scaled offsets are signed and are passed as uintptr_t simply
// bit-casted from intptr_t.
//
// We currently don't expose the personality routine pointer because we
// don't use it, but it could be easily added the same way HandleLSDA was.
struct UnwindVisitor {
  bool StartFDE(uintptr_t return_reg, uintptr_t pc_start, uintptr_t pc_end);

  bool HandleAugS();  // when 'S' aug character signals this is signal trampoline
  bool AfterCIE();    // i.e. to snapshot "table" after CIE is read

  // Called once per FDE, only when the CIE augmentation string contains
  // 'L'. lsda_ptr is the resolved address of this FDE's LSDA
  // (.gcc_except_table entry), in the same live-pointer address space as
  // every other pointer this reader hands out. Some FDEs sharing a CIE
  // that has 'L' still carry no real LSDA of their own; that shows up as
  // lsda_ptr == 0 and is not itself an error.
  bool HandleLSDA(uintptr_t lsda_ptr);

  // Note, when the FDE's instructions run out we invoke this one last
  // time with function_end. So the final row is closed just like every
  // other row is.
  bool HandleSetLoc(uintptr_t new_pc);

  bool HandleDefCFA(uintptr_t reg, uintptr_t offset);
  bool HandleDefCFAReg(uintptr_t reg);
  bool HandleDefCFAOffset(uintptr_t offset);
  bool HandleDefCFAExpression(std::span<const uint8_t> expr);

  bool HandleOffset(uintptr_t reg, uintptr_t new_offset);
  bool HandleRegister(uintptr_t reg, uintptr_t stored_in_reg);
  bool HandleRestore(uintptr_t reg);
  bool HandleSameValue(uintptr_t reg);
  bool HandleUndefined(uintptr_t reg);
  bool HandleValOffset(uintptr_t reg, uintptr_t offset);
  bool HandleExpression(uintptr_t reg, std::span<const uint8_t> expr);
  bool HandleValExpression(uintptr_t reg, std::span<const uint8_t> expr);

  bool HandleRememberState();
  bool HandleRestoreState();
};

namespace eh_frame_internal {

struct EHReaderState {
  // current PC/location
  uintptr_t current_loc;
  // PC of the end of function (exclusive).
  uintptr_t function_end;

  // Note, those are as wide as the CIE can make them. Narrowing them
  // to something denser is a concern of whoever caches this state.
  uintptr_t code_align;
  intptr_t data_align;

  uint8_t fde_ptr_enc;
};

template <std::derived_from<UnwindVisitor> V>
class Decoder {
 public:
  Decoder(EHReaderInputs inputs, V* v)
      : v_{v}, inputs_{inputs}, bounds_{inputs.eh_frame_start, inputs.eh_frame_end}, state_{} {
  }

  void FindAndDecode() {
    uintptr_t fde = FindFDE();
    if (!fde) {
      return;
    }
    ParseFDE(fde);
  }

  // Decodes the FDE at this exact address, whatever PC range it
  // covers. This is the enumeration entry point; FindAndDecode is the
  // .eh_frame_hdr lookup one.
  void DecodeFDEAt(uintptr_t fde_addr) {
    match_all_ = true;
    ParseFDE(fde_addr);
  }

 protected:
  using byte_slice = std::span<const uint8_t>;

  // Report and leave. Upstream this took a non-local exit; here it
  // throws, which is why this file may own things by RAII and the
  // original may not.
  [[noreturn]] __attribute__((format(printf, 2, 3), noinline)) void Fail(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    throw EHFrameError(buf);
  }

  template <typename T>
  T ReadObject(byte_slice* slice) {
    if (slice->size() < sizeof(T)) {
      Fail("eh_frame read error: truncated data");
    }

    T rv{};
    memcpy(&rv, slice->data(), sizeof(rv));
    *slice = slice->subspan(sizeof(rv));
    return rv;
  }

  // Interprets next N * sizeof(T) bytes as array of Ts. T has to be
  // POD. Checks size and alignment. slice is advanced by the 'eaten'
  // amount.
  template <typename T>
  std::span<const T> ReadSubslice(byte_slice* slice, size_t n) {
    static_assert(std::is_trivially_default_constructible_v<T>);
    static_assert(std::is_trivially_destructible_v<T>);
    size_t align = alignof(T);
    if ((reinterpret_cast<uintptr_t>(slice->data()) & (align - 1)) != 0) {
      Fail("eh_frame read error: insufficient alignment. Align needed: %zu, address: 0x%zx", align,
           reinterpret_cast<uintptr_t>(slice->data()));
    }
    size_t need_size;
    if (__builtin_mul_overflow(n, sizeof(T), &need_size)) {
      Fail("eh_frame read error: ReadSubslice overflow. n * sizeof(T) = %zd * %zd", n, sizeof(T));
    }
    if (slice->size() < need_size) {
      Fail("eh_frame read error: truncated data");
    }
    const T* start = reinterpret_cast<const T*>(slice->data());
    *slice = slice->subspan(need_size);
    return {start, n};
  }

  uintptr_t ReadUleb128(byte_slice* slice) {
    uintptr_t result = 0;
    uintptr_t shift = 0;
    constexpr uintptr_t max_shift = 8 * sizeof(uintptr_t);
    while (true) {
      if (shift >= max_shift) {
        Fail("eh_frame read error: uleb128 overflow");
      }
      uint8_t byte = ReadObject<uint8_t>(slice);
      if (shift > max_shift - 7 && ((byte & 0x7f) >> (max_shift - shift)) != 0) {
        Fail("eh_frame read error: uleb128 overflow");
      }
      result |= static_cast<uintptr_t>(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0)
        break;
      shift += 7;
    }
    return result;
  }

  intptr_t ReadSleb128(byte_slice* slice) {
    uintptr_t result = 0;
    uintptr_t shift = 0;
    constexpr uintptr_t max_shift = 8 * sizeof(uintptr_t);
    uint8_t byte;
    do {
      if (shift >= max_shift) {
        Fail("eh_frame read error: sleb128 overflow");
      }
      byte = ReadObject<uint8_t>(slice);
      if (shift > max_shift - 7) {
        uint8_t payload = byte & 0x7f;
        uint8_t sign_bit = (payload >> (max_shift - shift - 1)) & 1;
        uint8_t extra_bits = payload >> (max_shift - shift);
        uint8_t expected_extra = sign_bit ? ((1u << (7 - (max_shift - shift))) - 1) : 0;
        if (extra_bits != expected_extra) {
          Fail("eh_frame read error: sleb128 overflow");
        }
      }
      result |= static_cast<uintptr_t>(byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    if ((shift < max_shift) && (byte & 0x40)) {
      result |= static_cast<uintptr_t>(-1) << shift;
    }
    return static_cast<intptr_t>(result);
  }

  uintptr_t ReadEncodedPtr(byte_slice* slice, uint8_t encoding) {
    uint8_t lo = encoding & 0x0f;
    uint8_t hi = encoding & 0xf0;
    uintptr_t pcrel_base = 0;
    if (ABSL_PREDICT_TRUE(hi == DW_EH_PE_pcrel)) {
      pcrel_base = reinterpret_cast<uintptr_t>(slice->data());
    } else if (hi != 0) {
      // we don't support complex/adventurous encodings
      goto bad_encoding;
    }

    static_assert(sizeof(uintptr_t) == 8);  // 64-bit machines for now
    if (ABSL_PREDICT_TRUE(lo == DW_EH_PE_sdata4)) {
      return pcrel_base + ReadObject<int32_t>(slice);  // sign extends
    } else if (lo == DW_EH_PE_udata4) {
      return pcrel_base + ReadObject<uint32_t>(slice);
    } else if (lo == DW_EH_PE_udata8 || lo == DW_EH_PE_sdata8 || lo == DW_EH_PE_absptr) {
      return pcrel_base + ReadObject<uintptr_t>(slice);
    }

  bad_encoding:
    Fail("eh_frame read error: reading unsupported pointer format: 0x%02x", encoding);
  }

  const char* ReadASCIIZ(byte_slice* slice, size_t max_size) {
    const uint8_t* start = slice->data();
    auto zero = static_cast<const uint8_t*>(memchr(start, '\0', std::min(max_size, slice->size())));
    if (zero == nullptr) {
      Fail("eh_frame read error: truncated data while reading asciiz string");
    }
    *slice = slice->subspan(zero + 1 - start);
    return reinterpret_cast<const char*>(start);
  }

  void TruncateSlice(byte_slice* slice, size_t size) {
    if (slice->size() < size) {
      Fail("eh_frame read error: truncated data in TruncateSlice");
    }
    *slice = slice->subspan(0, size);
  }

  uintptr_t FindFDE();
  void ParseFDE(uintptr_t raw_fde_ptr);
  // Returns false if the visitor asked us to stop, true if the stream
  // ran out.
  bool RunInstructions(byte_slice slice, bool is_cie);

  byte_slice MakeSlice(uintptr_t start_addr) {
    if (!(bounds_.first <= start_addr && start_addr <= bounds_.second)) {
      Fail("out of bounds address 0x%016zx vs (0x%016zx, 0x%016zx)", start_addr, bounds_.first, bounds_.second);
    }
    return {reinterpret_cast<const uint8_t*>(start_addr), bounds_.second - start_addr};
  }

  bool DoSetLoc(uintptr_t new_loc, bool is_cie) {
    if (is_cie) {
      Fail("CIE initial instruction cannot advance");
    }
    state_.current_loc = new_loc;
    return v_->HandleSetLoc(new_loc);
  }

  uintptr_t code_align() const {
    return state_.code_align;
  }

  intptr_t data_align() const {
    return state_.data_align;
  }

  V* const v_;
  const EHReaderInputs inputs_;
  const std::pair<uintptr_t, uintptr_t> bounds_;
  EHReaderState state_;
  // Set by DecodeFDEAt: accept the FDE regardless of inputs_.lookup_pc.
  bool match_all_ = false;
};

struct EHFrameHdr {
  uint8_t version;
  uint8_t eh_frame_ptr_enc;
  uint8_t fde_count_enc;
  uint8_t table_enc;
};

struct EHFrameHdrEntry {
  int32_t start_ip_offset;
  int32_t fde_ptr_offset;
};

template <std::derived_from<UnwindVisitor> V>
uintptr_t Decoder<V>::FindFDE() {
  byte_slice slice = MakeSlice(inputs_.eh_frame_hdr);
  const EHFrameHdr& header = ReadSubslice<EHFrameHdr>(&slice, 1)[0];
  if (header.version != 1) {
    Fail("bad eh_frame_hdr version: %d", (int)header.version);
  }

  // Skip pointer to eh_frame. We use binary search table, not linear
  // search of .eh_frame data.
  (void)ReadEncodedPtr(&slice, header.eh_frame_ptr_enc);

  uintptr_t fde_count = ReadEncodedPtr(&slice, header.fde_count_enc);

  if (fde_count == 0 || header.table_enc == DW_EH_PE_omitted) {
    Fail("no binary search table for fdes");
  }

  // We've consumed the .eh_frame_hdr header data. Now we're going to
  // process binary search table. Each entry is a pair of
  // pointers. One to PC address of the code fragment and second is
  // pointer to FDE. "Pointers" are actually signed 32-bit offsets
  // from eh_frame_hdr header address.

  // libgcc only supports datarel | sdata4 table encoding (for the
  // binary search code). They have slow sorting fallback, but we
  // don't.
  //
  // Note, this relies on proper alignment. Which is the case in
  // practice. They check this and fallback. We check and hard-error.
  if (header.table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
    Fail("unsupported table encoding: %x", (int)header.table_enc);
  }

  std::span<const EHFrameHdrEntry> entries = ReadSubslice<EHFrameHdrEntry>(&slice, fde_count);

  size_t low = 0;
  size_t high = fde_count;

  while (low < high) {
    size_t mid = (low + high) / 2;
    uintptr_t start_pc = inputs_.eh_frame_hdr + entries[mid].start_ip_offset;

    if (inputs_.lookup_pc < start_pc) {
      high = mid;
    } else {
      low = mid + 1;
    }
  }
  if (low > 0) {
    return inputs_.eh_frame_hdr + entries[low - 1].fde_ptr_offset;
  }
  return 0;
}

template <std::derived_from<UnwindVisitor> V>
void Decoder<V>::ParseFDE(uintptr_t raw_fde_ptr) {
  /**
   * Table 4.7: Frame Descriptor Entry (FDE)
   * Source: AMD64 ABI Draft 1.0
   *
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Field                     | Length (byte)| Description                                                   |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Length                    | 4            | Length of the FDE (not including this 4-byte field)           |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | CIE pointer               | 4            | Distance to nearest preceding CIE (subtracted from current    |
   * |                           |              | addr). Non-zero; used to distinguish CIEs and FDEs.           |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Initial Location          | var          | Reference to function code. If 'R' is missing from CIE        |
   * |                           |              | Augmentation String, this is an 8-byte absolute pointer.      |
   * |                           |              | Otherwise, use CIE Augmentation Section EH_PE encoding.       |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Address Range             | var          | Size of function code. If 'R' is missing from CIE             |
   * |                           |              | Augmentation String, this is an 8-byte unsigned number.       |
   * |                           |              | Otherwise, use CIE Augmentation Section EH_PE encoding.       |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Optional FDE Augmentation | var          | Present if CIE Augmentation String is non-empty.              |
   * | Section                   |              | See table 4.8 for content.                                    |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Optional Call Frame       | var          | Instruction stream for unwinding.                             |
   * | Instructions              |              |                                                               |
   * +---------------------------+--------------+---------------------------------------------------------------+
   */
  byte_slice fde_slice = MakeSlice(raw_fde_ptr);
  uint32_t len = ReadObject<uint32_t>(&fde_slice);
  if (len == 0xffffffff) {
    Fail("64-bit DWARF length in FDE is not supported");
  }

  if (len == 0) {
    Fail("empty FDE");
  }

  TruncateSlice(&fde_slice, len);

  uint32_t cie_offset = ReadObject<uint32_t>(&fde_slice);
  // Parse CIE
  // For FDE, cie_offset is offset backwards to CIE start
  byte_slice cie_slice = MakeSlice(reinterpret_cast<uintptr_t>(fde_slice.data()) - 4 - cie_offset);
  /**
   * Table 4.5: Common Information Entry (CIE)
   * Source: AMD64 ABI Draft 1.0
   *
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Field                     | Length (byte)| Description                                                   |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Length                    | 4            | Length of the CIE (not including this 4-byte field).          |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | CIE id                    | 4            | Value 0 for .eh_frame (distinguishes CIEs from FDEs).         |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Version                   | 1            | Value One (1).                                                |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | CIE Augmentation String   | string       | Null-terminated string ("" or 'z' + 'P', 'L', 'R').           |
   * |                           |              | Presence of chars dictates field 8 (Augmentation Section).    |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Code Align Factor         | uleb128      | Multiplier for "Advance Location" instructions.               |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Data Align Factor         | sleb128      | Multiplier for all offsets in Call Frame Instructions.        |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Ret Address Reg           | 1 / uleb128  | Virtual register for return address. Byte in Dwarf V2/GCC,    |
   * |                           |              | uleb128 otherwise.                                            |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Optional CIE              | varying      | Present if Augmentation String is not empty.                  |
   * | Augmentation Section      |              | See table 4.6 for content.                                    |
   * +---------------------------+--------------+---------------------------------------------------------------+
   * | Optional Call             | varying      | Initial set of Call Frame Instructions.                       |
   * | Frame Instructions        |              |                                                               |
   * +---------------------------+--------------+---------------------------------------------------------------+
   */
  uint32_t cie_len = ReadObject<uint32_t>(&cie_slice);
  if (cie_len == 0xffffffff) {
    Fail("64-bit DWARF length in CIE is not supported");
  }
  TruncateSlice(&cie_slice, cie_len);

  uint32_t cie_id = ReadObject<uint32_t>(&cie_slice);
  if (cie_id != 0) {
    Fail("Wrong cie_id field: %x", (unsigned)cie_id);
  }

  uint8_t version = ReadObject<uint8_t>(&cie_slice);
  // NOTE: libgcc seemingly supports other versions
  if (version != 1) {
    Fail("unsupported CIE version: %d", (int)version);
  }

  const char* aug_str = ReadASCIIZ(&cie_slice, 16);
  const char* orig_aug_str = aug_str;

  state_.code_align = ReadUleb128(&cie_slice);
  state_.data_align = ReadSleb128(&cie_slice);
  if (state_.code_align == 0) {
    Fail("zero code alignment factor in CIE");
  }

  // Return address register. We don't interpret it ourselves, the
  // visitor gets it via StartFDE.
  uintptr_t return_reg = ReadObject<uint8_t>(&cie_slice);

  // Usually fde pointer encoding is pcrel|sdata4, but it is then
  // specified in the augmentation data of CIE ('R'
  // character). If/when that data is missing, we use 64-bit absolute
  // encoding as noted in the spec.
  uint8_t fde_ptr_enc = DW_EH_PE_absptr;
  // Encoding of the per-FDE LSDA pointer field, from the CIE's 'L' aug
  // data. DW_EH_PE_omitted means this CIE never carries an LSDA.
  uint8_t lsda_ptr_enc = DW_EH_PE_omitted;

  // empty aug string is allowed
  if (*aug_str) {
    // But if it is non-empty then we need it to have size
    if (aug_str[0] != 'z') {
      Fail("Aug string without leading 'z'. Got: %c", aug_str[0]);
    }
    aug_str++;

    uintptr_t aug_len = ReadUleb128(&cie_slice);
    byte_slice aug_data = ReadSubslice<uint8_t>(&cie_slice, aug_len);

    while (*aug_str) {
      char ch = *aug_str++;
      if (ch == 'R') {
        // Our encoding. We pick it from cie's aug data.
        fde_ptr_enc = ReadObject<uint8_t>(&aug_data);
        break;
      }
      if (ch == 'L') {
        // L is for some LSDA pointer encoding. In this case cie
        // augmentation contains lsda field encoding and FDE
        // augmentation will hold the actual field.
        lsda_ptr_enc = ReadObject<uint8_t>(&aug_data);
        continue;
      }
      if (ch == 'S') {
        // S is how glibc marks signal frame. Note musl doesn't
        // bother. Also ABI docs don't mention 'S', but libgcc uses it
        // for 'ip_before_insn' flag.
        if (!v_->HandleAugS()) {
          return;
        }
        continue;
      }
      if (ch == 'B') {
        // B is used for some aarch64 pointer auth stuff
        //
        // Nothing in the CIE's aug for this character
        continue;
      }
      if (ch == 'P') {
        // We need to skip personality data, to continue searching for
        // aug data for fde pointer encoding.
        auto enc = ReadObject<uint8_t>(&aug_data);
        // Note, we clear 'indirect' flag from the encoding, which is
        // sometimes used and which we don't support. We don't really
        // consume personality_ptr.
        auto personality_ptr = ReadEncodedPtr(&aug_data, enc & 0x7f);
        (void)enc;
        (void)personality_ptr;
        continue;
      }

      Fail("Unknown aug string character: %c (0x%02x)", ch, (uint8_t)ch);
    }
  }

  // Back to FDE. Fetch range of addresses covered by FDE entry. Using
  // encoding we found in CIE aug data.
  uintptr_t pc_start = ReadEncodedPtr(&fde_slice, fde_ptr_enc);
  // Note, the masking is not documented by the spec, but libgcc does
  // it. To read the size covered by FDE we need to do it.
  uintptr_t pc_range = ReadEncodedPtr(&fde_slice, fde_ptr_enc & 0x0f);

  if (!match_all_ && !(pc_start <= inputs_.lookup_pc && inputs_.lookup_pc < pc_start + pc_range)) {
    // We check if FDE does cover our pc. Note, this is how "not found"
    // is signalled: we return without ever calling the visitor.
    return;
  }

  state_.current_loc = pc_start;
  state_.function_end = pc_start + pc_range;
  state_.fde_ptr_enc = fde_ptr_enc;

  if (!v_->StartFDE(return_reg, pc_start, pc_start + pc_range)) {
    return;
  }

  // Process initial instructions in CIE.
  if (!RunInstructions(cie_slice, true)) {
    return;
  }

  // FDE augmentation data. The only field it can ever carry is the LSDA
  // pointer (present iff the CIE's augmentation string had 'L'); 'P' and
  // 'R' only ever contribute to the CIE's own augmentation data, never
  // the FDE's.
  if (*orig_aug_str == 'z') {
    uintptr_t aug_len = ReadUleb128(&fde_slice);
    byte_slice fde_aug_data = ReadSubslice<uint8_t>(&fde_slice, aug_len);
    if (lsda_ptr_enc != DW_EH_PE_omitted) {
      uintptr_t lsda_ptr = ReadEncodedPtr(&fde_aug_data, lsda_ptr_enc);
      if (!v_->HandleLSDA(lsda_ptr)) {
        return;
      }
    }
  }

  if (!v_->AfterCIE()) {
    return;
  }

  // FDE instructions
  RunInstructions(fde_slice, false);
}

template <std::derived_from<UnwindVisitor> V>
bool Decoder<V>::RunInstructions(byte_slice slice, bool is_cie) {
  while (!slice.empty()) {
    uint8_t opcode = ReadObject<uint8_t>(&slice);
    uint8_t operand = opcode & 0x3f;

    if ((opcode & 0xc0) == DW_CFA_advance_loc) {
      if (!DoSetLoc(state_.current_loc + uintptr_t{operand} * code_align(), is_cie)) {
        return false;
      }
      continue;
    }

    if ((opcode & 0xc0) == DW_CFA_offset) {
      uintptr_t offset = ReadUleb128(&slice);
      if (!v_->HandleOffset(operand, static_cast<intptr_t>(offset) * data_align())) {
        return false;
      }
      continue;
    }

    if ((opcode & 0xc0) == DW_CFA_restore) {
      if (!v_->HandleRestore(operand)) {
        return false;
      }
      continue;
    }

    switch (opcode) {
      case DW_CFA_nop:
        break;

      case DW_CFA_set_loc: {
        uintptr_t new_loc = ReadEncodedPtr(&slice, state_.fde_ptr_enc);
        if (new_loc < state_.current_loc) {
          Fail("set_loc backward move");
        }
        if (!DoSetLoc(new_loc, is_cie)) {
          return false;
        }
        break;
      }

      case DW_CFA_advance_loc1:
        if (!DoSetLoc(state_.current_loc + uintptr_t{ReadObject<uint8_t>(&slice)} * code_align(), is_cie)) {
          return false;
        }
        break;
      case DW_CFA_advance_loc2:
        if (!DoSetLoc(state_.current_loc + uintptr_t{ReadObject<uint16_t>(&slice)} * code_align(), is_cie)) {
          return false;
        }
        break;
      case DW_CFA_advance_loc4:
        if (!DoSetLoc(state_.current_loc + uintptr_t{ReadObject<uint32_t>(&slice)} * code_align(), is_cie)) {
          return false;
        }
        break;

      case DW_CFA_offset_extended: {
        uintptr_t reg = ReadUleb128(&slice);
        uintptr_t offset = ReadUleb128(&slice);
        if (!v_->HandleOffset(reg, static_cast<intptr_t>(offset) * data_align())) {
          return false;
        }
        break;
      }

      case DW_CFA_offset_extended_sf: {
        uintptr_t reg = ReadUleb128(&slice);
        intptr_t offset = ReadSleb128(&slice);
        if (!v_->HandleOffset(reg, offset * data_align())) {
          return false;
        }
        break;
      }

      case DW_CFA_restore_extended: {
        uintptr_t reg = ReadUleb128(&slice);
        if (!v_->HandleRestore(reg)) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa: {
        uintptr_t reg = ReadUleb128(&slice);
        // Note, def_cfa's offset is not scaled by data alignment.
        uintptr_t offset = ReadUleb128(&slice);
        if (!v_->HandleDefCFA(reg, offset)) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa_sf: {
        uintptr_t reg = ReadUleb128(&slice);
        intptr_t offset = ReadSleb128(&slice);
        if (!v_->HandleDefCFA(reg, offset * data_align())) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa_register: {
        uintptr_t reg = ReadUleb128(&slice);
        if (!v_->HandleDefCFAReg(reg)) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa_offset: {
        // Not scaled, same as def_cfa above.
        uintptr_t new_offset = ReadUleb128(&slice);
        if (!v_->HandleDefCFAOffset(new_offset)) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa_offset_sf: {
        intptr_t new_offset = ReadSleb128(&slice) * data_align();
        if (!v_->HandleDefCFAOffset(new_offset)) {
          return false;
        }
        break;
      }

      case DW_CFA_def_cfa_expression: {
        uintptr_t len = ReadUleb128(&slice);
        std::span<const uint8_t> expr = ReadSubslice<uint8_t>(&slice, len);
        if (!v_->HandleDefCFAExpression(expr)) {
          return false;
        }
        break;
      }

      case DW_CFA_expression: {
        uintptr_t reg = ReadUleb128(&slice);
        uintptr_t len = ReadUleb128(&slice);
        std::span<const uint8_t> expr = ReadSubslice<uint8_t>(&slice, len);
        if (!v_->HandleExpression(reg, expr)) {
          return false;
        }
        break;
      }

      case DW_CFA_val_expression: {
        uintptr_t reg = ReadUleb128(&slice);
        uintptr_t len = ReadUleb128(&slice);
        std::span<const uint8_t> expr = ReadSubslice<uint8_t>(&slice, len);
        if (!v_->HandleValExpression(reg, expr)) {
          return false;
        }
        break;
      }

      case DW_CFA_undefined: {
        uintptr_t reg = ReadUleb128(&slice);
        if (!v_->HandleUndefined(reg)) {
          return false;
        }
        break;
      }

      case DW_CFA_same_value: {
        uintptr_t reg = ReadUleb128(&slice);
        if (!v_->HandleSameValue(reg)) {
          return false;
        }
        break;
      }

      case DW_CFA_register: {
        uintptr_t reg1 = ReadUleb128(&slice);
        uintptr_t reg2 = ReadUleb128(&slice);
        if (!v_->HandleRegister(reg1, reg2)) {
          return false;
        }
        break;
      }

      case DW_CFA_remember_state:
        if (!v_->HandleRememberState()) {
          return false;
        }
        break;

      case DW_CFA_restore_state:
        if (!v_->HandleRestoreState()) {
          return false;
        }
        break;

      case DW_CFA_val_offset: {
        uintptr_t reg = ReadUleb128(&slice);
        uintptr_t offset = ReadUleb128(&slice);
        if (!v_->HandleValOffset(reg, static_cast<intptr_t>(offset) * data_align())) {
          return false;
        }
        break;
      }

      case DW_CFA_val_offset_sf: {
        uintptr_t reg = ReadUleb128(&slice);
        intptr_t offset = ReadSleb128(&slice);
        if (!v_->HandleValOffset(reg, offset * data_align())) {
          return false;
        }
        break;
      }

      case DW_CFA_AARCH64_negate_ra_state:
        // AArch64 PAC return address signing state toggle (also DW_CFA_GNU_window_save on SPARC).
        // Return addresses have PAC tags stripped architecturally on PC read, so this is a no-op.
        break;

      case DW_CFA_GNU_args_size:
        // Size of arguments pushed on stack (for exception handling unwinding).
        (void)ReadUleb128(&slice);
        break;

      default:
        Fail("unknown opcode: 0x%x", (int)opcode);
    }
  }

  // Ran out of instructions. The row we have now is the FDE's last one
  // and it reaches to the end of the FDE, so we close it just like any
  // other row, with the stream already exhausted.
  if (!is_cie) {
    return DoSetLoc(state_.function_end, false);
  }

  return true;
}

}  // namespace eh_frame_internal

// Given eh_frame_hdr and lookup_pc locates FDE and "visits" it's instructions via given visitor
template <std::derived_from<UnwindVisitor> V>
void FindAndDecodeFDE(EHReaderInputs inputs, V* v) {
  eh_frame_internal::Decoder<V> decoder{inputs, v};
  decoder.FindAndDecode();
}

// Decodes the single FDE living at fde_addr, whatever PC range it covers.
template <std::derived_from<UnwindVisitor> V>
void DecodeFDEAt(EHReaderInputs inputs, uintptr_t fde_addr, V* v) {
  eh_frame_internal::Decoder<V> decoder{inputs, v};
  decoder.DecodeFDEAt(fde_addr);
}

// Walks .eh_frame linearly and reports the address of every FDE record
// in it, in section order. CIEs and the terminator are skipped.
//
// This is what the runtime reader has no need for: it only ever
// binary-searches .eh_frame_hdr for one PC, while a checker wants every
// entry. Throws EHFrameError on a malformed record.
void EnumerateFDEs(uintptr_t eh_frame_start, uintptr_t eh_frame_end,
                   absl::FunctionRef<void(uintptr_t fde_addr)> callback);

}  // namespace unwind_analysis

#endif  // EH_FRAME_READER_H_

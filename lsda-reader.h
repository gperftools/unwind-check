/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef LSDA_READER_H_
#define LSDA_READER_H_

#include <stdint.h>

#include <vector>

#include "elf-image.h"

namespace unwind_analysis {

// One call-site table entry: [start, end) is the PC range that can throw
// into landing_pad. Entries with no handler (the call-site table encodes
// "exception propagates further out" as landing_pad == 0 in the raw data)
// are dropped by the reader, so every entry here has a real target.
struct LSDACallSite {
  uint64_t start;
  uint64_t end;
  uint64_t landing_pad;
};

// Parses one FDE's LSDA (the 'L' augmentation, see cfi-table.h's
// CFI::lsda_addr) and returns its call-site table as vaddr ranges, sorted
// by start address.
//
// Nothing here is specific to C++: the table format is the one gcc/clang
// emit for every frontend that uses DWARF-CFI-based unwinding, and the
// type table (which exception types are caught where) is irrelevant to
// this tool's question, so it is never even read.
//
// lsda_vaddr is CFI::lsda_addr; fde_pc_begin is the same FDE's pc_begin,
// used as the landing-pad base when the LSDA has no explicit @LPStart of
// its own, which is the overwhelmingly common case. Throws EHFrameError
// (see eh-frame-reader.h) on malformed data.
std::vector<LSDACallSite> ReadLSDACallSites(const ELFImage& image, uint64_t lsda_vaddr, uint64_t fde_pc_begin);

}  // namespace unwind_analysis

#endif  // LSDA_READER_H_

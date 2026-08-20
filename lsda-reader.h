/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef LSDA_READER_H_
#define LSDA_READER_H_

#include <stdint.h>

#include <vector>

#include "elf-image.h"

namespace unwind_analysis {

// Parses one FDE's LSDA (the .gcc_except_table entry named by its 'L'
// augmentation, see cfi-table.h's CFI::lsda_addr) and returns the
// distinct landing-pad addresses it names, as vaddrs.
//
// Nothing here is specific to C++: the table format is the one gcc/clang
// emit for every frontend that uses DWARF-CFI-based unwinding, and the
// type table (which exception types are caught where) is irrelevant to
// this tool's question, so it is never even read.
//
// lsda_vaddr is CFI::lsda_addr; fde_pc_begin is the same FDE's
// pc_begin, used as the landing-pad base when the LSDA has no explicit
// @LPStart of its own, which is the overwhelmingly common case. Throws
// EHFrameError (see eh-frame-reader.h) on malformed data.
std::vector<uint64_t> ReadLSDALandingPads(const ELFImage& image, uint64_t lsda_vaddr, uint64_t fde_pc_begin);

}  // namespace unwind_analysis

#endif  // LSDA_READER_H_

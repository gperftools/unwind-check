/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#ifndef COVERAGE_CHECK_H_
#define COVERAGE_CHECK_H_

#include <stdint.h>

#include <utility>
#include <vector>

#include "elf-image.h"
#include "fde-checker.h"

namespace unwind_analysis {

// Symbols in executable memory with no FDE covering them at
// all. Nothing else surfaces this. Typical cause is hand-written
// assembly that never got a .cfi_startproc/.cfi_endproc pair.
//
// `fde_ranges` is every FDE's [pc_begin, pc_end) from this binary's
// .eh_frame, independent of what verdict that FDE later earns (a PLT stub
// or an FDE flagged MISMATCH still "covers" its bytes for this purpose).
// Need not be sorted, need not be disjoint.
//
// One result per distinct start address: aliases sharing a vaddr would
// otherwise print an identical line each, since the report resolves the
// name from Symbolizer::Name(pc_begin) rather than anything stored here.
std::vector<FDEResult> CheckUncoveredSymbols(const ELFImage& image,
                                             const std::vector<std::pair<uint64_t, uint64_t>>& fde_ranges);

}  // namespace unwind_analysis

#endif  // COVERAGE_CHECK_H_

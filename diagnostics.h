/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef DIAGNOSTICS_H_
#define DIAGNOSTICS_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "cfi-table.h"
#include "disasm.h"
#include "elf-image.h"
#include "fde-checker.h"

// Everything in here is presentation only: turning what fde-checker.cc
// already computed into something a human can read. Nothing here feeds
// back into the BLESSED/REVIEW/MISMATCH verdict -- the checker never
// calls into this file, only unwind-check.cc and report.cc do, and only
// to decide how to print something that has already been decided.
namespace unwind_analysis {

// One instruction of an FDE's PC range, decoded top-to-bottom in address
// order, paired with the CFI row covering it. This is deliberately *not*
// the control-flow walk fde-checker.cc does -- it is what objdump-style
// linear disassembly sees, which is what a human reading a listing
// expects and is enough to show "the row of CFI stuff" around any given
// address without redoing dataflow.
struct ListedInsn {
  uint64_t pc = 0;
  uint32_t size = 0;
  std::string text;
  const CFIRow* row = nullptr;  // row covering pc, or nullptr if none does
  bool row_starts_here = false;
};

// Linearly decodes cfi's whole [pc_begin, pc_end) once. A decode failure
// truncates the listing at that point rather than aborting it -- the
// caller still gets everything before the bad byte.
std::vector<ListedInsn> ListInstructions(const ELFImage& image, Disassembler* disasm, const CFI& cfi);

// Binary-searches `listing` (sorted by pc, as ListInstructions produces
// it) for the entry covering `pc`. Returns -1 if none does.
int FindListedInsn(const std::vector<ListedInsn>& listing, uint64_t pc);

struct DiagnosticsOptions {
  int context_before = 6;
  int context_after = 4;
};

// Appends a context window -- a few real instructions around f.pc, each
// with its declared CFI row -- to *out, replacing the old single "at:
// <insn>" line. Returns false (and appends nothing) when `listing`
// doesn't cover f.pc, so callers can fall back to the old one-liner.
bool AppendFindingContext(const std::vector<ListedInsn>& listing, const Finding& f, const DiagnosticsOptions& opts,
                          std::string* out);

// --- --inspect: pipes an objdump + Ruby helper pipeline -----------------
//
// Rather than drawing our own ASCII-art jump arrows (which stops scaling
// past a handful of concurrent branches), --inspect hands the actual
// disassembly and jump visualization to `objdump --visualize-jumps`,
// which already does this well, and interleaves our own findings/CFI/
// state annotations into its output by address. See inspect.rb for the
// interleaving itself; this function's job is only to gather what needs
// interleaving and hand it over.

// Runs the checker on `cfi` (capturing the per-instruction converged
// state too when `deep` is set), serializes the result plus the declared
// CFI rows as JSON, and pipes that into `ruby_script_path` (inspect.rb),
// which itself pipes from objdump and prints the combined, colored
// listing straight to this process's stdout. `binary_path` is the ELF
// being inspected -- inspect.rb runs its own objdump over it, entirely
// independent of how this process opened it.
//
// The returned FDEResult is always populated (the check itself cannot
// fail short of a decode-level EHFrameError, which is the caller's
// problem, not this function's); the Status reports only pipeline-level
// failure -- spawning ruby, or ruby/objdump exiting non-zero -- which the
// caller should treat as fatal to the whole --inspect invocation.
absl::StatusOr<FDEResult> RunInspectPipeline(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry,
                                             bool deep, bool color, const std::string& binary_path,
                                             const std::string& ruby_script_path);

}  // namespace unwind_analysis

#endif  // DIAGNOSTICS_H_

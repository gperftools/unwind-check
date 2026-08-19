/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "cfi-table.h"
#include "disasm.h"
#include "eh-frame-reader.h"
#include "elf-image.h"
#include "fde-checker.h"
#include "report.h"
#include "symbolizer.h"

ABSL_FLAG(bool, verbose, false, "List blessed FDEs too, not just the ones needing attention.");
ABSL_FLAG(bool, summary_only, false, "Print only the trailing histogram.");
ABSL_FLAG(std::string, function, "",
          "Only check FDEs whose symbol name matches this ECMAScript regex. Matched against the name in the "
          "ELF symbol table, before addr2line gets a say.");
ABSL_FLAG(std::string, pc, "", "Only check the FDE covering this address (hex, 0x-prefixed or not).");
ABSL_FLAG(int, max_findings, 8, "Maximum distinct findings reported per FDE.");
ABSL_FLAG(bool, check_unmentioned_callee_saved, false,
          "Also require callee-saved registers with no CFI rule to still hold their entry value. "
          "Noisy on hand-written assembly.");
ABSL_FLAG(bool, report_coverage_gaps, true,
          "Report bytes inside an FDE that the control-flow walk never reached, and so never checked.");
ABSL_FLAG(bool, dump_cfi, false,
          "Print the decoded CFI row table for each selected FDE instead of checking anything. "
          "Compare against `readelf --debug-dump=frames-interp`.");
ABSL_FLAG(std::string, addr2line, "auto",
          "'auto' to use addr2line for source lines when the binary has debug info, 'off' to skip it, "
          "or a path to the tool.");

namespace unwind_analysis {
namespace {

constexpr int kExitBlessed = 0;
constexpr int kExitMismatch = 1;
constexpr int kExitReview = 2;
constexpr int kExitFailure = 3;

// One FDE as read from .eh_frame, before any code analysis.
struct RawFde {
  uint64_t vaddr = 0;
  std::optional<FdeCfi> cfi;
  std::string error;
};

FdeResult MakeStructuralResult(uint64_t fde_vaddr, uint64_t pc_begin, uint64_t pc_end, Finding::Severity severity,
                               std::string message) {
  FdeResult r;
  r.fde_addr = fde_vaddr;
  r.pc_begin = pc_begin;
  r.pc_end = pc_end;
  r.verdict = severity == Finding::Severity::kMismatch ? Verdict::kMismatch : Verdict::kReview;
  r.findings.push_back(Finding{severity, pc_begin, std::move(message), "", 0});
  return r;
}

// Whether a symbol name denotes something entered by `call`. See the
// comment at its only caller.
bool IsEntryPointName(std::string_view name) {
  return !absl::EndsWith(name, ".cold") && !absl::StrContains(name, ".cold.");
}

std::optional<uint64_t> ParseHex(const std::string& text) {
  if (text.empty()) {
    return std::nullopt;
  }
  const char* start = text.c_str();
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    start += 2;
  }
  char* end = nullptr;
  uint64_t value = strtoull(start, &end, 16);
  if (end == start || *end != '\0') {
    return std::nullopt;
  }
  return value;
}

Symbolizer::Addr2LineMode ParseAddr2LineMode(const std::string& value, std::string* tool_path) {
  if (value == "off") {
    return Symbolizer::Addr2LineMode::kOff;
  }
  if (value == "auto" || value.empty()) {
    return Symbolizer::Addr2LineMode::kAuto;
  }
  *tool_path = value;
  return Symbolizer::Addr2LineMode::kExplicit;
}

// Reads every FDE in .eh_frame. A record we cannot decode costs one
// report line, not the run.
std::vector<RawFde> ReadAllFdes(const ElfImage& image, std::string* fatal_error) {
  std::vector<RawFde> fdes;
  std::vector<uint64_t> addrs;
  try {
    EnumerateFDEs(static_cast<uintptr_t>(image.eh_frame_start()) + image.bias(),
                  static_cast<uintptr_t>(image.eh_frame_end()) + image.bias(),
                  [&](uintptr_t fde_addr) { addrs.push_back(image.ToVaddr(fde_addr)); });
  } catch (const EhFrameError& e) {
    // Whatever we got before the bad record is still worth checking.
    *fatal_error = e.what();
  }
  fdes.reserve(addrs.size());
  for (uint64_t addr : addrs) {
    RawFde raw;
    raw.vaddr = addr;
    try {
      raw.cfi = ReadFde(addr, image.eh_frame_start(), image.eh_frame_end(), image.bias());
    } catch (const EhFrameError& e) {
      raw.error = e.what();
    }
    fdes.push_back(std::move(raw));
  }
  return fdes;
}

// Checks that do not need any disassembly: FDE ranges must be inside
// executable memory, must be non-empty, and must not overlap each other.
// Nothing else available reports any of this.
void RunStructuralChecks(const ElfImage& image, const std::vector<RawFde>& fdes, std::vector<FdeResult>* results,
                         std::vector<const FdeCfi*>* checkable) {
  std::vector<const RawFde*> sorted;
  for (const RawFde& raw : fdes) {
    if (!raw.error.empty()) {
      results->push_back(MakeStructuralResult(raw.vaddr, 0, 0, Finding::Severity::kReview,
                                              absl::StrFormat("cannot decode this FDE: %s", raw.error)));
      continue;
    }
    const FdeCfi& cfi = *raw.cfi;
    if (cfi.pc_end <= cfi.pc_begin) {
      results->push_back(MakeStructuralResult(raw.vaddr, cfi.pc_begin, cfi.pc_end, Finding::Severity::kMismatch,
                                              "FDE covers an empty or backwards PC range"));
      continue;
    }
    if (!image.IsExecutable(cfi.pc_begin, cfi.pc_end - cfi.pc_begin)) {
      results->push_back(
          MakeStructuralResult(raw.vaddr, cfi.pc_begin, cfi.pc_end, Finding::Severity::kMismatch,
                               absl::StrFormat("FDE covers [0x%x, 0x%x), which is not inside one executable PT_LOAD",
                                               cfi.pc_begin, cfi.pc_end)));
      continue;
    }
    sorted.push_back(&raw);
    checkable->push_back(&cfi);
  }

  std::sort(sorted.begin(), sorted.end(),
            [](const RawFde* a, const RawFde* b) { return a->cfi->pc_begin < b->cfi->pc_begin; });
  for (size_t i = 1; i < sorted.size(); i++) {
    const FdeCfi& prev = *sorted[i - 1]->cfi;
    const FdeCfi& cur = *sorted[i]->cfi;
    if (cur.pc_begin < prev.pc_end) {
      results->push_back(
          MakeStructuralResult(sorted[i]->vaddr, cur.pc_begin, cur.pc_end, Finding::Severity::kMismatch,
                               absl::StrFormat("FDE range [0x%x, 0x%x) overlaps the preceding FDE's [0x%x, 0x%x)",
                                               cur.pc_begin, cur.pc_end, prev.pc_begin, prev.pc_end)));
    }
  }
}

// Prints one FDE's decoded row table, for eyeballing against
// `readelf --debug-dump=frames-interp`.
void DumpCfi(const FdeCfi& cfi, const Symbolizer& symbolizer) {
  std::string name = symbolizer.Name(cfi.pc_begin);
  absl::PrintF("FDE 0x%x pc=0x%x..0x%x%s%s\n", cfi.fde_addr, cfi.pc_begin, cfi.pc_end, name.empty() ? "" : "  ", name);
  for (const CfiRow& row : cfi.rows) {
    absl::PrintF("  0x%-14x cfa=%s", row.pc_start, row.cfa.ToString());
    for (int r = 0; r < kNumDwarfRegs; r++) {
      if (row.regs[r].kind == RegRule::Kind::kUnset) {
        continue;
      }
      absl::PrintF("  %s=%s", DwarfRegName(r), row.regs[r].ToString());
    }
    absl::PrintF("\n");
  }
}

int Run(const std::string& path) {
  absl::StatusOr<std::unique_ptr<ElfImage>> image = ElfImage::Open(path);
  if (!image.ok()) {
    absl::FPrintF(stderr, "unwind-check: %s\n", image.status().message());
    return kExitFailure;
  }
  if (!(*image)->has_eh_frame()) {
    absl::FPrintF(stderr, "unwind-check: %s has no .eh_frame section; there is nothing to check\n", path);
    return kExitFailure;
  }

  absl::StatusOr<std::unique_ptr<Disassembler>> disasm = Disassembler::Create();
  if (!disasm.ok()) {
    absl::FPrintF(stderr, "unwind-check: %s\n", disasm.status().message());
    return kExitFailure;
  }

  std::string enumerate_error;
  std::vector<RawFde> fdes = ReadAllFdes(**image, &enumerate_error);
  if (fdes.empty() && !enumerate_error.empty()) {
    absl::FPrintF(stderr, "unwind-check: cannot read .eh_frame of %s: %s\n", path, enumerate_error);
    return kExitFailure;
  }

  std::vector<FdeResult> results;
  std::vector<const FdeCfi*> checkable;
  RunStructuralChecks(**image, fdes, &results, &checkable);

  std::string tool_path;
  Symbolizer symbolizer{**image, ParseAddr2LineMode(absl::GetFlag(FLAGS_addr2line), &tool_path), tool_path};

  std::optional<std::regex> name_filter;
  const std::string function_flag = absl::GetFlag(FLAGS_function);
  if (!function_flag.empty()) {
    try {
      name_filter.emplace(function_flag, std::regex::ECMAScript);
    } catch (const std::regex_error& e) {
      absl::FPrintF(stderr, "unwind-check: bad --function regex: %s\n", e.what());
      return kExitFailure;
    }
  }
  std::optional<uint64_t> pc_filter;
  const std::string pc_flag = absl::GetFlag(FLAGS_pc);
  if (!pc_flag.empty()) {
    pc_filter = ParseHex(pc_flag);
    if (!pc_filter.has_value()) {
      absl::FPrintF(stderr, "unwind-check: cannot parse --pc value '%s' as hex\n", pc_flag);
      return kExitFailure;
    }
  }

  FdeChecker::Options options;
  options.check_unmentioned_callee_saved = absl::GetFlag(FLAGS_check_unmentioned_callee_saved);
  options.report_coverage_gaps = absl::GetFlag(FLAGS_report_coverage_gaps);
  options.max_findings_per_fde = static_cast<size_t>(std::max(1, absl::GetFlag(FLAGS_max_findings)));
  FdeChecker checker{**image, **disasm, options};

  // Where a function symbol starts, the FDE's first row is checkable
  // against the canonical entry state. Elsewhere -- PLT stubs, the cold
  // halves of split functions -- it is all we have to go on.
  //
  // The exception is why IsEntryPointName exists: a `foo.cold` fragment
  // carries a real STT_FUNC symbol but is reached by a jump from foo,
  // never by a call, so its first row legitimately describes a frame
  // that is already set up. Nothing structural distinguishes it -- the
  // linker merges .text.unlikely into .text -- so we go by the name GCC
  // and clang both give these, which is a convention and not a
  // guarantee. Getting this wrong is expensive: a statically linked
  // binary has dozens of them, and every one would be accused of an
  // impossible entry row.
  absl::flat_hash_set<uint64_t> function_starts;
  for (const FuncSymbol& sym : (*image)->func_symbols()) {
    if (IsEntryPointName(sym.name)) {
      function_starts.insert(sym.vaddr);
    }
  }

  const bool dump_cfi = absl::GetFlag(FLAGS_dump_cfi);

  for (const FdeCfi* cfi : checkable) {
    if (pc_filter.has_value() && !(cfi->pc_begin <= *pc_filter && *pc_filter < cfi->pc_end)) {
      continue;
    }
    if (name_filter.has_value()) {
      std::string name = symbolizer.Name(cfi->pc_begin);
      if (!std::regex_search(name, *name_filter)) {
        continue;
      }
    }
    if (dump_cfi) {
      DumpCfi(*cfi, symbolizer);
      continue;
    }
    try {
      results.push_back(checker.Check(*cfi, function_starts.contains(cfi->pc_begin)));
    } catch (const EhFrameError& e) {
      results.push_back(MakeStructuralResult(cfi->fde_addr, cfi->pc_begin, cfi->pc_end, Finding::Severity::kReview,
                                             absl::StrFormat("analysis aborted: %s", e.what())));
    }
  }

  if (dump_cfi) {
    return kExitBlessed;
  }

  ReportOptions report_options;
  report_options.verbose = absl::GetFlag(FLAGS_verbose);
  report_options.summary_only = absl::GetFlag(FLAGS_summary_only);
  PrintReport(results, &symbolizer, report_options);

  if (!enumerate_error.empty()) {
    absl::FPrintF(stderr, "unwind-check: .eh_frame walk stopped early: %s\n", enumerate_error);
  }

  Summary summary = Summarize(results);
  if (summary.mismatch > 0) {
    return kExitMismatch;
  }
  if (summary.review > 0) {
    return kExitReview;
  }
  return kExitBlessed;
}

}  // namespace
}  // namespace unwind_analysis

int main(int argc, char** argv) {
  absl::SetProgramUsageMessage(
      "Checks that an x86-64 ELF binary's .eh_frame CFI matches what its code actually does to the stack.\n"
      "Usage: unwind-check [flags] <binary>\n"
      "Exit codes: 0 all blessed, 1 a mismatch was found, 2 something needs review, 3 the run failed.");
  std::vector<char*> positional = absl::ParseCommandLine(argc, argv);
  if (positional.size() != 2) {
    absl::FPrintF(stderr, "unwind-check: expected exactly one binary to check\n");
    return 3;
  }
  return unwind_analysis::Run(positional[1]);
}

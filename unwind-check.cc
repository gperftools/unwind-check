/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "cfi-table.h"
#include "coverage-check.h"
#include "diagnostics.h"
#include "disasm.h"
#include "eh-frame-reader.h"
#include "elf-image.h"
#include "fde-checker.h"
#include "light-checker.h"
#include "report.h"
#include "rules_cc/cc/runfiles/runfiles.h"
#include "symbolizer.h"

ABSL_FLAG(bool, show_blessed, false, "List blessed FDEs too, not just the ones needing attention.");
ABSL_FLAG(bool, summary_only, false, "Print only the trailing histogram.");
ABSL_FLAG(std::string, function, "",
          "Only check FDEs whose symbol name matches this ECMAScript regex. Matched against the name in the "
          "ELF symbol table, before addr2line gets a say.");
ABSL_FLAG(std::string, pc, "", "Only check the FDE covering this address (hex, 0x-prefixed or not).");
ABSL_FLAG(int, max_findings, 8, "Maximum distinct findings reported per FDE.");
ABSL_FLAG(bool, check_unmentioned_callee_saved, false,
          "Also require callee-saved registers with no CFI rule to still hold their entry value. "
          "Noisy on hand-written assembly.");
ABSL_FLAG(bool, full, false,
          "Use the full dataflow-based checker (worklist over the whole reachable CFG, switch-table "
          "resolution, exception landing pads, guessing recovery) instead of the light one. The light "
          "checker (default) only checks CFA-rule consistency at stack-affecting instructions and direct "
          "jump/call targets, plus a narrow positional check on a push/spill's saved-register offset; it "
          "never resolves a switch table's dispatch and never produces REVIEW-LIGHT. See light-checker.h.");
ABSL_FLAG(bool, report_coverage_gaps, true,
          "Report bytes inside an FDE that the control-flow walk never reached, and so never checked.");
ABSL_FLAG(bool, report_uncovered_symbols, true,
          "Report, as REVIEW, symbols in executable memory that no FDE covers at all -- e.g. hand-written "
          "assembly that never got a .cfi_startproc.");
ABSL_FLAG(bool, dump_cfi, false,
          "Print the decoded CFI row table for each selected FDE instead of checking anything. "
          "Compare against `readelf --debug-dump=frames-interp`.");
ABSL_FLAG(bool, inspect, false,
          "Requires --pc. Instead of checking, print objdump's disasm+jump-arrow listing of the FDE covering "
          "--pc, with our own findings and declared CFI rows interleaved by address. Needs `ruby` and `objdump` "
          "on PATH.");
ABSL_FLAG(bool, inspect_deep, false,
          "With --inspect, also show the dataflow's converged abstract state before each instruction.");
ABSL_FLAG(bool, color, false, "With --inspect, always colorize the listing, whether or not stdout is a tty.");
ABSL_FLAG(bool, only_mismatch, false, "Only list FDEs with a MISMATCH verdict (the summary line is unaffected).");
ABSL_FLAG(bool, only_review, false,
          "Only list FDEs with a REVIEW or REVIEW-LIGHT verdict (the summary line is unaffected).");
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
struct RawFDE {
  uint64_t vaddr = 0;
  std::optional<CFI> cfi;
  std::string error;
};

FDEResult MakeStructuralResult(uint64_t fde_vaddr, uint64_t pc_begin, uint64_t pc_end, Finding::Severity severity,
                               std::string message) {
  FDEResult r;
  r.fde_addr = fde_vaddr;
  r.pc_begin = pc_begin;
  r.pc_end = pc_end;
  r.verdict = severity == Finding::Severity::kMismatch ? Verdict::kMismatch : Verdict::kReview;
  r.findings.push_back(Finding{severity, pc_begin, std::move(message), 0});
  return r;
}

// Whether a symbol name denotes something entered by `call`. See the
// comment at its only caller.
bool IsEntryPointName(std::string_view name) {
  return !absl::EndsWith(name, ".cold") && !absl::StrContains(name, ".cold.");
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
std::vector<RawFDE> ReadAllFDEs(const ELFImage& image, std::string* fatal_error) {
  std::vector<RawFDE> fdes;
  std::vector<uint64_t> addrs;
  try {
    EnumerateFDEs(static_cast<uintptr_t>(image.eh_frame_start()) + image.bias(),
                  static_cast<uintptr_t>(image.eh_frame_end()) + image.bias(),
                  [&](uintptr_t fde_addr) { addrs.push_back(image.ToVaddr(fde_addr)); });
  } catch (const EHFrameError& e) {
    // Whatever we got before the bad record is still worth checking.
    *fatal_error = e.what();
  }
  fdes.reserve(addrs.size());
  for (uint64_t addr : addrs) {
    RawFDE raw;
    raw.vaddr = addr;
    try {
      raw.cfi = ReadFDE(addr, image.eh_frame_start(), image.eh_frame_end(), image.bias());
    } catch (const EHFrameError& e) {
      raw.error = e.what();
    }
    fdes.push_back(std::move(raw));
  }
  return fdes;
}

// Checks that do not need any disassembly: FDE ranges must be inside
// executable memory, must be non-empty, and must not overlap each other.
// Nothing else available reports any of this.
void RunStructuralChecks(const ELFImage& image, const std::vector<RawFDE>& fdes, std::vector<FDEResult>* results,
                         std::vector<const CFI*>* checkable) {
  std::vector<const RawFDE*> sorted;
  for (const RawFDE& raw : fdes) {
    if (!raw.error.empty()) {
      results->push_back(MakeStructuralResult(raw.vaddr, 0, 0, Finding::Severity::kReview,
                                              absl::StrFormat("cannot decode this FDE: %s", raw.error)));
      continue;
    }
    const CFI& cfi = *raw.cfi;
    if (cfi.pc_end == cfi.pc_begin) {
      // Recent clang emits a handful of these per binary: a zero-length
      // FDE (pc_begin == pc_end, no rows) immediately preceding the real
      // FDE for the same code, apparently a side effect of ICF folding
      // multiple original symbols onto one function body. There is
      // nothing to check -- no PC range, no rows -- so we just note it
      // happened and flag it, rather than running it through (or letting
      // it pollute) the rest of the pipeline.
      results->push_back(MakeStructuralResult(raw.vaddr, cfi.pc_begin, cfi.pc_end, Finding::Severity::kMismatch,
                                              "FDE covers an empty PC range (pc_begin == pc_end); noted and skipped"));
      continue;
    }
    if (cfi.pc_end < cfi.pc_begin) {
      results->push_back(MakeStructuralResult(raw.vaddr, cfi.pc_begin, cfi.pc_end, Finding::Severity::kMismatch,
                                              "FDE covers a backwards PC range"));
      continue;
    }
    if (!image.IsExecutable(cfi.pc_begin, cfi.pc_end - cfi.pc_begin)) {
      results->push_back(
          MakeStructuralResult(raw.vaddr, cfi.pc_begin, cfi.pc_end, Finding::Severity::kMismatch,
                               absl::StrFormat("FDE covers [0x%x, 0x%x), which is not inside one executable PT_LOAD",
                                               cfi.pc_begin, cfi.pc_end)));
      continue;
    }
    // PLT stubs are linker-generated, not compiler output with CFI to
    // second-guess; assume correct and skip analysis entirely.
    if (image.InPLT(cfi.pc_begin, cfi.pc_end - cfi.pc_begin)) {
      FDEResult r;
      r.fde_addr = raw.vaddr;
      r.pc_begin = cfi.pc_begin;
      r.pc_end = cfi.pc_end;
      results->push_back(std::move(r));
      continue;
    }
    sorted.push_back(&raw);
    checkable->push_back(&cfi);
  }

  absl::c_sort(sorted, [](const RawFDE* a, const RawFDE* b) { return a->cfi->pc_begin < b->cfi->pc_begin; });
  for (size_t i = 1; i < sorted.size(); i++) {
    const CFI& prev = *sorted[i - 1]->cfi;
    const CFI& cur = *sorted[i]->cfi;
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
void DumpCFI(const CFI& cfi, const Symbolizer& symbolizer) {
  std::string name = symbolizer.Name(cfi.pc_begin);
  absl::PrintF("FDE 0x%x pc=0x%x..0x%x%s%s\n", cfi.fde_addr, cfi.pc_begin, cfi.pc_end, name.empty() ? "" : "  ", name);
  for (const CFIRow& row : cfi.rows) {
    absl::PrintF("  0x%-14x cfa=%v", row.pc_start, row.cfa);
    for (int r = 0; r < kNumDWARFRegs; r++) {
      if (row.regs[r].kind == RegRule::Kind::kUnset) {
        continue;
      }
      absl::PrintF("  %s=%v", DWARFRegName(r), row.regs[r]);
    }
    absl::PrintF("\n");
  }
}

// `ruby_script_path` is only consulted when --inspect is set; the caller
// resolves it (or leaves it empty, if --inspect wasn't requested) via
// the Bazel runfiles library, which needs argv[0] and so has to happen
// in main() rather than here.
int Run(const std::string& path, const std::string& ruby_script_path) {
  absl::StatusOr<std::unique_ptr<ELFImage>> maybe_image = ELFImage::Open(path);
  if (!maybe_image.ok()) {
    absl::FPrintF(stderr, "unwind-check: %s\n", maybe_image.status().message());
    return kExitFailure;
  }

  const ELFImage& image = **maybe_image;
  if (!image.has_eh_frame()) {
    absl::FPrintF(stderr, "unwind-check: %s has no .eh_frame section; there is nothing to check\n", path);
    return kExitFailure;
  }

  absl::StatusOr<std::unique_ptr<Disassembler>> maybe_disasm = Disassembler::Create();
  if (!maybe_disasm.ok()) {
    absl::FPrintF(stderr, "unwind-check: %s\n", maybe_disasm.status().message());
    return kExitFailure;
  }

  Disassembler* disasm = maybe_disasm.value().get();

  std::string enumerate_error;
  std::vector<RawFDE> fdes = ReadAllFDEs(image, &enumerate_error);
  if (fdes.empty() && !enumerate_error.empty()) {
    absl::FPrintF(stderr, "unwind-check: cannot read .eh_frame of %s: %s\n", path, enumerate_error);
    return kExitFailure;
  }

  std::vector<FDEResult> results;
  std::vector<const CFI*> checkable;
  RunStructuralChecks(image, fdes, &results, &checkable);
  if (absl::GetFlag(FLAGS_report_uncovered_symbols)) {
    std::vector<std::pair<uint64_t, uint64_t>> fde_ranges;
    for (const RawFDE& raw : fdes) {
      if (raw.cfi.has_value() && raw.cfi->pc_end > raw.cfi->pc_begin) {
        fde_ranges.emplace_back(raw.cfi->pc_begin, raw.cfi->pc_end);
      }
    }
    std::vector<FDEResult> uncovered = CheckUncoveredSymbols(image, fde_ranges);
    results.insert(results.end(), std::make_move_iterator(uncovered.begin()), std::make_move_iterator(uncovered.end()));
  }

  std::string tool_path;
  Symbolizer symbolizer{image, ParseAddr2LineMode(absl::GetFlag(FLAGS_addr2line), &tool_path), tool_path};

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
    uint64_t value;
    if (!absl::SimpleHexAtoi(pc_flag, &value)) {
      absl::FPrintF(stderr, "unwind-check: cannot parse --pc value '%s' as hex\n", pc_flag);
      return kExitFailure;
    }
    pc_filter = value;
  }

  // Every structurally valid FDE, sorted by pc_begin, so the checker can
  // tell whether a resolved switch-table entry lands inside *some* FDE (not
  // necessarily the one being checked), and can look up the declared CFI
  // row at a jump target outside the FDE it is currently checking -- see
  // fde-checker.h.
  std::vector<std::pair<std::pair<uint64_t, uint64_t>, const CFI*>> cfi_index;
  cfi_index.reserve(checkable.size());
  for (const CFI* cfi : checkable) {
    cfi_index.emplace_back(std::make_pair(cfi->pc_begin, cfi->pc_end), cfi);
  }
  absl::c_sort(cfi_index);

  FDECheckerOptions options;
  options.image = &image;
  options.disasm = disasm;
  options.check_unmentioned_callee_saved = absl::GetFlag(FLAGS_check_unmentioned_callee_saved);
  options.report_coverage_gaps = absl::GetFlag(FLAGS_report_coverage_gaps);
  options.max_findings_per_fde = static_cast<size_t>(std::max(1, absl::GetFlag(FLAGS_max_findings)));
  options.all_cfis = cfi_index;

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
  //
  // This same set decides what AbsState::SeedFromRow assumes about a
  // register the first row says nothing about: still its entry value at
  // a real entry point (nothing has run yet to make that untrue), just
  // unknown everywhere else (a `.cold` fragment's silence means nothing
  // needed unwinding that register, not that it is unchanged).
  absl::flat_hash_set<uint64_t> function_starts;
  for (const FuncSymbol& sym : image.func_symbols()) {
    if (IsEntryPointName(sym.name)) {
      function_starts.insert(sym.vaddr);
    }
  }

  const bool dump_cfi = absl::GetFlag(FLAGS_dump_cfi);
  const bool inspect = absl::GetFlag(FLAGS_inspect);
  const bool inspect_deep = absl::GetFlag(FLAGS_inspect_deep);

  if (inspect) {
    if (!pc_filter.has_value()) {
      absl::FPrintF(stderr, "unwind-check: --inspect requires --pc\n");
      return kExitFailure;
    }
    const CFI* target = nullptr;
    for (const CFI* cfi : checkable) {
      if (cfi->pc_begin <= *pc_filter && *pc_filter < cfi->pc_end) {
        target = cfi;
        break;
      }
    }
    if (target == nullptr) {
      absl::FPrintF(stderr, "unwind-check: no checkable FDE covers 0x%x\n", *pc_filter);
      return kExitFailure;
    }

    std::string name = symbolizer.Name(target->pc_begin);
    absl::PrintF("FDE 0x%x  [0x%x, 0x%x)%s%s%s\n", target->fde_addr, target->pc_begin, target->pc_end,
                 name.empty() ? "" : "  ", name, target->signal_frame ? "  (signal frame)" : "");
    // --inspect always runs the full checker (it needs CheckWithGuessing's
    // trace_out for --inspect_deep, which LightCheck does not produce) --
    // worth saying explicitly, since the light checker is the default for
    // the plain checking path and a --pc run without --inspect can
    // otherwise silently report from a different checker than --inspect
    // does for the same FDE.
    if (!absl::GetFlag(FLAGS_full)) {
      absl::FPrintF(stderr, "unwind-check: --inspect always uses the full checker, regardless of --full\n");
    }
    fflush(stdout);

    const bool color = absl::GetFlag(FLAGS_color) || isatty(STDOUT_FILENO) != 0;
    absl::StatusOr<FDEResult> inspected = RunInspectPipeline(
        options, *target, function_starts.contains(target->pc_begin), inspect_deep, color, path, ruby_script_path);
    if (!inspected.ok()) {
      absl::FPrintF(stderr, "unwind-check: %s\n", inspected.status().message());
      return kExitFailure;
    }
    // Findings not tied to a specific address (a truncation notice, "gave
    // up after N dataflow steps") never went into the pipeline's
    // annotations -- print them here, after the listing.
    for (const Finding& f : inspected->findings) {
      if (f.pc == 0) {
        absl::PrintF("  %s\n", f.message);
      }
    }
    Summary s = Summarize({*inspected});
    if (s.mismatch > 0) {
      return kExitMismatch;
    }
    if (s.review > 0 || s.review_light > 0) {
      return kExitReview;
    }
    return kExitBlessed;
  }

  for (const CFI* cfi : checkable) {
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
      DumpCFI(*cfi, symbolizer);
      continue;
    }
    try {
      results.push_back(absl::GetFlag(FLAGS_full)
                            ? CheckWithGuessing(options, *cfi, function_starts.contains(cfi->pc_begin))
                            : LightCheck(options, *cfi, function_starts.contains(cfi->pc_begin)));
    } catch (const EHFrameError& e) {
      results.push_back(MakeStructuralResult(cfi->fde_addr, cfi->pc_begin, cfi->pc_end, Finding::Severity::kReview,
                                             absl::StrFormat("analysis aborted: %s", e.what())));
    }
  }

  if (dump_cfi) {
    return kExitBlessed;
  }

  // Keyed by FDEResult::pc_begin, which equals the originating CFI's
  // pc_begin -- lets the report show a window of real instructions
  // around each finding instead of just the one it's anchored to.
  absl::flat_hash_map<uint64_t, const CFI*> cfi_by_pc_begin;
  cfi_by_pc_begin.reserve(checkable.size());
  for (const CFI* cfi : checkable) {
    cfi_by_pc_begin.emplace(cfi->pc_begin, cfi);
  }

  ReportOptions report_options;
  report_options.show_blessed = absl::GetFlag(FLAGS_show_blessed);
  report_options.summary_only = absl::GetFlag(FLAGS_summary_only);
  report_options.only_mismatch = absl::GetFlag(FLAGS_only_mismatch);
  report_options.only_review = absl::GetFlag(FLAGS_only_review);
  ReportContext report_context;
  report_context.image = &image;
  report_context.disasm = disasm;
  report_context.cfi_by_pc_begin = &cfi_by_pc_begin;
  PrintReport(results, &symbolizer, report_options, &report_context);

  if (!enumerate_error.empty()) {
    absl::FPrintF(stderr, "unwind-check: .eh_frame walk stopped early: %s\n", enumerate_error);
  }

  Summary summary = Summarize(results);
  if (summary.mismatch > 0) {
    return kExitMismatch;
  }
  if (summary.review > 0 || summary.review_light > 0) {
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
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  std::vector<char*> positional = absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  if (positional.size() != 2) {
    absl::FPrintF(stderr, "unwind-check: expected exactly one binary to check\n");
    return 3;
  }

  std::string ruby_script_path;
  if (absl::GetFlag(FLAGS_inspect)) {
    std::string error;
    std::unique_ptr<rules_cc::cc::runfiles::Runfiles> runfiles(
        rules_cc::cc::runfiles::Runfiles::Create(argv[0], &error));
    if (runfiles == nullptr) {
      absl::FPrintF(stderr, "unwind-check: could not locate runfiles: %s\n", error);
      return 3;
    }
    ruby_script_path = runfiles->Rlocation("_main/inspect.rb");
    if (ruby_script_path.empty() || access(ruby_script_path.c_str(), R_OK) != 0) {
      absl::FPrintF(stderr, "unwind-check: could not locate inspect.rb in runfiles\n");
      return 3;
    }
  }
  return unwind_analysis::Run(positional[1], ruby_script_path);
}

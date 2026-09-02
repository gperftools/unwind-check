/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#include "diagnostics.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "nlohmann/json.hpp"
#include "subprocess.h"

namespace unwind_analysis {

namespace {

std::string FormatRowCompact(const CFIRow* row) {
  if (row == nullptr) {
    return "<no CFI row>";
  }
  return absl::StrCat(*row);
}

// Compact rendering of one converged AbsState, for --inspect_deep: only
// what differs from "still holds its entry value", since that is the
// overwhelming common case and a full 16-register dump on every line
// would drown the listing it's supposed to clarify.
std::string FormatStateCompact(const AbsState& state) {
  std::vector<std::string> parts;
  for (int r = 0; r < kNumGPRs; r++) {
    const AbsVal& v = state.reg(r);
    if (v.IsOrigReg(r)) {
      continue;
    }
    parts.push_back(absl::StrFormat("%s=%v", DWARFRegName(r), v));
  }
  for (const auto& [offset, v] : state.slots) {
    parts.push_back(absl::StrFormat("[CFA%+d]=%v", offset, v));
  }
  if (parts.empty()) {
    return "(matches entry state)";
  }
  return absl::StrJoin(parts, " ");
}

absl::Status WriteAll(int fd, const std::string& data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return absl::InternalError(absl::StrCat("write: ", strerror(errno)));
    }
    off += static_cast<size_t>(n);
  }
  return absl::OkStatus();
}

}  // namespace

std::vector<ListedInsn> ListInstructions(const ELFImage& image, Disassembler* disasm, const CFI& cfi) {
  std::vector<ListedInsn> out;
  uint64_t pc = cfi.pc_begin;
  while (pc < cfi.pc_end) {
    std::span<const uint8_t> bytes = image.BytesAt(pc, std::min<uint64_t>(16, cfi.pc_end - pc));
    Instruction insn;
    if (bytes.empty() || !disasm->Decode(bytes.data(), bytes.size(), pc, &insn) || pc + insn.size > cfi.pc_end) {
      break;
    }
    ListedInsn li;
    li.pc = pc;
    li.size = insn.size;
    li.text = Disassembler::Text(insn).value_or(absl::StrFormat("<cannot format instruction at 0x%x>", pc));
    li.row = cfi.RowAt(pc);
    li.row_starts_here = li.row != nullptr && li.row->pc_start == pc;
    out.push_back(std::move(li));
    pc += insn.size;
  }
  return out;
}

int FindListedInsn(const std::vector<ListedInsn>& listing, uint64_t pc) {
  auto it = absl::c_lower_bound(listing, pc, [](const ListedInsn& li, uint64_t p) { return li.pc < p; });
  if (it == listing.end() || it->pc != pc) {
    return -1;
  }
  return static_cast<int>(it - listing.begin());
}

bool AppendFindingContext(const std::vector<ListedInsn>& listing, const Finding& f, const DiagnosticsOptions& opts,
                          std::string* out) {
  int idx = FindListedInsn(listing, f.pc);
  if (idx < 0) {
    return false;
  }
  int lo = std::max(0, idx - opts.context_before);
  int hi = std::min<int>(static_cast<int>(listing.size()) - 1, idx + opts.context_after);
  for (int i = lo; i <= hi; i++) {
    const ListedInsn& li = listing[i];
    absl::StrAppendFormat(out, "      %s 0x%-10x  %-28s  %s\n", i == idx ? "->" : "  ", li.pc, li.text,
                          FormatRowCompact(li.row));
  }
  return true;
}

absl::StatusOr<FDEResult> RunInspectPipeline(const FDECheckerOptions& options, const CFI& cfi, bool at_function_entry,
                                             bool deep, bool color, const std::string& binary_path,
                                             const std::string& ruby_script_path) {
  std::vector<InsnTrace> trace;
  FDEResult result = CheckWithGuessing(options, cfi, at_function_entry, deep ? &trace : nullptr);

  // Everything inspect.rb needs to know, keyed by address: the declared
  // CFI row at every row boundary, the converged state before every
  // reached instruction (deep mode only), and every finding that isn't
  // one of the FDE-wide notices (pc == 0, e.g. "N further findings not
  // shown") -- those the caller prints itself, outside the listing.
  nlohmann::json annotations = nlohmann::json::array();
  for (const CFIRow& row : cfi.rows) {
    annotations.push_back({{"pc", row.pc_start}, {"kind", "cfi_row"}, {"text", FormatRowCompact(&row)}});
  }
  for (const InsnTrace& t : trace) {
    annotations.push_back({{"pc", t.pc}, {"kind", "state"}, {"text", FormatStateCompact(t.state)}});
  }
  for (const Finding& f : result.findings) {
    if (f.pc == 0) {
      continue;
    }
    nlohmann::json item = {
        {"pc", f.pc},
        {"kind", "finding"},
        {"severity", f.severity == Finding::Severity::kMismatch ? "mismatch" : "review"},
        {"text", f.message},
    };
    if (f.repeats > 0) {
      item["repeats"] = f.repeats;
    }
    annotations.push_back(std::move(item));
  }
  // Annotated at the jmp's own pc only -- that's the one address this
  // annotation can be sure objdump's listing printed; a guessed target
  // can legitimately land outside [pc_begin, pc_end) via a cross-FDE edge
  // (§6), which this listing never covers.
  for (const GuessedJumpTable& gjt : result.guessed_jump_tables) {
    std::string text = absl::StrFormat("table at 0x%x, %d guessed entries:", gjt.table_addr, gjt.targets.size());
    for (uint64_t target : gjt.targets) {
      absl::StrAppendFormat(&text, " 0x%x", target);
    }
    annotations.push_back({{"pc", gjt.pc}, {"kind", "guessed"}, {"text", text}});
  }

  std::vector<std::string> argv = {
      "ruby",
      ruby_script_path,
      binary_path,
      absl::StrFormat("0x%x", cfi.pc_begin),
      absl::StrFormat("0x%x", cfi.pc_end),
      color ? "1" : "0",
  };
  SpawnOptions spawn_options;
  spawn_options.pipe_stdin = true;
  spawn_options.pipe_stdout = false;  // inherit -- goes straight to the terminal
  absl::StatusOr<Subprocess> proc = SpawnProcess(argv, spawn_options);
  if (!proc.ok()) {
    return absl::InternalError(absl::StrCat("exec-ing ruby failed: ", proc.status().message()));
  }

  absl::Status write_status = WriteAll(proc->stdin_fd, annotations.dump());
  close(proc->stdin_fd);
  int exit_code = WaitForProcess(proc->pid);
  if (!write_status.ok()) {
    return write_status;
  }
  if (exit_code != 0) {
    return absl::InternalError(absl::StrFormat("inspect pipeline exited with status %d", exit_code));
  }
  return result;
}

}  // namespace unwind_analysis

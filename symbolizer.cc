/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "symbolizer.h"

#include <cxxabi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"

namespace unwind_analysis {

namespace {

constexpr size_t kBatchSize = 4096;

std::string ShellQuote(const std::string& s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out += c;
    }
  }
  out += "'";
  return out;
}

bool ToolExists(const std::string& tool) {
  if (tool.find('/') != std::string::npos) {
    return access(tool.c_str(), X_OK) == 0;
  }
  const char* path = getenv("PATH");
  if (path == nullptr) {
    return false;
  }
  for (std::string_view dir : absl::StrSplit(path, ':')) {
    if (dir.empty()) {
      continue;
    }
    std::string candidate = absl::StrCat(dir, "/", tool);
    if (access(candidate.c_str(), X_OK) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::string Demangle(const std::string& name) {
  int status = 0;
  char* out = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
  if (status != 0 || out == nullptr) {
    free(out);
    return name;
  }
  std::string result{out};
  free(out);
  return result;
}

Symbolizer::Symbolizer(const ELFImage& image, Addr2LineMode mode, std::string tool_path)
    : image_(image), tool_path_(tool_path.empty() ? "llvm-addr2line" : std::move(tool_path)) {
  // NOTE: llvm-addr2line is much faster on larger binaries. TODO: try llvm-addr2line and addr2line in order.
  switch (mode) {
    case Addr2LineMode::kOff:
      return;
    case Addr2LineMode::kAuto:
      if (!image_.has_debug_info()) {
        return;  // silently: there is simply nothing to look up
      }
      if (!ToolExists(tool_path_)) {
        disabled_reason_ = absl::StrFormat("%s is not on PATH", tool_path_);
        return;
      }
      use_addr2line_ = true;
      return;
    case Addr2LineMode::kExplicit:
      if (!ToolExists(tool_path_)) {
        disabled_reason_ = absl::StrFormat("%s is not executable", tool_path_);
        return;
      }
      use_addr2line_ = true;
      return;
  }
}

std::string Symbolizer::DebugName(uint64_t vaddr) const {
  auto it = debug_names_.find(vaddr);
  return it == debug_names_.end() ? std::string() : it->second;
}

std::string Symbolizer::Name(uint64_t vaddr) const {
  const std::vector<FuncSymbol>& syms = image_.func_symbols();
  if (syms.empty()) {
    return DebugName(vaddr);
  }
  auto it =
      std::upper_bound(syms.begin(), syms.end(), vaddr, [](uint64_t v, const FuncSymbol& s) { return v < s.vaddr; });
  if (it == syms.begin()) {
    return DebugName(vaddr);
  }
  --it;
  // A zero-sized symbol tells us nothing about where it ends, so accept
  // it only as an exact hit.
  if (it->size == 0 ? it->vaddr != vaddr : vaddr - it->vaddr >= it->size) {
    return DebugName(vaddr);
  }
  std::string name = Demangle(it->name);
  if (vaddr == it->vaddr) {
    return name;
  }
  return absl::StrFormat("%s+0x%x", name, static_cast<unsigned>(vaddr - it->vaddr));
}

void Symbolizer::Prepare(const std::vector<uint64_t>& addresses) {
  if (!use_addr2line_ || addresses.empty()) {
    return;
  }
  std::vector<uint64_t> pending;
  for (uint64_t a : addresses) {
    if (queried_.insert(a).second) {
      pending.push_back(a);
    }
  }
  std::sort(pending.begin(), pending.end());
  pending.erase(std::unique(pending.begin(), pending.end()), pending.end());

  for (size_t start = 0; start < pending.size(); start += kBatchSize) {
    size_t end = std::min(start + kBatchSize, pending.size());
    // -f gives the function name too, which for a library that kept
    // nothing but .dynsym is the only source of names at all. -i is
    // deliberately left off: inlined frames would make the number of
    // output lines per address unpredictable and the pairing ambiguous.
    std::string cmd = absl::StrFormat("%s -f -C -e %s", ShellQuote(tool_path_), ShellQuote(image_.path()));
    for (size_t i = start; i < end; i++) {
      absl::StrAppendFormat(&cmd, " 0x%x", pending[i]);
    }
    cmd += " 2>/dev/null";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
      disabled_reason_ = "could not run addr2line";
      use_addr2line_ = false;
      return;
    }
    // Exactly two lines per address, in order: function name, then
    // file:line. Either can be "??" when it is not known.
    char line[4096];
    for (size_t i = start; i < end; i++) {
      std::string fields[2];
      bool complete = true;
      for (std::string& field : fields) {
        if (fgets(line, sizeof(line), pipe) == nullptr) {
          complete = false;
          break;
        }
        std::string_view text = absl::StripAsciiWhitespace(std::string_view{line});
        if (!text.empty() && !text.starts_with("??")) {
          field = std::string(text);
        }
      }
      if (!complete) {
        break;
      }
      // The name is only trustworthy when a source line came with it.
      // Given a binary with no debug info at all, addr2line still
      // answers -f by naming the nearest preceding dynamic symbol, size
      // be damned -- which is how every address in gcc's 2400 FDEs comes
      // back as "_obstack_newchunk". A name with a line behind it came
      // from real debug info and can be believed.
      if (!fields[1].empty()) {
        source_lines_.emplace(pending[i], fields[1]);
        if (!fields[0].empty()) {
          debug_names_.emplace(pending[i], fields[0]);
        }
      }
    }
    pclose(pipe);
  }
}

std::string Symbolizer::SourceLine(uint64_t vaddr) const {
  auto it = source_lines_.find(vaddr);
  return it == source_lines_.end() ? std::string() : it->second;
}

}  // namespace unwind_analysis

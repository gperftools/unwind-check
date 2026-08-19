/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef SYMBOLIZER_H_
#define SYMBOLIZER_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "elf-image.h"

namespace unwind_analysis {

// Puts names on the addresses a report mentions.
//
// Two independent layers. Symbol names come straight out of the ELF's
// own symbol table and are always available. Source file and line come
// from addr2line, run once over every address the report will mention,
// and are only there when the binary carries debug info.
//
// addr2line also fills a gap the ELF cannot: a stripped library keeps
// only .dynsym, so its internal functions have no name at all locally --
// glibc's __mpn_submul_1, for instance. addr2line follows
// .gnu_debuglink to the separate debug file and knows them, so its
// answer is used whenever the symbol table has nothing.
class Symbolizer {
 public:
  enum class Addr2LineMode { kAuto, kOff, kExplicit };

  Symbolizer(const ElfImage& image, Addr2LineMode mode, std::string tool_path);

  // "operator new(unsigned long)+0x2c", or "" when nothing covers vaddr.
  // Consults addr2line's answer as a fallback, so call Prepare first if
  // you want that.
  std::string Name(uint64_t vaddr) const;

  // Resolves source locations for these addresses in one batch. Must be
  // called before SourceLine; calling it more than once is fine.
  void Prepare(const std::vector<uint64_t>& addresses);

  // "sqlite3.c:221608", or "" when unavailable.
  std::string SourceLine(uint64_t vaddr) const;

  // Nonempty when addr2line was wanted but could not be used.
  const std::string& disabled_reason() const {
    return disabled_reason_;
  }

 private:
  std::string DebugName(uint64_t vaddr) const;

  const ElfImage& image_;
  std::string tool_path_;
  bool use_addr2line_ = false;
  std::string disabled_reason_;
  absl::flat_hash_map<uint64_t, std::string> source_lines_;
  absl::flat_hash_map<uint64_t, std::string> debug_names_;
  absl::flat_hash_set<uint64_t> queried_;
};

// Best-effort Itanium C++ demangling; returns the input unchanged when
// it is not a mangled name.
std::string Demangle(const std::string& name);

}  // namespace unwind_analysis

#endif  // SYMBOLIZER_H_

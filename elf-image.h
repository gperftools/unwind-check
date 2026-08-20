/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef ELF_IMAGE_H_
#define ELF_IMAGE_H_

#include <stdint.h>

#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"

namespace unwind_analysis {

struct LoadSegment {
  uint64_t vaddr;
  uint64_t memsz;
  uint64_t filesz;
  uint64_t offset;
  uint32_t flags;

  bool executable() const;
  bool Contains(uint64_t addr, uint64_t size) const;
};

struct FuncSymbol {
  uint64_t vaddr;
  uint64_t size;
  std::string name;  // as spelled in the ELF, still mangled
};

// An x86-64 ELF64 opened for offline analysis.
//
// The .eh_frame decoder we reuse works on live pointers: it does
// reinterpret_cast<const uint8_t*>(addr) and takes pcrel bases straight
// off the slice it is reading. Mapping the file raw and handing it file
// offsets would silently corrupt every pc_begin, because the
// .eh_frame-to-.text delta is different in file-offset space than it is
// in vaddr space.
//
// So ELFImage performs a "fake load": an address space reservation spanning
// every PT_LOAD's vaddr range, with each segment mmap'd via MAP_FIXED
// at the offset its p_vaddr asks for. Downstream everything then lives in
// one consistent address space, and bias() converts back to the
// link-time vaddrs a human wants to read in a report.
class ELFImage {
 public:
  ELFImage(const ELFImage&) = delete;
  ELFImage& operator=(const ELFImage&) = delete;
  ~ELFImage();

  static absl::StatusOr<std::unique_ptr<ELFImage>> Open(const std::string& path);

  const std::string& path() const {
    return path_;
  }

  // image_addr == vaddr + bias().
  uintptr_t bias() const {
    return bias_;
  }
  uintptr_t ToImage(uint64_t vaddr) const {
    return static_cast<uintptr_t>(vaddr) + bias_;
  }
  uint64_t ToVaddr(uintptr_t image_addr) const {
    return static_cast<uint64_t>(image_addr - bias_);
  }

  // .eh_frame bounds, as vaddrs. Empty (start == end) if the binary has none.
  uint64_t eh_frame_start() const {
    return eh_frame_start_;
  }
  uint64_t eh_frame_end() const {
    return eh_frame_end_;
  }
  bool has_eh_frame() const {
    return eh_frame_end_ > eh_frame_start_;
  }

  // .eh_frame_hdr vaddr, or 0 when PT_GNU_EH_FRAME is absent.
  uint64_t eh_frame_hdr() const {
    return eh_frame_hdr_;
  }

  // Whether anything is likely to be able to resolve source lines and
  // local symbol names here: either the debug info is in this file, or
  // .gnu_debuglink points at the file that has it. A stripped system
  // library has only the latter, and that is exactly where addr2line
  // earns its keep -- glibc's __mpn_submul_1 has no name in .dynsym.
  bool has_debug_info() const {
    return has_debug_line_ || has_debug_link_;
  }

  const std::vector<LoadSegment>& segments() const {
    return segments_;
  }

  // True iff [vaddr, vaddr+size) lies entirely inside one executable PT_LOAD.
  bool IsExecutable(uint64_t vaddr, uint64_t size) const;

  // True iff [vaddr, vaddr+size) lies entirely inside one non-executable
  // PT_LOAD's *file-backed* region -- i.e. within filesz, not just
  // memsz, so a .bss range never qualifies. Used to bound where a
  // resolved switch table may live: real data, never code.
  bool IsFileBackedNonExecutable(uint64_t vaddr, uint64_t size) const;

  // True iff [vaddr, vaddr+size) lies entirely inside one section whose
  // name starts with ".plt" -- ".plt", ".plt.got", ".plt.sec" (the IBT
  // variant), and whatever else a linker invents under that prefix.
  // False (never a false positive) when the binary has no such section,
  // e.g. because it was stripped of sections entirely.
  bool InPLT(uint64_t vaddr, uint64_t size) const;

  // Code (or any mapped) bytes at a vaddr. Returns a short span, or an
  // empty one, when the range runs past what is mapped.
  std::span<const uint8_t> BytesAt(uint64_t vaddr, uint64_t size) const;

  // STT_FUNC symbols from .symtab, or .dynsym when there is no .symtab.
  // Sorted by vaddr.
  const std::vector<FuncSymbol>& func_symbols() const {
    return func_symbols_;
  }

 private:
  ELFImage() = default;

  std::string path_;

  // The raw file mapping. Section headers and symbol tables are read
  // from here, since they need not be inside any PT_LOAD.
  const uint8_t* file_ = nullptr;
  size_t file_size_ = 0;

  // The fake-load mapping.
  uint8_t* image_ = nullptr;
  size_t image_size_ = 0;
  uintptr_t bias_ = 0;

  std::vector<LoadSegment> segments_;
  std::vector<FuncSymbol> func_symbols_;
  uint64_t eh_frame_start_ = 0;
  uint64_t eh_frame_end_ = 0;
  uint64_t eh_frame_hdr_ = 0;
  // [start, end) per section whose name starts with ".plt".
  std::vector<std::pair<uint64_t, uint64_t>> plt_ranges_;
  bool has_debug_line_ = false;
  bool has_debug_link_ = false;
};

}  // namespace unwind_analysis

#endif  // ELF_IMAGE_H_

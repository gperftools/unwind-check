/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "elf-image.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>

#include "absl/algorithm/container.h"
#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "dwarf-constants.h"

namespace unwind_analysis {

namespace {

constexpr uint64_t kPageSize = 4096;

uint64_t RoundDown(uint64_t v, uint64_t align) {
  return v & ~(align - 1);
}

uint64_t RoundUp(uint64_t v, uint64_t align) {
  return RoundDown(v + align - 1, align);
}

// True when [off, off+len) fits in a buffer of the given size, without
// the addition itself wrapping.
bool FitsIn(uint64_t off, uint64_t len, uint64_t size) {
  return off <= size && len <= size - off;
}

// Decodes one DW_EH_PE-encoded pointer out of the eh_frame_hdr. Only the
// handful of encodings that show up there are supported; anything else
// returns nullopt and the caller falls back.
std::optional<uint64_t> DecodeEhPtr(const uint8_t* data, size_t avail, uint64_t data_vaddr, uint8_t encoding,
                                    size_t* consumed) {
  uint8_t lo = encoding & 0x0f;
  uint8_t hi = encoding & 0xf0;
  uint64_t base = 0;
  if (hi == DW_EH_PE_pcrel) {
    base = data_vaddr;
  } else if (hi != 0) {
    return std::nullopt;
  }
  auto load = [&](size_t n, bool sign) -> std::optional<uint64_t> {
    if (avail < n) {
      return std::nullopt;
    }
    uint64_t raw = 0;
    memcpy(&raw, data, n);
    *consumed = n;
    if (sign && n < 8) {
      uint64_t sign_bit = uint64_t{1} << (n * 8 - 1);
      if (raw & sign_bit) {
        raw |= ~((sign_bit << 1) - 1);
      }
    }
    return raw;
  };
  std::optional<uint64_t> raw;
  switch (lo) {
    case DW_EH_PE_sdata4:
      raw = load(4, true);
      break;
    case DW_EH_PE_udata4:
      raw = load(4, false);
      break;
    case DW_EH_PE_sdata8:
    case DW_EH_PE_udata8:
    case DW_EH_PE_absptr:
      raw = load(8, false);
      break;
    default:
      return std::nullopt;
  }
  if (!raw.has_value()) {
    return std::nullopt;
  }
  return base + *raw;
}

}  // namespace

bool LoadSegment::executable() const {
  return (flags & PF_X) != 0;
}

bool LoadSegment::Contains(uint64_t addr, uint64_t size) const {
  if (addr < vaddr) {
    return false;
  }
  uint64_t off = addr - vaddr;
  return off <= memsz && size <= memsz - off;
}

ELFImage::~ELFImage() {
  if (image_ != nullptr) {
    munmap(image_, image_size_);
  }
  if (file_ != nullptr) {
    munmap(const_cast<uint8_t*>(file_), file_size_);
  }
}

bool ELFImage::IsExecutable(uint64_t vaddr, uint64_t size) const {
  for (const LoadSegment& seg : segments_) {
    if (seg.executable() && seg.Contains(vaddr, size)) {
      return true;
    }
  }
  return false;
}

bool ELFImage::IsFileBackedNonExecutable(uint64_t vaddr, uint64_t size) const {
  for (const LoadSegment& seg : segments_) {
    if (seg.executable() || vaddr < seg.vaddr) {
      continue;
    }
    uint64_t off = vaddr - seg.vaddr;
    if (off > seg.filesz || size > seg.filesz - off) {
      continue;
    }
    return true;
  }
  return false;
}

bool ELFImage::InPLT(uint64_t vaddr, uint64_t size) const {
  for (const auto& [start, end] : plt_ranges_) {
    if (vaddr < start) {
      continue;
    }
    uint64_t off = vaddr - start;
    uint64_t range = end - start;
    if (off <= range && size <= range - off) {
      return true;
    }
  }
  return false;
}

std::span<const uint8_t> ELFImage::BytesAt(uint64_t vaddr, uint64_t size) const {
  for (const LoadSegment& seg : segments_) {
    if (vaddr < seg.vaddr) {
      continue;
    }
    uint64_t off = vaddr - seg.vaddr;
    if (off >= seg.filesz) {
      continue;
    }
    uint64_t avail = std::min(size, seg.filesz - off);
    return {reinterpret_cast<const uint8_t*>(ToImage(vaddr)), static_cast<size_t>(avail)};
  }
  return {};
}

absl::StatusOr<std::unique_ptr<ELFImage>> ELFImage::Open(const std::string& path) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return absl::NotFoundError(absl::StrFormat("cannot open %s: %s", path, strerror(errno)));
  }
  absl::Cleanup closer = [fd] { close(fd); };

  struct stat st;
  if (fstat(fd, &st) != 0) {
    return absl::InternalError(absl::StrFormat("cannot stat %s: %s", path, strerror(errno)));
  }
  if (st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
    return absl::InvalidArgumentError(absl::StrFormat("%s is too small to be an ELF64 file", path));
  }

  size_t file_size = static_cast<size_t>(st.st_size);
  void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mapped == MAP_FAILED) {
    return absl::InternalError(absl::StrFormat("cannot mmap %s: %s", path, strerror(errno)));
  }

  std::unique_ptr<ELFImage> img{new ELFImage()};
  img->path_ = path;
  img->file_ = static_cast<const uint8_t*>(mapped);
  img->file_size_ = file_size;

  const uint8_t* file = img->file_;
  Elf64_Ehdr ehdr;
  memcpy(&ehdr, file, sizeof(ehdr));

  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
    return absl::InvalidArgumentError(absl::StrFormat("%s is not an ELF file", path));
  }
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 || ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
    return absl::InvalidArgumentError(absl::StrFormat("%s is not a little-endian ELF64 file", path));
  }
  if (ehdr.e_machine != EM_X86_64) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s targets machine %u; only x86-64 (%u) is supported", path, ehdr.e_machine, EM_X86_64));
  }
  if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s has ELF type %u; only ET_EXEC and ET_DYN are supported", path, ehdr.e_type));
  }
  if (ehdr.e_phnum == 0 || ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
      !FitsIn(ehdr.e_phoff, uint64_t{ehdr.e_phnum} * sizeof(Elf64_Phdr), file_size)) {
    return absl::InvalidArgumentError(absl::StrFormat("%s has a malformed program header table", path));
  }

  uint64_t min_vaddr = std::numeric_limits<uint64_t>::max();
  uint64_t max_end = 0;
  uint64_t eh_frame_hdr_vaddr = 0;
  for (unsigned i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr phdr;
    memcpy(&phdr, file + ehdr.e_phoff + i * sizeof(phdr), sizeof(phdr));
    if (phdr.p_type == PT_GNU_EH_FRAME) {
      eh_frame_hdr_vaddr = phdr.p_vaddr;
      continue;
    }
    if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0) {
      continue;
    }
    if (phdr.p_filesz > phdr.p_memsz || !FitsIn(phdr.p_offset, phdr.p_filesz, file_size)) {
      return absl::InvalidArgumentError(absl::StrFormat("%s has a PT_LOAD running past the end of the file", path));
    }
    img->segments_.push_back(
        LoadSegment{phdr.p_vaddr, phdr.p_memsz, phdr.p_filesz, phdr.p_offset, static_cast<uint32_t>(phdr.p_flags)});
    min_vaddr = std::min(min_vaddr, phdr.p_vaddr);
    max_end = std::max(max_end, phdr.p_vaddr + phdr.p_memsz);
  }
  if (img->segments_.empty()) {
    return absl::InvalidArgumentError(absl::StrFormat("%s has no PT_LOAD segments", path));
  }
  absl::c_sort(img->segments_, [](const LoadSegment& a, const LoadSegment& b) { return a.vaddr < b.vaddr; });

  // The fake load. One PROT_NONE reservation covering every PT_LOAD's vaddr
  // range, with each segment mapped into place via MAP_FIXED, so that the
  // vaddr deltas between sections are the real ones.
  min_vaddr = RoundDown(min_vaddr, kPageSize);
  uint64_t span = RoundUp(max_end, kPageSize) - min_vaddr;
  if (span > (uint64_t{1} << 40)) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s spans %u GiB of vaddr space; refusing to map", path, static_cast<unsigned>(span >> 30)));
  }
  void* image = mmap(nullptr, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (image == MAP_FAILED) {
    return absl::ResourceExhaustedError(absl::StrFormat("cannot reserve %u bytes of image space for %s: %s",
                                                        static_cast<unsigned>(span), path, strerror(errno)));
  }
  img->image_ = static_cast<uint8_t*>(image);
  img->image_size_ = span;
  img->bias_ = reinterpret_cast<uintptr_t>(image) - static_cast<uintptr_t>(min_vaddr);

  for (const LoadSegment& seg : img->segments_) {
    if (seg.filesz == 0) {
      continue;
    }
    if ((seg.vaddr % kPageSize) != (seg.offset % kPageSize)) {
      return absl::InvalidArgumentError(
          absl::StrFormat("%s has a PT_LOAD with unaligned vaddr 0x%x vs offset 0x%x", path, seg.vaddr, seg.offset));
    }
    uint64_t seg_vaddr_start = RoundDown(seg.vaddr, kPageSize);
    uint64_t file_offset = RoundDown(seg.offset, kPageSize);
    uint64_t page_offset = seg.vaddr - seg_vaddr_start;
    uint64_t map_len = RoundUp(seg.filesz + page_offset, kPageSize);
    void* target_addr = reinterpret_cast<void*>(img->ToImage(seg_vaddr_start));
    void* mapped_seg = mmap(target_addr, map_len, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, file_offset);
    if (mapped_seg == MAP_FAILED) {
      return absl::InternalError(
          absl::StrFormat("cannot mmap segment at 0x%x for %s: %s", seg.vaddr, path, strerror(errno)));
    }
  }

  // Sections, when they are there. A stripped .so has none, hence the
  // .eh_frame_hdr fallback below.
  bool have_sections = ehdr.e_shoff != 0 && ehdr.e_shnum != 0 && ehdr.e_shentsize == sizeof(Elf64_Shdr) &&
                       FitsIn(ehdr.e_shoff, uint64_t{ehdr.e_shnum} * sizeof(Elf64_Shdr), file_size) &&
                       ehdr.e_shstrndx < ehdr.e_shnum;
  if (have_sections) {
    auto shdr_at = [&](unsigned i) {
      Elf64_Shdr sh;
      memcpy(&sh, file + ehdr.e_shoff + i * sizeof(sh), sizeof(sh));
      return sh;
    };
    Elf64_Shdr shstr = shdr_at(ehdr.e_shstrndx);
    const char* strings = nullptr;
    size_t strings_size = 0;
    if (shstr.sh_type != SHT_NOBITS && FitsIn(shstr.sh_offset, shstr.sh_size, file_size)) {
      strings = reinterpret_cast<const char*>(file + shstr.sh_offset);
      strings_size = shstr.sh_size;
    }
    auto name_of = [&](const Elf64_Shdr& sh) -> std::string_view {
      if (strings == nullptr || sh.sh_name >= strings_size) {
        return {};
      }
      size_t max = strings_size - sh.sh_name;
      const char* p = strings + sh.sh_name;
      size_t len = strnlen(p, max);
      return {p, len};
    };

    unsigned symtab_idx = 0;
    unsigned dynsym_idx = 0;
    for (unsigned i = 0; i < ehdr.e_shnum; i++) {
      Elf64_Shdr sh = shdr_at(i);
      std::string_view name = name_of(sh);
      if (name == ".eh_frame" && sh.sh_addr != 0 && sh.sh_size != 0) {
        img->eh_frame_start_ = sh.sh_addr;
        img->eh_frame_end_ = sh.sh_addr + sh.sh_size;
      } else if (name.starts_with(".plt") && sh.sh_addr != 0 && sh.sh_size != 0) {
        img->plt_ranges_.emplace_back(sh.sh_addr, sh.sh_addr + sh.sh_size);
      } else if (name == ".debug_line") {
        img->has_debug_line_ = true;
      } else if (name == ".gnu_debuglink") {
        img->has_debug_link_ = true;
      } else if (sh.sh_type == SHT_SYMTAB) {
        symtab_idx = i;
      } else if (sh.sh_type == SHT_DYNSYM) {
        dynsym_idx = i;
      }
    }

    unsigned chosen = symtab_idx != 0 ? symtab_idx : dynsym_idx;
    if (chosen != 0) {
      Elf64_Shdr sym = shdr_at(chosen);
      if (sym.sh_link < ehdr.e_shnum && sym.sh_entsize == sizeof(Elf64_Sym) &&
          FitsIn(sym.sh_offset, sym.sh_size, file_size)) {
        Elf64_Shdr str = shdr_at(sym.sh_link);
        if (FitsIn(str.sh_offset, str.sh_size, file_size)) {
          const char* names = reinterpret_cast<const char*>(file + str.sh_offset);
          size_t count = sym.sh_size / sizeof(Elf64_Sym);
          for (size_t i = 0; i < count; i++) {
            Elf64_Sym s;
            memcpy(&s, file + sym.sh_offset + i * sizeof(s), sizeof(s));
            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC || s.st_shndx == SHN_UNDEF || s.st_value == 0) {
              continue;
            }
            if (s.st_name >= str.sh_size) {
              continue;
            }
            size_t max = str.sh_size - s.st_name;
            const char* p = names + s.st_name;
            size_t len = strnlen(p, max);
            if (len == 0) {
              continue;
            }
            img->func_symbols_.push_back(FuncSymbol{s.st_value, s.st_size, std::string(p, len)});
          }
        }
      }
    }
    absl::c_sort(img->func_symbols_, [](const FuncSymbol& a, const FuncSymbol& b) { return a.vaddr < b.vaddr; });
  }

  img->eh_frame_hdr_ = eh_frame_hdr_vaddr;

  // Stripped-of-sections fallback: PT_GNU_EH_FRAME points at
  // .eh_frame_hdr, whose eh_frame_ptr field points at .eh_frame. We have
  // no size for it, so we run to the end of the containing segment and
  // rely on the terminator record.
  if (!img->has_eh_frame() && eh_frame_hdr_vaddr != 0) {
    std::span<const uint8_t> hdr = img->BytesAt(eh_frame_hdr_vaddr, 20);
    if (hdr.size() >= 8 && hdr[0] == 1) {
      size_t consumed = 0;
      std::optional<uint64_t> ptr =
          DecodeEhPtr(hdr.data() + 4, hdr.size() - 4, eh_frame_hdr_vaddr + 4, hdr[1], &consumed);
      if (ptr.has_value()) {
        for (const LoadSegment& seg : img->segments_) {
          if (seg.Contains(*ptr, 0)) {
            img->eh_frame_start_ = *ptr;
            img->eh_frame_end_ = seg.vaddr + seg.filesz;
            break;
          }
        }
      }
    }
  }

  return img;
}

}  // namespace unwind_analysis

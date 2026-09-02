# unwind-check

unwind-check is a static checker for x86-64 Linux unwind info. You give
it an ELF file -- an executable or a `.so` -- and for every instruction
covered by `.eh_frame` it asks one question: does the CFI declared there
actually match what the code does to the stack and to the callee-saved
registers?

It is the offline, "prove it" sibling of
[aw-backtrace](../aw-backtrace/README.md). aw-backtrace has to unwind
real stacks at runtime, quickly and without crashing, whatever the
compiler emitted. unwind-check has all the time in the world and no
signal-safety constraints, so it goes the other way: disassemble the
covered code, interpret its effect on the frame abstractly, and compare
that against the unwind rules row by row.

## Why this exists

Nothing else seems to check unwind info this way: statically, over a
whole binary, against what the code actually does. It is useful to
have a workable tool that can broadly confirm -- or disprove -- that a
system's unwind info is sound, and catch bugs along the way. Longer
term, the hope is that this or a similar tool will keep compilers from
ever shipping wrong unwind info.

And there is wrong unwind info out there. The bugs this targets:
confirmed clang CFI bugs where a stack adjustment moved but its CFI
annotation didn't, OCaml native-code mismatches, and a long tail of
hand-written assembly with plain wrong `.cfi_*` directives.

## Prior art

I had forgotten about it when I started, but Bastian, Kell and Zappa
Nardelli got here first: [Reliable and Fast DWARF-Based Stack
Unwinding](https://tobast.fr/doc/publications/oopsla19-dwarf.pdf),
OOPSLA 2019. Part of that paper validates `.eh_frame` against what the
code really does -- the same question this tool asks -- and the rest
synthesizes unwind tables for binaries that lack them, and speeds up
unwinding. Worth reading.

The approach is different, though. Theirs is dynamic: run the binary
under a debugger and check the table row for each executed instruction
against the live machine state. That is exact, and limited to the
paths you actually execute -- much the same tradeoff aw-backtrace's
`backtrace-comparer` makes, though that one compares captured
backtraces against the real call stack rather than auditing the
tables.

unwind-check is static -- every instruction of every FDE, no execution
and no inputs needed, which is how a `.cold` fragment or an exception
landing pad gets looked at at all -- and pays for it in `REVIEW`s
wherever the analysis can't model something.

Otherwise the field is thin. `llvm-dwarfdump --verify` never looks at
`.eh_frame` at all; `readelf -wf` and `llvm-readelf --unwind` are pure
dumpers with no verify mode, and won't even tell you that two FDEs
overlap. objtool is the closest static relative, but it checks
frame-pointer discipline for the Linux kernel and emits ORC, rather
than checking a compiler's `.eh_frame`.

## The contract

The governing rule is: bless the easy cases, and flag everything else
for a human with a diagnostic that says why. Silence is never an
answer. An unhandled construct is a loud `REVIEW`, not a quiet pass,
and code the analysis never reached is reported as unreached rather
than counted as fine.

Four verdicts:

* `BLESSED` -- every instruction reached was checked and agreed.
* `REVIEW` -- nothing looked wrong, but something was beyond what this
  version can analyse. The reason is named explicitly.
* `REVIEW-LIGHT` -- a `REVIEW` whose only point of uncertainty was a
  single table-shaped indirect jump with no compiler-declared bound,
  which a second independent guess at the table size then recovered
  completely cleanly. Still exits non-zero.
* `MISMATCH` -- the CFI contradicts the code.

Exit codes: `0` all blessed, `1` a mismatch, `2` review only, `3` the
run itself failed.

There are two checkers. The default ("light") reseeds fresh at every
instruction and gives up on the rest of an FDE the moment it can no
longer confirm the CFA -- it trades precision for very few false
mismatches. `--full` switches to the dataflow-based checker, which does
a real forward worklist analysis, resolves PIC switch tables, follows
exception landing pads through the LSDA, and checks callee-saved
registers at every `ret`.

In theory, and as per the original goal, MISMATCH should be considered
"this is _proven_ wrong". In reality we sometimes get false-positive
MISMATCHes (with the full checker) because we fail to recognize
noreturn calls and then expect the fall-through path to match the
unwind info. Still, quite a few of the MISMATCHes it reports are
obviously genuine bugs (and we hopefully dump enough info to convince
anyone).

It does a somewhat okay-ish job of discovering table-driven switch
destinations, but is still far from catching all of them. Perhaps
eventually we'll find a robust way.

Also notable: non-PIE binaries (`-fno-pie -no-pie`) are currently
broken -- we mis-decode the absolute pointers used for LSDA data. TODO.

## Building and running

```
bazel test :all
bazel build -c opt --copt=-g :unwind-check && ./bazel-bin/unwind-check /bin/ls
```

Once you have a mismatch candidate, drill in with `--pc` set to the
reported address -- any address in the flagged FDE's range works, in
ELF vaddrs. The report below is here to show the
shape of the output and how to read it, not to make a case about any
particular compiler:

```
$ ./bazel-bin/unwind-check --pc=81a5e20 /usr/lib/x86_64-linux-gnu/libLLVM-21.so
MISMATCH isl_stream_read_val  [0x81a5e20 - 0x81a5fab)
  0x81a5e62: declared CFA is rsp+48, but the code leaves rsp at CFA-40
         0x81a5e4e     mov (%rbx), %eax              cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e50     cmp $0x113, %eax              cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e55     jnz 0x00000000081A5E75        cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e57     mov %rbx, %rdi                cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e5a     call 0x000000000825A760       cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e5f     mov (%r14), %rdi              cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
      -> 0x81a5e62     add $0x08, %rsp               cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e66     test %ebp, %ebp               cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e68     jz 0x00000000081A5EBA         cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6a     pop %rbx                      cfa=rsp+40 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6b     pop %r14                      cfa=rsp+32 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
  0x81a5e68: declared CFA is rsp+40, but the code leaves rsp at CFA-48 [and at 1 more addresses]
         0x81a5e55     jnz 0x00000000081A5E75        cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e57     mov %rbx, %rdi                cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e5a     call 0x000000000825A760       cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e5f     mov (%r14), %rdi              cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e62     add $0x08, %rsp               cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e66     test %ebp, %ebp               cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
      -> 0x81a5e68     jz 0x00000000081A5EBA         cfa=rsp+48 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6a     pop %rbx                      cfa=rsp+40 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6b     pop %r14                      cfa=rsp+32 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6d     pop %r15                      cfa=rsp+24 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
         0x81a5e6f     pop %rbp                      cfa=rsp+16 rbx=[CFA-40] rbp=[CFA-16] r14=[CFA-32] r15=[CFA-24] ra=[CFA-8]
```

Reading that: the first line is the verdict, the symbol and the FDE's
range. Each line indented under it is one finding -- the address it
was raised at, then what the declared CFI claims against what the walk
computed for that same address. `[and at N more addresses]` means the
identical finding recurred further along and got collapsed into one
line.

Below each finding is a window of the surrounding instructions, with
`->` on the one the finding is about. The annotations trailing each
instruction are the *declared* CFI row in force there -- the table,
not the analysis. That is the part worth getting used to: the whole
column is the claim under test, and the computed side that contradicts
it appears only in the finding line above. `--inspect_deep` prints the
computed state per instruction if you want both side by side.

So here the tool is saying: the declared CFA stays at rsp+48 across
the `add $0x8, %rsp` at 0x81a5e62 and only starts coming down at the
`pop`s, which means that for the two instructions in between, the
table describes a stack 8 bytes deeper than the code actually has.

For the full asm-plus-CFI dump of the whole FDE, spliced into
`objdump` output:

```
$ ./bazel-bin/unwind-check --pc=81a5e20 --inspect /usr/lib/x86_64-linux-gnu/libLLVM-21.so
```

Use `-c opt` for anything that runs against a real binary -- a dbg
build is tens of times slower, enough that libc can time out.

We use the system-supplied Zydis disassembler, so apt/dnf-install it
(`libzydis-dev` here). abseil comes from the Bazel central registry;
`.bazelversion` pins Bazel 9.2.0. Sources are C++20.

A few useful flags:

* `--full` -- switch to the dataflow checker.
* `--summary_only` / `--show_blessed` -- less / more output.
* `--function=<regex>`, `--pc=<hex>` -- narrow to one function or FDE.
* `--dump_cfi` -- (needs `--pc`) print the decoded row table instead
  of checking it (compare against `readelf --debug-dump=frames-interp`).
* `--inspect` (with `--pc`) -- disassembly-plus-CFI listing of one FDE,
  spliced into `objdump`'s output with its jump arrows and coloring.
* `--report_uncovered_symbols`, `--report_coverage_gaps` -- on by
  default; surface code with no FDE at all, and bytes inside an FDE the
  walk never reached.
* `--addr2line=auto|off|<path>` -- source lines for findings, including
  against stripped system libraries via `.gnu_debuglink`.

There is also a `./robustness-sweep.rb` tool. Give it a large enough
number and it'll scan every ELF it can find (it looks in /usr/bin and
/usr/lib). It is quite fast. On my system it takes only about 16
seconds to check everything (don't be alarmed by the high mismatch
count: nearly all of it is a single ocamlopt bug, plus the LLVM issues
mentioned above, each manifesting across many FDEs -- all to be
reported shortly):

```
$ \time ./robustness-sweep.rb 20000
binaries=6435 abnormal_exits=0
totals: fdes=11113417 blessed=10887919 review_light=0 review=166410 mismatch=59088
slow_over_5s: 5860ms:libwebkitgtk-6.0.so.4.16.10 5625ms:libLLVM.so.20.1 5573ms:libLLVM.so.21.1 5971ms:libwebkit2gtk-4.1.so.0.21.10
394.33user 15.86system 0:15.73elapsed 2606%CPU (0avgtext+0avgdata 828972maxresident)k
0inputs+1608outputs (16major+19290107minor)pagefaults 0swaps
```

## Code pointers

* `elf-image.{h,cc}` -- opens the ELF and does a "fake load": reserve
  one address space spanning every `PT_LOAD` and `mmap` each segment
  `MAP_FIXED` at its `p_vaddr`, so the copied reader's live-pointer
  arithmetic and pcrel bases just work.
* `eh-frame-reader.{h,cc}`, `dwarf-constants.h` -- the `.eh_frame`
  reader, copied from aw-backtrace. `dwarf-constants.h` is
  byte-for-byte identical. For now the decision was to copy and adapt
  aw-backtrace's eh-frame-reader (linear FDE enumeration, throwing
  failures, LSDA-pointer extraction). Perhaps eventually they will be
  unified. We're keeping it light and simple.
* `cfi-table.{h,cc}` -- the *declared* side: turns one FDE into a row
  table.
* `abs-state.{h,cc}` -- the two lattices. One tracks each register and
  stack slot relative to the CFA, which is what a declared unwind rule
  is checked against; the other exists purely to resolve PIC switch
  tables. Joins report what disagreed rather than widening silently.
* `insn-semantics.{h,cc}` -- the *computed* side: what each modelled
  instruction (`push`/`pop`, `add`/`sub`/`and`/`lea` on rsp/rbp, spills
  and reloads, `mov`, `leave`, `call`, `ret`, branches) does to the
  frame. Everything else drops its written registers to unknown -- an
  unmodelled instruction costs precision, never correctness.
* `disasm.{h,cc}` -- thin wrapper over Zydis.
* `fde-checker.{h,cc}` -- the full checker: CFG walk, worklist
  dataflow, switch-table resolution, and the row-by-row comparison.
* `lsda-reader.{h,cc}` -- parses `.gcc_except_table`'s call-site table
  so exception landing pads get checked on the exceptional edge too.
* `light-checker.{h,cc}` -- the default checker (see above).
* `coverage-check.{h,cc}` -- executable symbols with no FDE at all.
* `symbolizer.{h,cc}`, `subprocess.{h,cc}` -- names and source lines;
  a `posix_spawn`-based helper (argv array only, no shell) for
  `addr2line`.
* `diagnostics.{h,cc}`, `inspect.rb` -- the `--inspect` JSON and the
  `objdump` splice.
* `report.{h,cc}`, `unwind-check.cc` -- flags, the structural checks
  (`.eh_frame` present, FDE ranges non-empty, inside one executable
  `PT_LOAD`, non-overlapping), and output.
* `testdata/fixtures.S` -- hand-written CFI whose right answer is fixed
  by construction.
* `robustness-sweep.rb` -- the non-hermetic counterpart to
  `bazel test`: run both checkers over a large sample of the machine's
  real binaries and diff the verdict counts. Sweeps here run on the
  order of a few hundred binaries at a time.

The reader has been checked against ground truth: it matches
`readelf -wf` exactly on `/bin/ls`, libc, libstdc++ and gcc (thousands
of FDEs, zero diffs), and `--dump_cfi` reproduces
`readelf --debug-dump=frames-interp` row for row.

## LLM disclosure

I've used Claude to help me research, plan, develop, and review this
code.

I read the code. I fully own all of it, slop or not, produced by me or
by an LLM under my supervision. I keep LLM-produced code in line with
my style; where the style differs too much, especially in comments, I
either rewrite it myself or have the LLM redo it.

In fact for this project most of the code was written by Claude. It
all started when, as part of getting aw-backtrace into shape, I
reviewed the backtracing approach of gprofng and was reminded that
abstract interpretation isn't hard at all. How hard could it be, I
thought? Well, it took a few days to get this in good enough
shape. Perhaps I used Sonnet at lower effort a little too much.

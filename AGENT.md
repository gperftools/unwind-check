# unwind-check

Where things live and why they are the way they are. See `goal.md` for the
original brief.

## 1. What this is

A static checker that takes an x86-64 Linux ELF (executable or `.so`) and asks,
for every instruction covered by `.eh_frame`, whether the CFI declared there
matches what the code actually does to the stack.

Nothing else does this. `llvm-dwarfdump --verify` never looks at `.eh_frame` at
all; `readelf -wf` and `llvm-readelf --unwind` are pure dumpers with no verify
mode, and will not even tell you two FDEs overlap. The bugs this is aimed at are
catalogued in `../backtrace-test/spec/README`: two confirmed clang CFI bugs
where a stack adjustment moved but its CFI annotation did not, plus a long tail
of hand-written assembly with missing or wrong `.cfi_*`.

**The contract, and it governs every judgement call in here:** bless the easy
cases, and flag anything else for a human with a diagnostic saying why. There
are exactly three verdicts:

* `BLESSED` — every instruction reached was checked and agreed.
* `REVIEW` — nothing looked wrong, but something was beyond what this version
  can analyse. Named explicitly, never silent.
* `MISMATCH` — the CFI contradicts the code.

Silence is never an answer. An unhandled construct is a loud `REVIEW`, and code
the walk never reached is reported as such rather than counted as blessed.

Exit codes follow: 0 all blessed, 1 a mismatch, 2 review only, 3 the run failed.

## 2. Build and test

```
bazel test :all                              # five test targets, all hermetic
bazel build -c opt :unwind-check && ./bazel-bin/unwind-check --summary_only /bin/ls
```

**Use `-c opt` for anything that runs on a real binary.** A dbg build is slow
enough that even a single medium binary like `/usr/bin/gcc` can run for
minutes instead of under a second; `libc.so.6` under dbg is enough to time out
an interactive session. `bazel test` is fine either way since the fixtures are
tiny, but `bazel run` / `bazel-bin/unwind-check` against anything real should
always be `-c opt`.

* `.bazelversion` pins 9.2.0.
* Capstone is the locally installed `libcapstone-dev` (5.0.9 here), linked with
  a bare `-lcapstone` and the system include path. No bazel integration, per
  `goal.md`.
* abseil comes from the bazel central registry. Unlike backtrace-test, this tool
  is offline rather than async-signal-safe, so it is free to use exceptions,
  RAII, allocation and abseil, and it does.
* C++20, 2-space, 120 cols, `BasedOnStyle: Google`. Emacs mode line on every
  file; keep them on new ones. Everything is in `namespace unwind_analysis`.

Useful flags: `--verbose` (list blessed FDEs too), `--summary_only`,
`--function=<regex>`, `--pc=<hex>`, `--dump_cfi` (print the decoded row table
instead of checking; compare against `readelf --debug-dump=frames-interp`),
`--addr2line=auto|off|<path>`, `--check_unmentioned_callee_saved`,
`--report_coverage_gaps`.

## 3. Code map

| file | what it holds |
| --- | --- |
| `elf-image.{h,cc}` | opening the ELF and the "fake load" (§4.1); sections, PT_LOADs, symbols |
| `eh-frame-reader.{h,cc}` | copied from backtrace-test, with two deliberate edits (§4.2) |
| `dwarf-constants.h` | copied verbatim from backtrace-test |
| `cfi-table.{h,cc}` | the *declared* side: a visitor turning one FDE into a row table |
| `disasm.{h,cc}` | RAII Capstone handle, detail on |
| `abs-state.{h,cc}` | the lattice and its join (§4.3) |
| `insn-semantics.{h,cc}` | the *computed* side: what each instruction does to the stack (§4.4) |
| `fde-checker.{h,cc}` | CFG walk, worklist dataflow, and the comparison (§4.5) |
| `symbolizer.{h,cc}` | symbol names and source lines (§4.7) |
| `report.{h,cc}`, `unwind-check.cc` | flags, structural checks, output |
| `testdata/fixtures.S` | hand-written CFI whose right answer is fixed by the fixture |
| `robustness-sweep.sh` | the non-hermetic counterpart to `bazel test`: does it survive real binaries |

## 4. How it works

### 4.1 The fake load

The reader we copied works on **live pointers**: `MakeSlice` does
`reinterpret_cast<const uint8_t*>(addr)` and takes pcrel bases straight off the
slice it is reading. Mapping the file raw and handing it file offsets would
silently corrupt every `pc_begin`, because the `.eh_frame`-to-`.text` delta is
different in file-offset space than in vaddr space.

So `ELFImage` materialises one address space reservation spanning every
PT_LOAD's vaddr range, with each segment mmap'd via `MAP_FIXED` at the offset
its `p_vaddr` asks for. Downstream lives in one consistent address space;
`bias()` converts back to link-time vaddrs for the report. This is checked
directly by `elf-image-test.cc`'s `PreservesVaddrDistancesAcrossSections`.

### 4.2 The copied reader

`eh-frame-reader.h` is `../backtrace-test/eh-frame-reader.h` with two changes,
both enabled by being offline. Everything else is byte-identical, deliberately,
so the two can still be diffed.

1. **`Fail` throws `EHFrameError`** instead of taking the `WithExit` non-local
   exit that runs no destructors. One malformed FDE now costs one report line
   instead of the process — and the upstream rule that nothing in that file may
   own anything by RAII does not apply here.
2. **`EnumerateFDEs`** walks `.eh_frame` linearly. Upstream only ever
   binary-searches `.eh_frame_hdr` for a single PC, which is all a runtime
   unwinder needs; a checker wants every entry. `StartFDE` also gained the FDE's
   PC range, which upstream's visitor never needed.

Do **not** reach for the existing `AW_SKIP_EXIT` knob if resyncing: it turns
`Fail` into `__builtin_trap()`, which is exactly wrong here.

Verified against ground truth: our FDE ranges match `readelf -wf` exactly on
`/bin/ls`, libc, libstdc++ and gcc (~12,000 FDEs, zero differences), and
`--dump_cfi` reproduces `readelf --debug-dump=frames-interp` row for row.

### 4.3 The lattice

The anchor: **CFA is defined once as `rsp` on entry plus 8** and never
redefined. Every tracked value is expressed relative to it, which is what makes
a declared CFI rule directly checkable instead of something to re-derive.

A value is `kTop`, `kBottom`, `kCFARel(delta)`, or `kOrigReg(r)` — "whatever
DWARF register r held on entry". `kTop` and `kBottom` used to be a single
conflated `kUnknown`; they are kept apart because they behave oppositely under
`Join`. `kTop` means *truly unknown* — nothing has been tracked, or precision
was deliberately dropped (an unmodelled instruction, a clobber) — and is the
meet's identity element: meeting it with anything yields that thing back.
`kBottom` means *error/conflict* — two paths each claimed a different concrete
value — and is absorbing: once a register or slot drops to `kBottom` it stays
there, rather than a later join quietly overwriting the recorded conflict with
whatever a third path happens to say. The state is those for the 16 GPRs plus
a map from CFA-relative stack offset to value; a slot absent from the map
reads as `kTop`, so `kBottom` must be stored explicitly there while `kTop`
never is.

`Join` is pointwise, and **reports** what disagreed rather than silently
widening. `.eh_frame` declares one state per PC, so two edges arriving with
different values cannot both match the single row there. It is also
order-independent: joining `a` into a copy of `b` and `b` into a copy of `a`
land on the same state, which `abs-state-test.cc` checks directly.

**Seeding is not `Entry()`.** Plenty of FDEs cover a *fragment* of a function —
cold parts split out of a function, PLT stubs — and start with registers already
spilled and rsp well below the CFA. `AbsState::SeedFromRow` reads the start
state off the FDE's own first row. Assuming `Entry()` everywhere produced 28
false mismatches on `/bin/ls` alone.

`SeedFromRow` also takes `at_function_entry`, which decides what an
*unmentioned* register (`RegRule::Kind::kUnset`, the row saying nothing at
all) seeds to. At a genuine function entry nothing has executed yet, so
silence trivially means "still holds what the caller passed in," the same
fact `Entry()` assumes outright — so it seeds to `kOrigReg(r)`. Anywhere else
— a `.cold` fragment reached by a jump after the hot part already ran, an
exception landing pad reached by the unwinder mid-function — the CFI's
silence only means nothing needed unwinding that register, not that it is
unchanged, so it seeds to `kTop` instead. An *explicit* `kSameValue` rule is a
real CFI assertion either way and is always trusted. `FDEChecker` passes
`false` for every landing pad, since a pad is reached only by the unwinder.

For the FDE's own first row, `FDEChecker` deliberately does **not** pass its
own `at_function_entry` parameter through here — it passes `is_canonical_entry`
instead, a structural fact about the row itself (`CFA = rsp+8`, `ra` at
`[CFA-8]`) rather than a claim from the symbol table. The two sound like they
should agree, and for a normal, symbolized function they do. But a stripped
binary — the common case — has no `.symtab`, and dynsym only names exported
functions: on a stock `/bin/ls` here, 339 of its 341 FDEs carry no symbol at
all, so `at_function_entry` is false for nearly everything. Seeding on it
anyway made unmentioned callee-saved registers seed to `kTop` almost
everywhere, which cascades into a wrong-looking mismatch or review at nearly
every `ret` — dropping `/bin/ls` from 327/341 blessed to 31/341 in testing.
`is_canonical_entry` needs no symbol and is sound for the same reason
`at_function_entry` is: a callee-saved register cannot be clobbered without
first being spilled, and spilling one requires moving off `CFA = rsp+8` — so
an unmoved, canonical CFA is itself proof nothing relevant has run yet. The
one thing this trades away is precision on a genuine entry with a
*non-canonical* first row (`_dl_runtime_resolve_fxsave` again): such an FDE
now seeds unmentioned registers to `kTop` rather than their entry value, but
it already earns its own review below for not looking like an entry, so
nothing is lost silently.

Where a function symbol starts the FDE, `FDEChecker` separately notes it if the
first row is not the canonical `CFA = rsp+8` with `ra` at `[CFA-8]`. That is a
**review, not a mismatch**, and deliberately so: we cannot prove an FDE is
entered by a call. glibc's `_dl_runtime_resolve_fxsave` carries a real function
symbol and legitimately starts at `rsp+24`, because the PLT jumps to it with two
words already pushed. `unwind-check.cc`'s `IsEntryPointName` additionally drops
`foo.cold` fragments, which carry real `STT_FUNC` symbols but are reached by a
jump from `foo`. Nothing structural separates them — the linker merges
`.text.unlikely` into `.text` — so that one goes by the name GCC and clang both
use, a convention rather than a guarantee. It matters: a statically linked
binary has dozens, and each was being accused of an impossible entry row.

### 4.4 Instruction semantics

Modelled precisely: `push`/`pop`, `add`/`sub`/`and`/`lea` on rsp/rbp, `mov` to
and from `[rsp+off]` / `[rbp+off]`, `mov reg,reg`, `leave`, `call`, `ret`,
`jmp`, `jcc`. That is the same small set objtool, LLVM's `CFIInstrInserter` and
Binary Ninja's stack tracker each special-case; nobody lifts all of x86-64 for
this question.

Everything else goes through Capstone's register-access information and drops
the registers it writes to unknown. An unmodelled instruction therefore costs
precision, never correctness — including `and $-16,%rsp`, which needs no
realignment special case: rsp simply becomes untracked, an rbp-based CFA rule
stays checkable, and an rsp-based one turns into a review note.

Two deliberate approximations, both commented at their definitions:

* **Stores through a base we cannot place are assumed not to alias the frame.**
  Unsound in principle, and exactly what objtool and `CFIInstrInserter` assume.
  The alternative drowns the report.
* **Dropping dead slots spares the 128-byte red zone** (`DropDeadSlots`). GCC
  routinely leaves a register's `DW_CFA_offset` rule in force after the `pop`
  that restored it, never emitting `DW_CFA_restore`. That is safe precisely
  because the kernel honours the red zone. Dropping those slots outright flagged
  essentially every GCC-compiled function. Calls use `DropSlotsBelow` instead —
  no red zone survives a call.

### 4.5 The walk, and the one inference in it

Analysis runs in two passes:

1. **Forward dataflow (abstract interpretation):** Recursive descent within
   `[pc_begin, pc_end)` following direct branches, with a per-instruction
   worklist dataflow until the state settles across all reachable instructions.
2. **Verification and reporting:** Once the dataflow has converged to a fixed
   point, reached instructions are inspected in deterministic (sorted PC) order.
   At each address the declared CFI row is compared against the settled state
   **before** the transfer function runs, because the row at pc describes the
   state when `RIP == pc`.

The subtle part is `FallThroughIsReal`. Falling off the end of an instruction is
usually a real edge, but not when the call never returns (`call abort`) or the
bytes are the alignment nop before a cold fragment. Carrying our state into
those manufactures contradictions that are not in the binary.

The CFI itself settles it, with no list of noreturn functions and no care for
what the callee is named. An edge is dropped only when **both**:

* a new CFI row starts at the next address — unrelated code never begins in the
  middle of a row, and a stale-CFI bug can span several instructions, so within
  one row we must keep walking; **and**
* that row's CFA rule is satisfied by neither the state before this instruction
  nor the state after it. Satisfied by the state *after* is an ordinary edge.
  Satisfied by the state *before* means the CFI is describing things one
  instruction late — which is the bug we exist to find, so that edge is taken
  and reported.

Cost: a doubly-wrong CFI could be pruned rather than reported. It then shows up
as an unchecked coverage gap, not as a silent pass.

Merge conflicts are reported as `REVIEW`, not `MISMATCH`, and only when the row
at that address actually consults the register or slot that disagreed. A
disagreement the CFI never reads cannot make the row wrong, and this version has
known reachability gaps, so it reports rather than accuses.

### 4.6 Exit-state validation

Everything above checks the declared CFI against the code within one FDE.
This section is about the edge itself: what happens when an *unconditional*
direct jump, or a resolved switch-table entry, leaves `[pc_begin, pc_end)`.
(Conditional jumps out of the FDE, `jne .Lcold`, are left alone — a taken
branch out is normal control flow this tool was never trying to follow.)

**The primary path: check against the target's own declared row.**
`check_cross_fde_edge` (in `fde-checker.cc`, inside `FDEChecker::Check`) looks
up whichever checkable FDE covers the jump target and, if one does, compares
the abstract state at the jump against *that* FDE's declared CFI row at that
exact PC — the same `RowChecker::Check` used for every ordinary in-FDE
comparison, unmodified. This works with no coordinate translation, because a
tail call or a jump into a `.cold` fragment pushes no new frame: the target's
CFA rule and the source's tracked CFA-relative values describe the same
physical stack, so `RowChecker::CheckCFA`'s test reduces to "does the target
row's CFA rule yield the same CFA the source state is already tracking",
regardless of whose row it is. The one adjustment: when the target row is
that FDE's own canonical entry (`CFIRow::IsCanonicalEntry`), an unmentioned
callee-saved register is force-checked as still holding its entry value —
DWARF's ordinary convention at a genuine call entry, the same one
`AbsState::SeedFromRow` already applies when seeding that FDE's own analysis
— so a tail call that clobbers a callee-saved register without restoring it
is still caught even when the target's body never bothered to say so
explicitly. This is strictly more precise than guessing at ABI compliance: a
jump into a `.cold` fragment whose frame is legitimately still half torn down
now verifies cleanly instead of only earning a REVIEW, and a jump whose state
actually contradicts the target is a real `MISMATCH`, not a hand-waved
REVIEW. The same lookup and comparison applies to a resolved switch-table
entry landing outside the FDE, which is the common way a table dispatches
into a shared `.cold` case.

**The fallback: the x86-64 return convention.** `CheckExitState` runs only
when no checkable FDE covers the target — a jump into a PLT stub (excluded
from the checkable set even when gnu-ld gives it CFI; lld doesn't) or into
genuinely uncovered code — and at every `ret`, where there is no "target FDE"
in the first place. Three things must hold at that point: rsp back at
`CFA-8`, every callee-saved register still holding its entry value, and the
return-address slot at `[CFA-8]` still holding what the call originally put
there. A `ret` that fails any of these is a `MISMATCH` — the ABI is not
optional. A tail-call jump is softer: rsp not being back at `CFA-8` is only a
`REVIEW`, because the jump might be an ordinary branch into a noreturn call
or other uncovered code rather than a real tail call, and in that ambiguous
case the frame legitimately is not torn down yet. When that ambiguity fires,
the callee-saved and return-address checks are skipped entirely rather than
compared against a CFA that may not mean "the frame is gone" here. All three
checks also degrade to a named `REVIEW` (never silence) when the relevant
value is untracked rather than concretely wrong, matching the rest of this
tool's "say why, don't guess" rule.

This only runs when the FDE's first row was canonical (see `is_canonical_entry`
in §4.3) — otherwise there is no "should be `CFA-8`" to check against, and the
FDE gets one review saying so instead.

**Indirect tail calls.** An unresolved indirect jump (`jmp *%rax`) is
ordinarily a named `REVIEW` — jump tables are not resolved (§6). But if the
state at that jump already looks like a clean exit (rsp at `CFA-8`, every
callee-saved register at its entry value — see `IsExitState`), it is blessed
instead, on the theory that this is a virtual call or function-pointer tail
call rather than an in-function jump table, and whatever it jumps to is
somebody else's FDE, checked on its own. This is a heuristic, not a proof: a
small dispatcher function that hasn't touched the stack yet can have exactly
this shape at a genuine jump-table dispatch, and its case targets would then
go unwalked without a word at that PC. The safety net is
`--report_coverage_gaps` (on by default): bytes inside the FDE the walk never
reached still surface as a `REVIEW` naming the gap, so this can turn a
specific "unresolved indirect jump" diagnostic into a vaguer "N bytes not
reached" one, but it cannot turn into a silent, fully wrong `BLESSED` unless
that flag is turned off, or every one of the jump's real targets happens to
be reached some other way regardless.

### 4.7 Symbolization

Names come from `.symtab`, or `.dynsym` when there is no `.symtab`, and always
work. Source lines come from a single batched `addr2line` run over every address
the report is about to print.

Two things worth knowing. `auto` mode enables addr2line when the binary has
`.debug_line` **or** `.gnu_debuglink`: a stripped system library has only the
latter, and following it is how a finding in libc gets reported against
`sysdeps/x86_64/addmul_1.S:36`. And addr2line's `-f` name is only believed when a
source line came with it — given no debug info at all it still answers `-f` by
naming the nearest preceding dynamic symbol, size be damned, which is how every
one of gcc's 2448 FDEs comes back as `_obstack_newchunk`.

### 4.8 Structural checks

Before any disassembly, in `unwind-check.cc`: `.eh_frame` must exist; each FDE range
must be non-empty and inside one executable PT_LOAD; ranges must not overlap.
Nothing else available reports any of this.

Poor-man's PLT handling lives in the same pass: `ELFImage::InPLT` (`elf-image.{h,cc}`)
records the vaddr range of every section whose name starts with `.plt` --
`.plt`, `.plt.got`, `.plt.sec` (the IBT variant), and whatever else a linker
invents under that prefix -- and any FDE falling entirely inside one is
skipped and reported blessed without ever reaching `FDEChecker`. These are
linker-generated stubs, not compiler output with CFI worth second-guessing.
Sections are optional and this degrades to finding nothing, same as the rest
of §4.7's symbol handling; a plain `jmp` *into* a PLT stub from ordinary code
still goes through the regular tail-call exit-state check, unweakened.

## 5. Where it stands

Measured with the tool itself (numbers drift a little with the toolchain
versions installed on whatever machine runs this — treat the shape, not the
exact digits, as durable):

| binary | FDEs | blessed | review | mismatch |
| --- | --- | --- | --- | --- |
| `/bin/ls` | 341 | 338 | 2 | 1 |
| `libc.so.6` | 3919 | 3862 | 54 | 3 |
| `libstdc++.so.6` | 5332 | 4831 | 501 | 0 |
| `/usr/bin/gcc` | 2448 | 2290 | 157 | 1 |
| a `-static` hello world | 1090 | 1055 | 32 | 3 |

Review counts here are much lower than earlier versions of this tool: §4.6's
cross-FDE check resolves the majority of what used to be an unavoidable
REVIEW at every `.cold`-fragment tail call and every switch-table case shared
across FDEs, verifying them against the target's own declared row instead.

The remaining mismatches are known and were checked by hand; some kinds are
already listed in `spec/README` as known-bad:

* GMP's hand-written `__mpn_addmul_1` and `__mpn_submul_1` carry no `.cfi_*` at
  all, so the table still claims `rsp+8` two pushes in.
* glibc's `__clone` ends its CFI before it is done with the stack.
* `_start`, which pops the return address while the CIE still says it is on the
  stack. Real, and harmless: nothing unwinds past `_start`.

`/usr/bin/gcc`'s remaining mismatch is a spill slot the CFI claims holds one
register but which is reached holding the entry value of a different one on
some path — either a genuine inaccuracy or an artefact of a path this version
cannot prove unreachable. It is flagged, which is what the contract asks for.

Precision at scale: over a 400-binary sample of `/usr/bin` and
`/usr/lib/x86_64-linux-gnu` — 41,872 FDEs, 40,932 blessed — there were **zero**
crashes, hangs or runs over five seconds, and exactly **one** mismatch, which
was `_start` again. Reproduce with `./robustness-sweep.sh`;
anything it prints as ABNORMAL is a bug in this tool.

Remaining reviews are dominated by the two documented gaps — unreached bytes
(C++ exception landing pads, which is why libstdc++ is the outlier) and
unresolved indirect jumps whose target can't be resolved to a jump table at
all — plus jump-out edges whose target has no covering FDE, which still fall
back to the ABI-based tail-call heuristic (§4.6).

## 6. Known gaps and what is next

Deliberately out of scope for this version, in rough order of value:

* **Jump tables.** An indirect jump is a `REVIEW` naming the PC, unless the
  state at that point already looks like a clean function exit, in which case
  it is blessed as a probable indirect tail call instead (§4.6) — a real jump
  table dispatching from that same shape is the failure mode, caught only by
  `--report_coverage_gaps` rather than by name. The heuristics to properly
  resolve tables are already written down in
  `../backtrace-test/doc/binary-unwind-analysis.adoc`: the function-bounds
  golden rule, the PIC `movsxd`/`add` pattern, and a 512-entry circuit breaker.
  This plus landing pads is most of the review volume. A table this version
  *does* resolve is on firmer footing than before: an entry landing outside
  the FDE (typically a shared `.cold` case) is now checked against whatever
  FDE covers it (§4.6) rather than just noted as unfollowed, so a stale-CFI
  bug reachable only through such a table no longer goes unverified.
* **Exception landing pads.** Reachable only through the LSDA, so the walk never
  gets there and the bytes are reported as an unchecked gap. Parsing
  `.gcc_except_table` would seed them.
* **DWARF expressions.** Recorded, never evaluated. A tiny expression
  interpreter plus the four-state DRAP recogniser from
  `../backtrace-test/doc/amd64-drap-problem.adoc` — including the known gcc<16
  missing-`cfi_restore` window — is the next chunk.
* `.eh_frame_hdr` consistency checking (count, sortedness, entries pointing at
  the FDEs they claim) is not implemented; only `.eh_frame` itself is checked.
* aarch64, `.debug_frame`, 64-bit DWARF lengths, CIE versions other than 1.
* `--format=json` and a suppression baseline.
* The full `spec/README` corpus as a regression suite: sqlite/speedtest1, the
  LLVM binaries with the two confirmed clang bugs, glibc `dl_trampoline` and
  `setcontext`, widevine's realigning code, the openssl perlasm.

Testing gaps: the structural checks (overlapping ranges, non-executable FDE
ranges) have no test — they are hard to produce with an assembler and are
currently only exercised by real binaries.

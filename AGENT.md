# unwind-check

Where things live and why they are the way they are. See `goal.md` for the original brief.

## 1. What this is

A static checker that takes an x86-64 Linux ELF (executable or `.so`) and asks, for every
instruction covered by `.eh_frame`, whether the CFI declared there matches what the code actually
does to the stack.

Nothing else does this. `llvm-dwarfdump --verify` never looks at `.eh_frame`; `readelf -wf` /
`llvm-readelf --unwind` are pure dumpers with no verify mode and won't even tell you two FDEs
overlap. The bugs this targets are catalogued in `../aw-backtrace/spec/README`: two confirmed
clang CFI bugs (a stack adjustment moved but its CFI annotation didn't) plus a long tail of
hand-written assembly with missing or wrong `.cfi_*`.

**The contract, and it governs every judgement call in here:** bless the easy cases, flag anything
else for a human with a diagnostic saying why. Silence is never an answer — an unhandled construct
is a loud `REVIEW`, and code the walk never reached is reported as such, not counted as blessed.
Four verdicts:

* `BLESSED` — every instruction reached was checked and agreed.
* `REVIEW` — nothing looked wrong, but something was beyond what this version can analyse. Named
  explicitly.
* `REVIEW-LIGHT` — a `REVIEW` whose sole point of uncertainty was one table-shaped indirect jump
  with no compiler-declared bound, fully recovered by guessing (§6). Still exits non-zero; only
  reached when a second, independent guess at the table size came back completely clean.
* `MISMATCH` — the CFI contradicts the code.

Exit codes: 0 all blessed, 1 a mismatch, 2 review only, 3 the run failed.

## 2. Build and test

```
bazel test :all                              # seven test targets, all hermetic
bazel build -c opt :unwind-check && ./bazel-bin/unwind-check --summary_only /bin/ls
```

**Use `-c opt` for anything that runs on a real binary** — a dbg build is slow enough that
`/usr/bin/gcc` can take minutes and `libc.so.6` can time out an interactive session. **Gotcha:**
`bazel-bin/unwind-check` is one symlink, not one binary — it points at whichever config the *most
recent* build/test touched, so a plain `bazel test :all` after `bazel build -c opt` silently
repoints it back to the (30-60x slower) dbg build, which reads exactly like a hang or a perf
regression. If a real binary suddenly looks hung after touching the build, re-run `bazel build -c
opt :unwind-check` first.

* `.bazelversion` pins 9.2.0.
* Disassembly is Zydis (`libzydis-dev`, system-installed, `-lZydis -lZycore`, no bazel integration
  — same offline policy `goal.md` set). Formatter is pinned to `ZYDIS_FORMATTER_STYLE_ATT`; unlike
  Capstone, Zydis's AT&T style is a separate pass over already-decoded operands, so it can't
  reorder the structured operand array `Transfer()` reads.
* abseil comes from the bazel central registry. This tool is offline rather than
  async-signal-safe, so it freely uses exceptions, RAII, allocation, abseil.
* C++20, 2-space, 120 cols, `BasedOnStyle: Google`. Emacs mode line on every file. Everything is
  in `namespace unwind_analysis`.

The light checker (§4.9) runs by default; `--full` switches to the dataflow-based `FDEChecker`
(§4.5-§4.6; §4.3-§4.4's lattice and instruction semantics are shared machinery both checkers use).

Useful flags: `--show_blessed`, `--summary_only`, `--function=<regex>`, `--pc=<hex>`, `--dump_cfi`
(print the decoded row table instead of checking; compare against `readelf
--debug-dump=frames-interp`), `--addr2line=auto|off|<path>`, `--check_unmentioned_callee_saved`,
`--report_coverage_gaps`, `--report_uncovered_symbols` (§4.8), `--inspect` (requires `--pc`;
disasm+CFI listing of one FDE instead of the summary), `--inspect_deep` (with `--inspect`, also
shows the dataflow's converged abstract state before each instruction).

`--inspect` serializes declared CFI rows/findings/(deep mode) state as JSON (`diagnostics.cc`) and
pipes it into `inspect.rb`, which runs `objdump -d --visualize-jumps` over the range and splices
annotations in by address, reusing objdump's jump-arrow gutters and disasm coloring rather than
reimplementing them. `inspect.rb` (a Bazel `data` dep, located via `@rules_cc//cc/runfiles`) and
`subprocess.{h,cc}` (`posix_spawn`-based, argv-array only, no shell — also used by
`symbolizer.cc`'s addr2line) fail loudly on a missing tool or unrecognized output. `--inspect`
always runs the full checker regardless of `--full` (needs `CheckWithGuessing`'s `trace_out`,
which `LightCheck` doesn't produce) — a stderr warning says so.

## 3. Code map

| file | what it holds |
| --- | --- |
| `elf-image.{h,cc}` | opening the ELF and the "fake load" (§4.1); sections, PT_LOADs, symbols |
| `eh-frame-reader.{h,cc}` | copied from aw-backtrace, with two deliberate edits (§4.2) |
| `dwarf-constants.h` | copied verbatim from aw-backtrace |
| `cfi-table.{h,cc}` | the *declared* side: a visitor turning one FDE into a row table |
| `disasm.{h,cc}` | thin wrapper over a Zydis decoder and AT&T-style formatter |
| `abs-state.{h,cc}` | the two lattices (CFI and switch-table) and their joins (§4.3) |
| `insn-semantics.{h,cc}` | the *computed* side: what each instruction does to the stack (§4.4) |
| `lsda-reader.{h,cc}` | parses `.gcc_except_table`'s call-site table for landing pads (§4.5) |
| `fde-checker.{h,cc}` | CFG walk, worklist dataflow, and the comparison (§4.5) |
| `coverage-check.{h,cc}` | symbols in executable memory with no FDE at all (§4.8) |
| `light-checker.{h,cc}` | the second, no-dataflow checker (§4.9); default, `--full` switches back |
| `symbolizer.{h,cc}` | symbol names and source lines (§4.7) |
| `subprocess.{h,cc}` | `posix_spawn`-based child-process helper, no shell |
| `report.{h,cc}`, `unwind-check.cc` | flags, structural checks, output |
| `diagnostics.{h,cc}`, `inspect.rb` | `--inspect` JSON + objdump splice (§2) |
| `testdata/fixtures.S` | hand-written CFI whose right answer is fixed by the fixture |
| `robustness-sweep.rb` | non-hermetic counterpart to `bazel test`: survives real binaries? |

## 4. How it works

### 4.1 The fake load

The copied reader works on **live pointers**: it dereferences addresses directly and takes pcrel
bases off the slice it's reading. Mapping the file raw with file offsets would corrupt every
`pc_begin`, since the `.eh_frame`-to-`.text` delta differs between file-offset space and vaddr
space.

So `ELFImage` reserves one address space spanning every PT_LOAD's vaddr range, mmapping each
segment `MAP_FIXED` at its `p_vaddr`. Downstream lives in one consistent address space; `bias()`
converts back to link-time vaddrs for the report. Checked by `elf-image-test.cc`'s
`PreservesVaddrDistancesAcrossSections`.

### 4.2 The copied reader

`eh-frame-reader.h` is `../aw-backtrace/eh-frame-reader.h` with two changes, both enabled by
being offline — everything else byte-identical, deliberately, so the two can still be diffed:

1. **`Fail` throws `EHFrameError`** instead of the `WithExit` non-local exit that skips
   destructors — one malformed FDE now costs one report line, not the process. (Don't reach for
   `AW_SKIP_EXIT` if resyncing — that turns `Fail` into `__builtin_trap()`, exactly wrong here.)
2. **`EnumerateFDEs`** walks `.eh_frame` linearly instead of binary-searching `.eh_frame_hdr` for
   one PC — a checker wants every entry. `StartFDE` also gained the FDE's PC range.

Verified against ground truth: matches `readelf -wf` exactly on `/bin/ls`, libc, libstdc++, gcc
(~12,000 FDEs, zero diffs); `--dump_cfi` reproduces `readelf --debug-dump=frames-interp` row for
row.

### 4.3 The lattice

**Anchor:** CFA is defined once as `rsp` on entry plus 8 and never redefined. Every tracked value
is relative to it, which is what makes a declared CFI rule directly checkable instead of something
to re-derive.

**Two separate lattice types**, same top/bottom shape, different join rules, consulted by
different code:

* `AbsVal` (the CFI lattice, what a declared unwind rule is checked against): `kTop` (truly
  unknown — nothing tracked, or precision deliberately dropped; identity element of `Join`),
  `kBottom` (error/conflict — two paths claimed different concrete values; absorbing, so a later
  join can't paper over a recorded conflict), `kCFARel(delta)`, `kOrigReg(r)` ("whatever DWARF
  register r held on entry"), `kOther` (known, and definitely *not* CFA-relative or any register's
  entry value — e.g. a rip-relative `lea` result). `kOther` matters because every `RowChecker`
  test is `is_unknown() -> review, else -> mismatch`: `lea .LC0(%rip),%rbx` where the CFI says rbx
  is untouched is a real bug (`kOther` vs. declared), while an unmodelled `add %rax,%rbx` is just
  giving up (`kTop` — regression-tested by `fixtures.S`'s `bad_lea_into_callee_saved`). State: 16
  GPRs plus a map from CFA-relative stack offset to value; an absent slot reads as `kTop`, so
  `kBottom` must be stored explicitly.
* `TableVal` (everything that exists solely to resolve PIC switch-table dispatches, invisible to
  any CFI rule): `kNone`, `kConflict`, `kConst`, `kTableEntry`, `kJumpTarget`, plus `value_bound`
  and `table_bound`. `value_bound` is anything provable about a number's width, from any source (a
  zero-extending widen, a 32-bit write, a guard). `table_bound` is the narrower subset established
  *only* by a `cmp $imm,%r; ja default` guard — a compiler-declared bound — and only it may size a
  switch table; a width fact like `movzbl` proving "at most 255" is honest but would resolve a
  256-entry table out of whatever `.rodata` follows the real one. Both bounds join by `max`, with
  `kBoundTop` as identity so one unbounded path wipes out another's bound with no special case.
  `kNone` vs `kConflict` must stay distinct: adopt-from-`kNone` lets an ignorant predecessor
  destroy a resolved dispatch (loses `/bin/ls`'s main switch immediately), while the reverse lets
  a third predecessor resurrect an answer after two others already disagreed.

`Join` itself is pointwise and **reports** what disagreed rather than widening silently —
`.eh_frame` declares one state per PC, so two edges landing there with different values can't both
be right — and is order-independent (checked in `abs-state-test.cc`).

**Both halves of a register move together.** `SetReg` clears the table half too, so a fresh CFI
value can't keep a stale table identity; `SetTableReg` stamps `kOther` on the CFI side (a
`.rodata` pointer is definitionally "not an entry value"); `CopyReg` carries both, for a
full-width register move only. **Slots hold CFI values only** — a spilled table base/index loses
its table identity, which the 400-binary sweep shows costs nothing measurable and avoids a second
slot map and join.

**Seeding is not `Entry()`.** Many FDEs cover a *fragment* — cold splits, PLT stubs — starting
with registers already spilled. `AbsState::SeedFromRow` reads the start state off the FDE's own
first row instead; assuming `Entry()` everywhere produced 28 false mismatches on `/bin/ls` alone.

`SeedFromRow` takes `at_function_entry`, deciding what an *unmentioned* register seeds to:
`kOrigReg(r)` at a genuine entry (silence means "still holds the caller's value"), `kTop`
elsewhere (a `.cold` fragment or landing pad reached mid-function, where silence just means
nothing needed unwinding that register). An *explicit* `kSameValue` rule is always trusted either
way.

For the FDE's own first row, `FDEChecker` uses `is_canonical_entry` instead (`CFA = rsp+8`, `ra`
at `[CFA-8]` — a structural fact, not a symbol-table claim) — because most FDEs carry no symbol at
all (339/341 on a stock `/bin/ls`), and seeding on `at_function_entry` there dropped `/bin/ls`
from 327/341 blessed to 31/341 (unmentioned callee-saved regs seeding to `kTop` almost
everywhere). A canonical, unmoved CFA is itself proof nothing relevant has run yet, symbol or not
— at the cost of precision on a genuine entry with a non-canonical first row
(`_dl_runtime_resolve_fxsave`, entered at `rsp+24` because the PLT already pushed two words),
which already earns its own review below for not looking like an entry.

Where a function symbol starts the FDE but the first row isn't canonical, that's a **review, not a
mismatch** — we can't prove an FDE is entered by a call. `IsEntryPointName` also drops `foo.cold`
fragments (real `STT_FUNC` symbols reached by a jump from `foo`, by naming convention only — the
linker merges `.text.unlikely` into `.text`, so nothing structural separates them).

**A comparison is not a bound; a branch is.** `cmp $imm,%reg` only records itself in
`AbsState::last_cmp`; deriving a bound at the `cmp` invents one on paths where it doesn't apply (a
switch's default edge, or no branch at all). The only place a comparison becomes a fact is
`TransferEdge` — a second entry point beside `Transfer`, called by the walker on a per-edge copy
of the state — on the one branch edge where the value is in range (fall-through for `ja`/`jae`,
taken edge for `jbe`/`jb`). `last_cmp` is invalidated by any later EFLAGS write (`Transfer`) or
any later write to the compared register (`SetReg`/`ClobberReg`) — both needed, or `cmp $5,%eax;
mov (%rbx),%rax; ja default` would bound the wrong value. (`Join` merges `last_cmp` itself:
equal-preserving-else-clear.)

A guard becomes a bound two ways, both needed because of width: `cmp $0xe,%esi` says nothing about
all of `rsi` (upper half undefined by the psABI) but everything about a later `mov %esi,%eax` that
reads exactly those 32 bits. (1) **Promotion at the branch**, when `value_bound` already proves
the register no wider than what was compared, or the compare was 64-bit — immediate full-register
fact. (2) **Collection at a widen** otherwise: the guard rides along until a zero/sign-extending
read of at most as many bits picks it up. Promotion doesn't retire the guard, since the state can
still weaken at a later join and `Join` never lets an absent `last_cmp` adopt a present one — both
paths must record it (`libstdc++`'s `basic_stringstream` dispatch regressed to `REVIEW` until they
did). Guard bounds are tracked forward this way rather than found by an on-demand backward
byte-walk, which gets the dominance property for free (a `ja` reachable from a predecessor that
skipped the `cmp` just sees `last_cmp` cleared by the ordinary `Join`).

### 4.4 Instruction semantics

Modelled precisely: `push`/`pop`, `add`/`sub`/`and`/`lea` on rsp/rbp, `mov` to and from
`[rsp+off]`/`[rbp+off]`, `mov reg,reg`, `movzx reg,reg`, `leave`, `call`, `ret`, `jmp`, `jcc`,
`cmp $imm,%reg` (only for the switch-table guard fact, §4.3). Close to the same small set objtool,
LLVM's `CFIInstrInserter`, and Binary Ninja's stack tracker each special-case — nobody lifts all
of x86-64 for this question.

A destination's *identity* survives only a full-width move; its numeric bounds (TableVal half)
survive any write covering the whole 64-bit register — 64-bit explicit, or 32-bit (x86-64
zero-extends those): `mov %esi,%eax`, `movzbl`, `movsbl`, `movslq`. An 8/16-bit destination
carries nothing (`mov %sil,%al` leaves bits 8..63 alone). Sign-extending forms carry only when
`value_bound` proves the source's sign bit clear. Source and guard are read before the destination
is clobbered — `movzbl %al,%eax` reads the register it also writes.

Everything else goes through Zydis's per-operand read/write accounting and drops written registers
to unknown — an unmodelled instruction costs precision, never correctness (`and $-16,%rsp` needs
no special case: rsp just goes untracked). Two deliberate approximations:

* **Stores through an unplaceable base are assumed not to alias the frame.** Unsound in principle,
  same assumption objtool and `CFIInstrInserter` make. The alternative drowns the report.
* **Dropping dead slots spares the 128-byte red zone** (`DropDeadSlots`). GCC routinely leaves a
  `DW_CFA_offset` rule in force after the `pop` that restored it, relying on the kernel honouring
  the red zone; not dropping those slots flagged essentially every GCC-compiled function. Calls
  use `DropSlotsBelow` instead — no red zone survives a call.

### 4.5 The walk, and the one inference in it

Two passes: (1) forward worklist dataflow, recursive descent within `[pc_begin, pc_end)` following
direct branches until the state converges; (2) verification in deterministic (sorted PC) order,
comparing the declared row against the state *before* the transfer function runs at each address
(the row at pc describes the state when `RIP == pc`).

**`FallThroughIsReal`.** Falling off an instruction is usually a real edge, but not after a
noreturn call (`call abort`) or alignment padding before a cold fragment. The CFI settles it, with
no noreturn-function list: an edge is dropped when a new row starts at the next address, **and**
either signal says that row belongs to a different block:

* **CFA rule check.** Satisfied by neither before- nor after-state means it describes something
  unrelated. Satisfied only by the after-state is an ordinary edge. Satisfied only by the
  before-state means the CFI is one instruction late — the bug this tool exists to find — so that
  edge is taken and reported.
* **Row shape right after a call.** The CFA test alone is blind to the common case: a call never
  moves rsp, so an rsp-based CFA rule is trivially satisfied on both sides whether or not the
  callee returns. A row with no register-save rule beyond `ra` is prologue-shaped — the same shape
  a real block start has. Seeing that shape appear right after a call, when the row being left had
  accumulated real rules, means a fresh block starts here (e.g. two `.cold` throw-sites
  concatenated back to back). Fires only right after a call, and only when the row being left
  wasn't itself already bare.

Cost of getting this wrong: a doubly-wrong CFI could be pruned instead of reported, but then shows
up as an unchecked coverage gap, not a silent pass. Validated against `robustness-sweep.rb`'s
400-binary sample: the shape check never changed a binary's mismatch count, only reclassified a
handful of FDEs from `BLESSED` to `REVIEW` (GCC-family binaries calling `internal_error`/
`fancy_abort`-style helpers). Merge conflicts are `REVIEW`, not `MISMATCH`, and only reported when
the row at that address actually consults the register/slot that disagreed.

**Exception landing pads.** Nothing branches to a landing pad directly — only the unwinder does,
via the LSDA — so the walk wouldn't find one on its own. `lsda-reader.{h,cc}` parses
`.gcc_except_table`'s call-site table into `[start,end) -> landing_pad` ranges; when the dataflow
processes a `call` whose PC falls in one, `Check()` propagates the actual computed post-call state
(callee-saved/CFA preserved, caller-saved clobbered — the same transfer used for the call's
fall-through edge) to the pad as a real edge, which doubles as a cross-check that the pad's
declared row agrees with reality — a stale CFI on the exceptional edge is now a genuine
`MISMATCH`, not unobservable. Seeding a pad from its own declared row survives only as a fallback
for an unresolved call site, flagged with its own weaker `REVIEW`.

One call site can feed many pads and vice versa — ordinary `Join`. The worklist must dedup pending
pushes (`pending_pushes`, at most one entry per pc), or several predecessors detecting a change
before a shared target is dequeued redo `Transfer` for no new information — a high-fan-in landing
pad in real C++ (`lib2geom.so.1.4.0`, `zutty`) turned sub-second FDEs into 15-50s ones without
this.

### 4.6 Exit-state validation

What happens when an *unconditional* jump, or a resolved switch-table entry, leaves `[pc_begin,
pc_end)`.

**Primary path: check against the target's own declared row.** `CheckCrossFDEEdge` looks up
whichever checkable FDE covers the jump target and compares the abstract state at the jump against
that FDE's declared row there, via the same `RowChecker::Check` used everywhere else. No
coordinate translation needed — a tail call or jump into a `.cold` fragment pushes no new frame,
so the target's CFA rule and the source's CFA-relative values describe the same physical stack.
One adjustment: when the target row is that FDE's own canonical entry, an unmentioned callee-saved
register is force-checked as still holding its entry value (the same convention `SeedFromRow`
applies at a real entry), so a tail call that clobbers a callee-saved register without restoring
it is still caught. Same lookup applies to a resolved switch-table entry landing outside the FDE.

**Fallback: the x86-64 return convention.** `CheckExitState` runs only when no checkable FDE
covers the target (a PLT stub, or genuinely uncovered code), and at every `ret`. Three things must
hold: rsp back at `CFA-8`, every callee-saved register still at its entry value, and the
return-address slot at `[CFA-8]` unchanged — a failing `ret` is a non-optional `MISMATCH`. A
tail-call jump is softer: rsp not back at `CFA-8` is only a `REVIEW` (might be a branch into a
noreturn call rather than a real tail call), and then the other two checks are skipped entirely.
All three degrade to a named `REVIEW`, never silence, when the value is untracked rather than
concretely wrong. Only runs when the FDE's first row was canonical (§4.3) — otherwise there's no
"should be `CFA-8`" to check, and one review says so instead.

**Indirect tail calls.** An unresolved indirect jump (`jmp *%rax`) that doesn't resolve to a
switch table (§4.3/§4.4/§6) is ordinarily a named `REVIEW`. But if the state already looks like a
clean exit (rsp at `CFA-8`, every callee-saved register at entry value — `IsExitState`), it's
blessed instead, on the theory that this is a virtual/function-pointer tail call whose target is
somebody else's FDE, checked on its own. Heuristic, not proof — a dispatcher that hasn't touched
the stack yet could have this shape at a genuine jump-table dispatch — but
`--report_coverage_gaps` (on by default) still surfaces unreached bytes as a `REVIEW`, so this
degrades to a vaguer diagnostic rather than a silent wrong `BLESSED`, unless that flag is off.

### 4.7 Symbolization

Names from `.symtab`, or `.dynsym` if absent, always work. Source lines come from one batched
`addr2line` run over every address about to be printed. `auto` mode enables addr2line when the
binary has `.debug_line` **or** `.gnu_debuglink` — a stripped system library has only the latter,
which is how a libc finding gets reported against a real source line. addr2line's `-f` name is
only trusted when a source line came with it — with no debug info at all it still answers `-f` by
naming the nearest preceding dynamic symbol regardless of distance, so a bare name alone is not to
be trusted.

### 4.8 Structural checks

Before any disassembly, in `unwind-check.cc`: `.eh_frame` must exist; each FDE range must be
non-empty and inside one executable PT_LOAD; ranges must not overlap. Nothing else available
reports any of this.

Poor-man's PLT handling in the same pass: `ELFImage::InPLT` records the vaddr range of every
section named `.plt*`; an FDE falling entirely inside one is skipped and reported blessed without
reaching `FDEChecker` — linker-generated stubs, not compiler output worth second-guessing. A plain
`jmp` *into* a PLT stub from ordinary code still goes through the regular tail-call check.

**Symbols with no FDE at all.** Everything above assumes an FDE exists to be checked; nothing so
far catches the case where one never was declared, which is exactly the silence the contract in
§1 rules out. `coverage-check.{h,cc}` (`CheckUncoveredSymbols`, `--report_uncovered_symbols`,
default on) merges every FDE's `[pc_begin, pc_end)` and walks `ELFImage::func_symbols()` looking
for a symbol in executable memory (skipping `.plt*`, per `InPLT` above) whose range isn't fully
covered. Any gap is a `REVIEW` naming how many bytes are uncovered — typically hand-written
assembly that never got a `.cfi_startproc`/`.cfi_endproc` pair, e.g. glibc's `__clone` trampoline
(`sysdeps/unix/sysv/linux/x86_64/clone.S`), found this way on a stock `libc.so.6`. One finding per
distinct start address, since the report resolves the printed name from `Symbolizer::Name`, not
from anything this check stores — two aliases at the same address would otherwise repeat an
identical line. Unlike `--report_coverage_gaps` (bytes *inside* a declared FDE the walk never
reached), this is bytes with no FDE to walk in the first place.

### 4.9 The light checker

`light-checker.{h,cc}` (`LightCheck`) is a second, much smaller checker, selected by default
(`--full` switches to `FDEChecker`). Switch-table REVIEWs and `FallThroughIsReal` mis-guesses
drove most of the remaining review/false-mismatch count; rather than tighten those heuristics
further, this sidesteps the machinery entirely — no worklist, no dataflow, no switch-table
resolution, no LSDA.

**The idea: reseed completely fresh at every instruction, and give up on the rest of the FDE the
moment the CFA can no longer be confirmed**, rather than carry state carefully enough to tell a
real bug from an artifact. At every stack-affecting instruction: does `SeedFromRow` (off the row
governing *that* instruction, through one `Transfer`) agree with the CFA rule at the next
instruction (or, for an unconditional `jmp`, the target row — possibly a different FDE via
`all_cfis`, same lookup as §4.6)? Concretely known and disagreeing → real `MISMATCH`. CFA rule
unevaluable, or its register gone untracked → one `REVIEW` explaining why, and stop checking the
rest of this FDE (`CheckCFA`'s `bool` return). Decoding always continues in address order
regardless — which is what still lets a switch-case body or landing pad get decoded without
resolving the dispatch that reaches it; only *checking* stops. A call's own fall-through
transition is exempt from the check entirely — `Transfer` never moves rsp across a call, so
comparing rows before/after it is "do two blocks' rows happen to agree," not "does this
instruction match its CFI," and a noreturn call followed by an unrelated fragment's fresh prologue
is exactly the case where they need not.

**Two narrow carve-outs on top of "give up":**

* Once CFA anchor is rbp, `SeedFromRow` unconditionally sets rsp untracked for every instruction
  under that row (DWARF genuinely doesn't say where rsp is once it stops being the CFA register).
  That makes the transition back out of an rbp frame (`pop %rbp` alone, or `leave`) a guaranteed
  give-up under the plain rule, on essentially every frame-pointer function. `leave` actually
  derives rsp correctly on its own; bare `pop %rbp` doesn't (`POP`'s `Transfer` only updates rsp
  if rsp is already `kCFARel`, never true here). So `LightCheck` special-cases exactly this
  transition (`row->cfa == RegOffset(rbp,16) && next_row->cfa == RegOffset(rsp,8)`): silently
  blessed for `pop %rbp` or `leave`, a `REVIEW` (a shape mismatch, not lost tracking) otherwise.
* A `nop` is silently skipped — sometimes where a compiler places what's really the previous
  `ret`'s effect becoming visible in the row table, a placement quirk rather than a provable bug.

**Scope is deliberately narrow: only the CFA rule is checked.** No callee-saved-at-`ret`
convention, no ABI tail-call fallback (§4.6), no `check_unmentioned_callee_saved`, no
saved-register-slot verification. A positional check of *which* register a `push`/store wrote —
matching what the CFI newly attributes to that offset — was tried and removed: compilers routinely
group the CFI updates announcing a save well after the instruction that performed it, so verifying
it needs remembering state across a whole prologue, i.e. dataflow, the exact complexity this
design avoids. Across the 400-binary sweep it never caught a real bug (its one real-code firing
was itself a false positive), so nothing was lost by dropping it. `Verdict::kReviewLight` is never
produced here (no guessing recovery attempted, §6); `Verdict::kReview` covers an unevaluable CFA
rule (`DW_CFA_def_cfa_expression` — DRAP, hand-realigned openssl asm — or none stated) and a
CFA-defining register gone untracked.

**Known accepted false positive:** `libffi.so.6.0.4`'s hand-written `ffi_closure_unix64`
trampoline ends its dispatch with `jmp %r10` (correctly unchecked) immediately followed, in the
same FDE, by jump-table data rather than padding. Decode always continues in address order (needed
so switch-case bodies still get decoded), walks into that data, and some of it disassembles as a
plausible `pop %rsi` that disagrees with the still-correct governing row. A real fix — stopping
decode at any non-fallthrough instruction — would also blind this checker to switch-case bodies
reached only by a jump, so it's left alone for one trampoline in 400 binaries.

## 5. Where it stands

Numbers drift with toolchain versions; treat the shape, not exact digits, as durable. Most FDEs on
a typical Debian sid system are `BLESSED`. Known exceptions: LLVM-compiled code (2 known issues to
file), OCaml native code mismatches, hand-written asm that declares an FDE but never updates CFI,
and some full-checker false positives from noreturn-call misrecognition cascading into
tracked-value disagreements. Switch-table bound discovery is still the main gap; also common is
`REVIEW` noise from unreached instructions where an incoming path into a `.cold` fragment wasn't
registered.

**Two traps when comparing two sweep runs** (both plausible-looking, not an obvious failure):

* `robustness-sweep.rb` resolves `./bazel-bin/unwind-check` on every invocation — a `bazel test`
  in another window mid-sweep silently swaps in the dbg build (§2). Copy the opt binary somewhere
  stable and pass `BIN=`.
* The 400-binary sample is a seeded shuffle (`SWEEP_SEED`, default 0) of whatever
  `candidate_binaries` globs *at that moment* — installing or removing any package reshuffles the
  whole selection (one `apt install` changed the sampled corpus from 669,554 to 741,775 FDEs
  here). Run both binaries back-to-back; a differing `fdes=` total means you compared different
  corpora, not a result.

## 6. Known gaps and what is next

**Guessing recovery for unbounded jump tables** (full checker only; `fde-checker.{h,cc}`).
`Check()` normally reports a `REVIEW` when an indirect jump's table shape (base, index register,
entry width) is fully resolved but `table_bound == kBoundTop` (§4.3: no compiler-declared guard).
If that was the FDE's *only* point of uncertainty, `CheckWithGuessing` retries once with guessing
enabled: `ProbeJumpTable` reads successive entries straight out of `.rodata`, keeping each one
only if it decodes, lands inside some known FDE, and that FDE's declared row there matches the
state at the jump (the same rule `CheckCrossFDEEdge`, §4.6, applies to a *bounded* table) —
stopping at the first entry that fails. The verdict downgrades to `REVIEW-LIGHT` only when the
retry comes back fully `BLESSED`; any other outcome keeps the original `REVIEW`, since a guess is
only worth reporting when it recovers a clean answer, never as a weaker partial one.

Testing gaps: most structural checks (overlapping ranges, non-executable FDE ranges) have no test —
hard to produce with an assembler, currently only exercised by real binaries. The one exception is
`CheckUncoveredSymbols` (§4.8): a symbol with no FDE is trivial to produce on purpose (just omit
`.cfi_startproc`), so `testdata/fixtures.S`'s `uncovered_no_cfi` and `coverage-check-test.cc` cover
it directly rather than only via real binaries.

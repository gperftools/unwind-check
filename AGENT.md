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
are three verdicts, plus one deliberately weaker shade of `REVIEW`:

* `BLESSED` — every instruction reached was checked and agreed.
* `REVIEW` — nothing looked wrong, but something was beyond what this version
  can analyse. Named explicitly, never silent.
* `REVIEW-LIGHT` — a `REVIEW` whose sole point of uncertainty was one
  table-shaped indirect jump with no compiler-declared bound, which guessing
  then fully recovered (§6, "Guessing recovery for unbounded jump tables").
  Grouped separately in reports and the summary line, still exits non-zero
  like any other review, and never a synonym for
  `BLESSED`: it is only ever reached by falling back to the original
  `REVIEW`'s own findings, downgraded, when a second, independent analysis
  guessing the table's size came back completely clean.
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

**Gotcha: `bazel-bin/unwind-check` is one symlink, not one binary.** It points
at whichever config directory the *most recent* `bazel build`/`bazel test`
invocation touched. Running `bazel build :all` or `bazel test :all` (no
`-c opt`) after a `bazel build -c opt :unwind-check` silently repoints
`bazel-bin/unwind-check` back at the dbg build — the file still runs, just
30-60x slower, which reads exactly like a hang or a real performance
regression on something like `libc.so.6` (measured: a run that takes 3.8s
under opt sat past a 2-minute timeout under the config `bazel test :all` left
behind). If a real binary suddenly looks like it hung after touching the
build, re-run `bazel build -c opt :unwind-check` before concluding anything
about the code — it re-points the symlink even when nothing needed
recompiling, and costs nothing to run defensively before any timing-sensitive
check.

* `.bazelversion` pins 9.2.0.
* Disassembly is Zydis, the locally installed `libzydis-dev` (4.1.1 here),
  linked with a bare `-lZydis -lZycore` and the system include path. No bazel
  integration, following the same policy `goal.md` set for its predecessor.
  Started as Capstone; switched to Zydis because Capstone has real gaps on
  x86 (the TODO's "11 cannot decode the instruction at this address in
  libcrypto" was one symptom). The formatter is pinned to
  `ZYDIS_FORMATTER_STYLE_ATT` for diagnostics -- safely, unlike Capstone,
  where selecting AT&T syntax is known to also reorder the *structured*
  operand array, not just the printed text, silently breaking anything that
  assumes operands[0] is the destination. Zydis's formatter is a separate
  pass over the already-decoded operands, so the style chosen there has no
  effect on what `Transfer()` sees.
* abseil comes from the bazel central registry. Unlike backtrace-test, this tool
  is offline rather than async-signal-safe, so it is free to use exceptions,
  RAII, allocation and abseil, and it does.
* C++20, 2-space, 120 cols, `BasedOnStyle: Google`. Emacs mode line on every
  file; keep them on new ones. Everything is in `namespace unwind_analysis`.

Useful flags: `--verbose` (list blessed FDEs too), `--summary_only`,
`--function=<regex>`, `--pc=<hex>`, `--dump_cfi` (print the decoded row table
instead of checking; compare against `readelf --debug-dump=frames-interp`),
`--addr2line=auto|off|<path>`, `--check_unmentioned_callee_saved`,
`--report_coverage_gaps`, `--inspect` (requires `--pc`; prints a nice
disasm+CFI listing of that FDE instead of the summary report -- see below),
`--inspect_deep` (with `--inspect`, also shows the dataflow's converged
abstract state before each instruction).

`--inspect` doesn't draw its own disassembly or jump arrows: `diagnostics.cc`
serializes the declared CFI rows, findings, and (deep mode) converged state as
JSON and pipes it into `inspect.rb`, which runs `objdump -d
--visualize-jumps` over the same address range and splices our annotations
into objdump's output by address, right before the line each annotation
describes. `objdump` already draws jump-arrow gutters and colorizes
disassembly better than reimplementing that was worth it. `inspect.rb` is a
Bazel `data` dependency of `unwind-check`, located at runtime via the
`@rules_cc//cc/runfiles` library; both it and `subprocess.{h,cc}` (a
`posix_spawn`-based helper used here and by `symbolizer.cc`'s `addr2line`
invocation, argv-array only, no shell) fail loudly rather than degrade
silently -- a missing `ruby`/`objdump`, or objdump output the script doesn't
recognize, is a hard error naming what went wrong.

## 3. Code map

| file | what it holds |
| --- | --- |
| `elf-image.{h,cc}` | opening the ELF and the "fake load" (§4.1); sections, PT_LOADs, symbols |
| `eh-frame-reader.{h,cc}` | copied from backtrace-test, with two deliberate edits (§4.2) |
| `dwarf-constants.h` | copied verbatim from backtrace-test |
| `cfi-table.{h,cc}` | the *declared* side: a visitor turning one FDE into a row table |
| `disasm.{h,cc}` | thin wrapper over a Zydis decoder and AT&T-style formatter |
| `abs-state.{h,cc}` | the two lattices (CFI and switch-table) and their joins (§4.3) |
| `insn-semantics.{h,cc}` | the *computed* side: what each instruction does to the stack (§4.4) |
| `lsda-reader.{h,cc}` | parses `.gcc_except_table`'s call-site table for exception landing pads (§4.5) |
| `fde-checker.{h,cc}` | CFG walk, worklist dataflow, and the comparison (§4.5) |
| `symbolizer.{h,cc}` | symbol names and source lines (§4.7) |
| `subprocess.{h,cc}` | `posix_spawn`-based child-process helper, no shell involved |
| `report.{h,cc}`, `unwind-check.cc` | flags, structural checks, output |
| `diagnostics.{h,cc}`, `inspect.rb` | `--inspect`: gathers CFI rows/findings/state as JSON, pipes into `inspect.rb`, which interleaves them into `objdump --visualize-jumps`'s output |
| `testdata/fixtures.S` | hand-written CFI whose right answer is fixed by the fixture |
| `robustness-sweep.rb` | the non-hermetic counterpart to `bazel test`: does it survive real binaries |

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
`false` when it falls back to seeding a landing pad from its own declared
row (§4.5's fallback path) — the primary path derives a landing pad's state
from the call site that actually reaches it instead of seeding from the row
at all, so this only matters for the rarer fallback.

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

**There are two lattices, and they are separate types.** `AbsVal` is the
CFI lattice: the thing a declared unwind rule is checked against, and the
only thing `Join` reports disagreements about. `TableVal` is everything
that exists solely to resolve PIC switch-table dispatches. They used to be
one struct with seven kinds and two auxiliary bound fields, three of the
kinds being invisible to every CFI rule; splitting them is what let a pile
of special cases be deleted rather than relocated.

`AbsVal` is `kTop`, `kBottom`, `kCFARel(delta)`, `kOrigReg(r)`, `kOther`.
`TableVal` is `kNone`, `kConflict`, `kConst`, `kTableEntry`, `kJumpTarget`,
plus the two bounds. Both have the same top/bottom shape, and for the same
reasons — the identity element must adopt, the give-up state must absorb —
but they are joined by different rules and consulted by different code.

**`kOther` is a third state of knowledge, not a synonym for `kTop`.** It
means "I know what is in this register, and it is definitely not
CFA-relative and not any register's entry value" — a rip-relative `lea`
result, typically. Every `RowChecker` test is `is_unknown() -> review, else
-> mismatch`, so the difference is exactly the difference between *could
not verify* and *verified false*: `lea .LC0(%rip),%rbx` where the CFI says
rbx is untouched is a real CFI bug, while an unmodelled `add %rax,%rbx` is
just us giving up. Before the split this state was carried, accidentally,
by the table kinds themselves — they happened to make `is_unknown()` false.
Moving those out without naming what they were doing would have silently
downgraded that whole class of mismatch to review. `bad_lea_into_callee_saved`
in the fixtures is there to catch exactly that, and it is the only check in
the suite that does.

**The join carve-out is gone, not moved.** `Join` used to need a rule
saying "two switch-table kinds disagreeing is not a reportable conflict",
because two unrelated `.rodata` pointers meeting at a merge arrived as two
different `kConst`s. They now arrive as two `kOther`s, which compare
*equal*, so there is nothing to report and nothing to suppress. What is
left is one rule with no exceptions: two CFI values that each name
something, and name different things, go to `kBottom` and get reported.

`TableVal`'s join reports nothing at all, because nothing in it is a CFI
claim. Identity is adopt-from-`kNone`, keep-if-equal, else `kConflict`.
Both bounds join by `max`, which is the only thing an upper bound can join
by: two paths proving `<= 4` and `<= 7` leave `<= 7` standing, and
`kBoundTop` being max's identity is what makes an unbounded path wipe out
the other path's bound with no special case. Identity and bounds are
settled separately so that giving up on one cannot silently keep the other.

Keeping `kNone` and `kConflict` apart is load-bearing in both directions,
and getting it wrong is easy: collapsing them into one "nothing here" state
makes a predecessor that knows nothing *destroy* a resolved dispatch
instead of being absorbed by it, which loses real switch tables (`/bin/ls`'s
main dispatch, immediately). Collapsing the other way — letting a
disagreement land on the identity element — lets a third predecessor
resurrect a concrete answer after two paths already disagreed.

**The bounds live on `TableVal`.** `value_bound` is everything provable
about the number, from any source: a zero-extending widen (`movzbl %al,%ecx`
proves at most 255), the bare fact that an instruction wrote a 32-bit
register (every such write zero-extends on x86-64), or a guard. Its job is
proving widths. `table_bound` is the subset established by a
`cmp $imm,%r; ja default` guard and nothing else — a bound the *compiler*
declared — and only it may size a switch table. A width fact is honest but
useless as a table size (`movzbl` proving an index is at most 255 would
resolve a 256-entry table out of whatever `.rodata` follows the real one),
and a wrong table size sends the walk to wrong targets. The split also
keeps `table_bound == kBoundTop` a meaningful "no compiler-declared bound"
predicate, which is what routes an unbounded dispatch to guessing recovery
(§6) rather than silently resolving it.

**Both halves of a register always move together.** `AbsState::SetReg`
clears the table half rather than leaving it alone, so a register that just
got a new value can never keep a stale table identity or a bound describing
what used to be there — the mistake this split would otherwise make easy to
write by accident. `SetTableReg` sets a table value and stamps `kOther` on
the CFI side, since a `.rodata` pointer is precisely "definitely not an
entry value". `CopyReg` carries both, for the one case that must: a
full-width register-to-register move, where a value keeps its identity
*and* its bounds.

**Slots hold CFI values only.** A table base or index that gets spilled and
reloaded loses its table identity. This is deliberate, not an oversight:
the 400-binary sweep shows it costs nothing measurable, and it spares a
second slot map and a second join. It also dissolves a bug the old design
had to handle explicitly — a spilled switch scratch value used to produce a
spurious conflict, which is why the carve-out had to be generalised from
registers to slots; two spilled table values are now both `kOther`, so they
simply agree.

**A comparison is not a bound; a branch is.** This is the part that was
wrong for a long time and is worth stating flatly. `cmp $imm,%reg` sets
flags and establishes nothing whatsoever; `InsnSemantics::Transfer`'s
`ZYDIS_MNEMONIC_CMP` case only *records* it in `AbsState::last_cmp`. Deriving a
bound at the `cmp` — which an earlier version did, to rescue narrow
compares — invents one on the default edge of a switch, or with no branch
at all. The single place a comparison becomes a fact is
`InsnSemantics::TransferEdge`, on the one branch edge where the value is in
range: the fall-through for `ja`/`jae`, which branch *away* from the table,
and the taken edge for `jbe`/`jb`, which branch *into* it.

`TransferEdge` is a second entry point alongside `Transfer`, and the split
is the point: `Transfer` says what an instruction does on *every* path out
of it, `TransferEdge` what one particular successor additionally proves. A
conditional branch produces two different successor states and
`TransferOutcome` has no way to express that, so the walker makes its own
per-edge copy and calls `TransferEdge` on it. It must not be folded into
`Transfer`, which runs before the walk knows which successor it is
building. Keeping it here rather than in the walker is what leaves
`fde-checker.cc` with exactly one Zydis mnemonic reference (padding
detection); deciding *which edge means what* is instruction semantics,
while deciding *which edges exist and where they go* is the walk.

`last_cmp` is invalidated by two independent things, and both are needed:
any later EFLAGS write, handled once up front in `Transfer`; and any later
write to the compared register, handled in `AbsState::SetReg`/`ClobberReg`
— the only two places a register's value changes, which is what makes them
the choke point. Without the second, `cmp $5,%eax; mov (%rbx),%rax; ja
default` bounds whatever landed in rax rather than what was compared.
(`Join` writes `gpr[]` directly and bypasses both, on purpose: it does its
own `last_cmp` merge, equal-preserving-else-clear.)

**A guard has two lives, and `FlagsGuard::proven_bound` says which one it
is living.** Before a branch it is inert and that field is `kBoundTop`.
After a branch has selected the in-range edge it holds the bound
established there, and the record is a fact about a value — *the low
`width_bits` bits of `reg` are at most `proven_bound`* — which from then on
survives EFLAGS writes, because flags have nothing to do with it any more;
only a write to `reg` retires it.

The comparison's own operand stays in a separate `imm` field and is never
rewritten. The two cannot share one field: at `cmp` time the bound is not
yet computable, since `ja`/`jbe` split at `reg <= imm` while `jae`/`jb`
split at `reg < imm`, and which applies depends on a branch not yet seen.
So the record genuinely starts as an operand and gains a bound later;
keeping them apart is what stops either from having to mean both, and
leaves the diagnostics able to say what a bound was derived from.

That width qualification is the whole point, and it is what an earlier cut
of this got backwards. `cmp $0xe,%esi` on an argument register says nothing
about `rsi`, whose upper half the psABI leaves undefined — but everything
about the `mov %esi,%eax` two instructions later that reads exactly those
32 bits and zero-extends them. So there are two ways a guard becomes a
bound, and both are needed:

1. **Promotion at the branch**, when `value_bound` already proves the
   register no wider than what was compared (`value_bound <=
   WidthBound(width)`), or the compare was 64-bit. Then it is a fact about
   all 64 bits immediately.
2. **Collection at a widen**, otherwise. The proven guard rides along until
   a zero- or sign-extending read of at most `width_bits` bits picks it up
   (`ProvenGuardBound` in `insn-semantics.cc`), and *that* is what makes it
   a full-register fact — the widen's own zero-extension is the proof.
   Reading more bits than the guard covered does not qualify.

Both happen: the promotion path does not retire the guard. It cannot,
because promotion is a decision about the *state*, and the state can weaken
between visits as more predecessors arrive. Recording the fact in one place
on the visit that promoted and another on the visit that could not would
lose it entirely at the join, since `Join` never lets an absent `last_cmp`
adopt a present one. `libstdc++`'s `basic_stringstream` dispatch is exactly
this case and regressed to `REVIEW` until the guard was kept on both paths.
Re-application is prevented by `TransferEdge` acting only on a guard that
has no `proven_bound` yet, not by retiring it.

The switch-table guard used to be found by a 64-hop backward byte-walk on
demand (`FindGuardBound`, since deleted), independent of the joined lattice
and therefore with no protection against exactly the resurrection bug
above, plus real cost: worklist dedup (below) made it merely wasteful
rather than pathological, but it still re-derived the same answer on every
reprocessing of a `ja`/`jae`. Tracking it forward as `last_cmp` removes the
byte-walk, the hop cap, and the `fallthrough_pred` bookkeeping entirely,
and gets the dominance property for free: a `ja`/`jae` reachable from a
bypassing predecessor that never ran the `cmp` sees `last_cmp` cleared by
the same `Join` that clears everything else on disagreement, rather than a
structural search that had no way to know the point it was searching
backward from had more than one real predecessor.

### 4.4 Instruction semantics

Modelled precisely: `push`/`pop`, `add`/`sub`/`and`/`lea` on rsp/rbp, `mov` to
and from `[rsp+off]` / `[rbp+off]`, `mov reg,reg`, `movzx reg,reg`, `leave`,
`call`, `ret`, `jmp`, `jcc`, `cmp $imm,%reg` (only for the `AbsState::last_cmp`
switch-table guard fact, §4.3 — cmp writes no register or memory). That is
close to the same small set objtool, LLVM's `CFIInstrInserter` and Binary
Ninja's stack tracker each special-case; nobody lifts all of x86-64 for this
question.

A destination's *identity* survives only a full-width move, but its numeric
bounds (§4.3, on the TableVal half) survive any write that covers the whole
64-bit register --
64-bit explicitly, or 32-bit because x86-64 zero-extends those. That is
`mov %esi,%eax`, `movzbl %al,%ecx`, `movsbl`, `movslq`: GCC routinely
widens a guarded switch index into whatever register the table load
actually reads, so carrying the bounds across is what lets the guard and
the table load disagree on register without losing the guard. An 8- or
16-bit destination carries nothing, because `mov %sil,%al` leaves bits
8..63 of rax alone however tightly bounded `%sil` was. Sign-extending
forms carry only when `value_bound` proves the source's sign bit clear, so
that sign- and zero-extension agree.

The source and the guard are read *before* the destination is clobbered:
`movzbl %al,%eax` is the commonest spelling of the widen and reads the
register it also writes.

Everything else goes through Zydis's per-operand read/write accounting and
drops the registers it writes to unknown. An unmodelled instruction therefore
costs precision, never correctness — including `and $-16,%rsp`, which needs no
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

**Exception landing pads.** Nothing in a function body branches to a landing
pad directly — it's reached only through the unwinder, via the LSDA — so the
walk above would never find one on its own. `lsda-reader.{h,cc}` parses
`.gcc_except_table`'s call-site table (`ReadLSDACallSites`) into `[start, end)
→ landing_pad` ranges; whenever the forward dataflow processes a `call`
instruction whose PC falls in one of those ranges, `Check()` treats
the landing pad as a real edge and propagates the *actual computed state
right after that call* — callee-saved and CFA preserved, caller-saved
clobbered, the same transfer function already used for the call's own
fall-through edge, since that's exactly what the unwinder would restore
before jumping to the pad. This is strictly more precise than an earlier
version that seeded each pad by trusting its own declared CFI row outright:
the state now comes from code actually walked, so it doubles as a real
cross-check that the row agrees with it — a stale CFI specific to the
exceptional edge is now a genuine `MISMATCH` opportunity, not
definitionally unobservable. That row-trusting seed survives only as a
fallback, for a landing pad no call site's range happened to resolve to (an
unusual encoding, or a call left unreached for an unrelated reason) — used
rarely, and flagged with its own `REVIEW` when it fires, so it's visibly the
weaker path rather than silently indistinguishable from a verified one.

Wiring a landing pad in as a real edge means one call site can, in
principle, feed many different landing pads and one landing pad can be fed
by many call sites (a shared cleanup block in exception-heavy C++ is
exactly this shape) — ordinary multi-predecessor `Join`, nothing special.
What *did* need a real fix: without deduplicating the worklist, several
predecessors each detecting a change before their shared target is dequeued
produced duplicate pops that redid decode/`Transfer` work for no new
information, since the state read out of `in_states` is already fully
joined by the time any of the duplicate pops run. `propagate`'s
`pending_pushes` map exists for exactly this — at most one entry per pc
sits in the worklist at a time — and mattered in practice: a landing pad
with high call-site fan-in in real C++ (`lib2geom.so.1.4.0`,
`zutty`) turned sub-second FDEs into 15-50 second ones before the fix.
(A tempting-looking alternative — batch every call site's contribution to a
landing pad locally and flush it to the worklist only once, rather than
deduplicating pushes — was tried first and made no measurable difference;
the actual cost was the duplicate *pops*, not redundant re-walks of the
pad's own body, so batching the flush didn't address it. Worklist dedup
did, and is the simpler fix besides.)

### 4.6 Exit-state validation

Everything above checks the declared CFI against the code within one FDE.
This section is about the edge itself: what happens when an *unconditional*
direct jump, or a resolved switch-table entry, leaves `[pc_begin, pc_end)`.
(Conditional jumps out of the FDE, `jne .Lcold`, are left alone — a taken
branch out is normal control flow this tool was never trying to follow.)

**The primary path: check against the target's own declared row.**
`check_cross_fde_edge` (in `fde-checker.cc`, inside `Check()`) looks
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

**Indirect tail calls.** An unresolved indirect jump (`jmp *%rax`) — one that
doesn't resolve to a switch table (§4.3, §4.4, §6) — is ordinarily a named
`REVIEW`. But if the
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
| `libstdc++.so.6` | 5332 | 5149 | 183 | 0 |
| `/usr/bin/gcc` | 2448 | 2295 | 152 | 1 |
| a `-static` hello world | 1090 | 1055 | 32 | 3 |

This table predates guessing recovery (§6): on current binaries some of each
`review` column now further splits into `review-light`, e.g. `/usr/bin/gcc`
currently reports 2294 blessed, 3 review-light, 150 review, 1 mismatch —
still 2448 total, just a few of the old reviews now guessed clean. Shape,
not exact digits, applies here too.

The Capstone-to-Zydis migration was validated by A/B-diffing both decoders'
output, on the same machine, over this table's binaries plus the 400-binary
`robustness-sweep.rb` sample: identical verdict counts everywhere except one
FDE in `libstdc++.so.6` (`std::from_chars`'s internals), which moved from
blessed to review. Traced by hand: a local scratch buffer's stack slot
genuinely overlaps a callee-saved spill slot the CFI still declares live at
that PC, on one code path — Zydis's decode is not in question, the finding
is real, and REVIEW (not MISMATCH) is the correct, conservative verdict for
it. Whether Capstone missed this from a decode gap or some other imprecision
was not tracked down. `libaom.so.3`, the one binary in the sweep sample over
robustness-sweep.rb's 5-second slow-flag threshold, is very slightly faster
under Zydis (~5.7s vs ~6.6s under Capstone) rather than slower.

Review counts here are much lower than earlier versions of this tool. Two
things did most of it: §4.6's cross-FDE check resolves the majority of what
used to be an unavoidable REVIEW at every `.cold`-fragment tail call and
every switch-table case shared across FDEs, verifying them against the
target's own declared row instead; and, on top of that, exception landing
pads (§4.5) and switch-table resolution (§4.3, §4.4) closed most of what was
`libstdc++.so.6`'s outlier-sized review count — it went from 501 reviews to
183 once landing pads stopped being an unchecked coverage gap by name.

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
`/usr/lib/x86_64-linux-gnu` — 741,775 FDEs, 710,014 blessed, 424 mismatches
— there were **zero** crashes and zero abnormal exits. Reproduce with
`./robustness-sweep.rb`; anything it prints as ABNORMAL is a bug in this
tool. A handful of large binaries (`libLLVM-17.so.1`,
`libwebkit2gtk-4.1.so.0.21.10`) take 30-40s, which the sweep reports
separately rather than treating as a failure. Those numbers are about 16%
higher than they were before the two-bound rework (§4.3) -- the extra
per-write bound bookkeeping and the two additional max-joins per register
and slot. That is a known, accepted cost, not a regression to bisect for.

**Two traps when comparing two sweep runs**, both of which produce
plausible-looking nonsense rather than an obvious failure:

* `robustness-sweep.rb` resolves `./bazel-bin/unwind-check` on every
  invocation, so a `bazel test` in another window mid-sweep silently swaps
  it for the dbg build (§2). Copy each opt binary somewhere stable and pass
  it via `BIN=`.
* The 400-binary sample is a seeded shuffle (`SWEEP_SEED`, default 0) of
  whatever `candidate_binaries` globs *at that moment*, so installing or
  removing any package in `/usr/bin` or `/usr/lib/x86_64-linux-gnu`
  reshuffles the entire selection -- a single `apt install` between two
  runs changed the sampled corpus from 669,554 FDEs to 741,775 here, which
  looks exactly like a huge behaviour change. Run both binaries
  back-to-back, and treat a differing `fdes=` total as proof you compared
  different corpora rather than as a result.

The two-bound rework (§4.3) removed a whole class of **false** mismatches
along with the fabricated bounds that caused them: a bound invented from a
bare `cmp` over-sized a switch table, the walk ran past the real table into
the next thing in `.rodata`, and those junk "targets" were then accused of
contradicting their own FDEs' CFI. Thirteen of these disappeared from
`libwebkit2gtk` alone, all of them turning into `REVIEW-LIGHT`; mismatch
counts on the other 63 binaries with any mismatch at all were byte-identical
before and after. Wrongly accusing a compiler of a CFI bug is the worst
output this tool can produce, so that is the single most valuable thing that
change bought.

Remaining reviews are dominated by indirect jumps that don't resolve to a
switch table at all (data-driven dispatch, a table shape §4.4's rules don't
recognise, or a genuinely unbounded dispatch with no guard), a landing pad
whose call site couldn't be matched and so fell back to trusting its own row
(§4.5), and jump-out edges whose target has no covering FDE, which still
fall back to the ABI-based tail-call heuristic (§4.6).

## 6. Known gaps and what is next

In rough order of value. Most of these remain deliberately out of scope;
jump tables are the exception — implemented, with one traced-but-unresolved
correctness question called out below rather than left silent.

* **Jump tables are resolved** (§4.3, §4.4: `AbsVal::table_bound`/`last_cmp`
  track the `cmp $imm,%r; ja default` guard, `insn-semantics.cc`'s `movslq`/`add` rules
  turn that plus a PIC table-base `lea` into a `kJumpTarget`, and
  `ResolveJumpTable`/`kMaxJumpTableEntries` reads and bounds the table itself)
  — this used to be out of scope; it no longer is. An indirect jump is still a
  named `REVIEW` when it can't be resolved this way, unless the state at that
  point already looks like a clean function exit, in which case it's blessed
  as a probable indirect tail call instead (§4.6). A table entry landing
  outside the FDE (typically a shared `.cold` case) is checked against
  whatever FDE covers it (§4.6) rather than just noted as unfollowed.
  **What's still a real gap:** whether a jump table gets resolved *at all* is
  decided from `AbsVal::table_bound` as it stands *during* pass-1 dataflow,
  not from its fully-settled fixed-point value — unlike every other edge in
  the walk, which is purely structural (never state-dependent) and so
  trivially reprocessed with the latest state on every visit. A merge point
  with genuinely disagreeing guards (two different dispatches sharing one
  table, from different bounds) can, depending on visitation order, have
  some of its targets resolved-and-walked using a not-yet-final snapshot of
  the state. Note this is *not* limited to "the fields around the bound":
  the bound itself is a max-join over an auxiliary lattice, so it too only
  widens toward its fixed point, and a snapshot taken early is tighter than
  the final answer. What keeps that from being a soundness hole is that a
  too-tight bound resolves *fewer* table entries, and the entries not
  walked show up as an unreached-code `REVIEW` in pass 2 — provided they
  land inside this FDE. Pass 2 also always re-derives `has_jump_table` from
  the truly-final state, so the top-level "is this dispatch flagged"
  verdict is order-independent. Believed low-risk and traced at length, but
  not proven safe, and deliberately not fixed this round: the fix is to
  make edge-assertion itself a monotone, order-independent function of the
  accumulating state (e.g. a running union of every valid piece of
  evidence, rather than a snapshot re-evaluation), not a scheduling change
  — a two-phase "settle everything else, then resolve tables" ordering does
  not work, because a table's own targets (and exception landing pads) can
  reveal code relevant to *other*, not-yet-resolved dispatches' bounds.
* **Guessing recovery for unbounded jump tables** (`fde-checker.{h,cc}`:
  `CheckWithGuessing`, `ProbeJumpTable`, `RowMatchesCleanly`). The bullet above
  covers a table whose `cmp $imm,%r; ja default` guard was found; this one
  is for an indirect jump whose `kJumpTarget` shape is otherwise fully
  resolved (table base, index register, entry width) but which never had a
  compiler-declared bound captured at all — `insn-semantics.cc`'s `Transfer` now marks that
  case `has_unbounded_jump_target` instead of folding it into the generic
  "unresolved indirect jump" `REVIEW`.

  A normal `Check()` run still reports that `REVIEW` (findings are what a
  human reads), but also counts how many such jumps it saw in
  `FDEResult::guessable_jump_pc` — populated only when there was **exactly
  one**, on the theory that guessing across several independent
  uncertainties in one FDE compounds risk for no proportionate gain.
  `CheckWithGuessing`, the entry point `unwind-check.cc` and `--inspect`
  actually call, checks that field and, when set, runs a **second,
  independent `Check()`** with `guessing_enabled = true`. That run reaches
  the same jump and, instead of giving up, calls `ProbeJumpTable`: index 0
  is always worth trying (a known-good table base's first entry), and each
  subsequent index is trusted only as long as it keeps decoding to a real
  instruction landing inside some FDE *and* the actual declared CFI row at that
  target (this FDE's own row if the target lands inside it, otherwise
  whichever FDE covers it, exactly the in-FDE/cross-FDE split §4.6 already
  uses for a real resolved table) checked against the state the jump
  carries, via `RowMatchesCleanly` — a dry run of the same `RowChecker`
  logic into a scratch sink, so a candidate that will not check out cleanly
  never pollutes the real report before the guess decides to stop trusting
  it. The probe stops at the first index that fails either test, or at
  `kMaxJumpTableEntries`, whichever comes first, and the recovered entries
  then get walked and verified exactly like any other resolved dispatch.

  `CheckWithGuessing` accepts this second run's result only when it comes
  back **fully `BLESSED`** — any remaining finding, guessed-table-related
  or not, means the original `REVIEW` is returned untouched, findings and
  all. On success, the original result's verdict becomes `REVIEW-LIGHT`
  and its findings are kept as-is (so a human still sees exactly why the
  FDE was flagged), with the retry's `guessed_jump_tables` (the guessed
  entry count and every resolved target address) attached for the report
  and `--inspect` to show.

  **This is a guess, not a proof**, and deliberately reported as one:
  nothing in the acceptance test can distinguish "still inside the real
  table" from "wandered into a second table placed immediately after it in
  `.rodata`" — a real risk, since back-to-back switch tables are common and
  a neighboring table's entries are, by construction, also valid-looking
  code addresses. Checking each candidate's CFI compatibility during the
  probe (rather than only structural decode-and-lands-in-FDE, which was
  this feature's first cut) tightens the boundary a lot in practice — a
  genuinely different dispatch's targets are checked against *this* jump's
  live register state, which usually will not match — but it is still a
  heuristic acceptance test, not a guarantee, which is exactly why a
  successful guess downgrades to `REVIEW-LIGHT` rather than `BLESSED`
  outright, and why `REVIEW-LIGHT` keeps the original findings visible
  rather than presenting as a clean pass.
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

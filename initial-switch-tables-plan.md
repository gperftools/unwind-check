# Switch tables: plan for the PIC/PIE case

Scope: resolve compiler-generated switch jump tables in position-independent
code (PIE executables and `.so`s), so that the code they reach gets walked and
checked instead of being reported as `REVIEW`. Non-PIC absolute-pointer tables
are explicitly **not** in this plan; see §7.

Everything below was measured on real binaries with the tool as of commit
`76a1f7e` plus offline scripts. Numbers are reproducible, see §8.

## 1. Why this is worth doing

Current tool, run with `--report_coverage_gaps`:

| binary | FDEs | blessed | review | review FDEs naming an unresolved indirect jump |
| --- | --- | --- | --- | --- |
| `speedtest1` (PIE, clang) | 1634 | 1570 | 62 | **61** |
| `libc.so.6` | 3919 | 3760 | 156 | 32 |
| `libstdc++.so.6` | 5332 | 4527 | 805 | 48 |
| `libcrypto.so.3` | 13337 | 13066 | 264 | 145 |
| `/bin/ls` | 341 | 327 | 13 | 8 |

For `sqlite`'s `speedtest1`, **61 of the 62 reviews are jump tables** — the 62nd
is a genuine CFA finding. For `libcrypto` it is roughly half. The two review
reasons always travel together: an FDE gets `unresolved indirect jump` at the
`jmp`, and then `N bytes from here were not reached by the control-flow walk`
for each unreached case body.

`libstdc++` is *not* jump-table-bound and will barely move: its 805 reviews are
dominated by 389 `cannot say what is stored there` and 323 `unconditional jump
out of FDE`. Those are separate problems; do not judge this work by libstdc++.

## 2. There is exactly one PIC pattern

1299 register-indirect jumps across four PIC/PIE binaries, built by both clang
and GCC, produced exactly one switch-table shape:

```
    lea    TBL(%rip), %B          ; B = &table          -- may be in an earlier block
    cmp    $N, %I                 ; I = index
    ja     default                ; terminator of the block that dominates the lookup
    ...                           ; unrelated instructions may sit between cmp and ja
    movslq disp(%B,%I,4), %T      ; T = sign-extended int32 table[I]
    add    %B, %T                 ; T = &table + offset
    [notrack] jmp *%T
```

Breakdown of `jmp *%reg` sites:

| | sqlite | libstdc++ | libc | libcrypto |
| --- | --- | --- | --- | --- |
| indirect tail call / vtable (no `add %B,%T`) | 26 | 201 | 182 | 386 |
| pattern matched **and** bounded → resolvable | **82** | **52** | **72** | **151** |
| pattern matched, no bound found | 5 | 29 | 28 | 51 |
| other | 2 | 2 | 28 | 2 |

Two things follow from the first row. The *majority* of register-indirect jumps
are indirect tail calls and vtable dispatches, which `FDEChecker`'s existing
`IsExitState` path already blesses — the TODO item "one type of indirect jumps:
jmp-ing via c++ vtable ... detect is state compatible with tail-call" is
effectively already done. And a site that has no `add %B,%T` before it is not a
switch table; do not try to make it one.

Table sizes observed: 1 to 160 entries. Always in `.rodata`.

## 3. Design

### 3.1 Add a constant kind to the lattice (`abs-state.h`)

About 20% of table bases are `lea`'d in a **different basic block** from the
`movslq` that uses them — sqlite's `sqlite3VdbeExec` loads the base once outside
its 187-way dispatch loop. A purely local backward scan therefore has to walk the
CFG anyway, which is work the existing worklist already does. So put the value in
the lattice:

Add to `AbsVal::Kind`:

* `kConst` — a known absolute address/constant, in `delta`.
* `kTableEntry` — the result of a table load: `table` base address and the DWARF
  register number of the index.
* `kJumpTarget` — a resolved `table + table[index]`: carries `table` and index reg.

`kTableEntry` and `kJumpTarget` need two fields beyond what `AbsVal` has today
(table address and index register); either widen `AbsVal` or keep a small side
table in `AbsState` keyed by register. Widening is simpler and `AbsVal` is not
hot.

Transfer rules to add in `InsnSemantics::Transfer` (`insn-semantics.cc`):

* `lea disp(%rip),%B` → `B = kConst(next_pc + disp)`.
* `mov $imm,%r` (64-bit imm or zero-extended 32-bit) → `r = kConst(imm)`.
  Optional; not needed for PIC but free.
* `movslq disp(%B,%I,4),%T` where `B` is `kConst(c)` and scale is 4 →
  `T = kTableEntry{table = c + disp, index = I}`.
* `add %B,%T` (either operand order) where `B` is `kConst(c)` and `T` is
  `kTableEntry{table, index}` with `table` derived from that same `c` →
  `T = kJumpTarget{table, index}`.
* Everything else clobbers as it does today.

Doing this in the lattice rather than by backward pattern-scan buys operand-order
independence, tolerance of intervening instructions (sqlite has
`mov %r9d,0xc(%rsp)` between the `add` and the `jmp`), and cross-block bases, all
for free. Capstone reports `mem.base`, `mem.index` and `mem.scale` separately, so
there is no base/index ambiguity to disentangle — unlike parsing AT&T text.

**`Join` must not report a disagreement between two of the new kinds.** This is
a narrow guard, and it is worth being precise about its scope: it applies only
when *both* sides are `kConst`/`kTableEntry`/`kJumpTarget` and they differ. Meets
involving `kCFARel` or `kOrigReg` on either side are untouched, and so are
`kTop`/`kBottom`, which keep their existing identity and absorbing behaviour.
In the one case being carved out, the result is `kTop` and **no** `JoinConflict`
is recorded.

The justification is about what the report claims, not about noise. `Join`
records a conflict (`abs-state.cc:148`) and `FDEChecker` turns it into a review
on the premise, written at `fde-checker.cc:612`, that `.eh_frame` declares one
state per PC, so two edges arriving with different values means one of them
contradicts the row. That holds for values a CFI row can assert. No CFI row
asserts anything about a `.rodata` pointer sitting in a scratch register, so
such a report would be a false accusation with a confusing message, about a
fact the checker only tracks as an implementation detail of jump-table
resolution.

Do not expect this to change any counts. `RowDependsOn` only fires for a
register conflict on a `kSameValue`, `kValOffset` or `kInRegister` rule, or when
the CFA is based on that register — and measured against
`readelf --debug-dump=frames-interp`, `same_value` occurs **zero** times in
speedtest1, libstdc++ and libc, and `kInRegister` 19 times in all of libc.
`kAtCFAOffset`, the rule a spilled callee-saved register actually gets,
deliberately does not make `RowDependsOn` fire for a register conflict, because
it names a stack slot rather than the register's live contents. The CFA-base
case cannot arise either: a register the CFA is based on holds `kCFARel`, never
`kConst`. So this is a one-line guard against a bad report that would otherwise
be rare rather than a fix for observed noise — implement it, but do not go
looking for a review count to drop.

Add a case to `abs-state-test.cc` pinning that two differing constants meet to
`kTop` and record no conflict, and that a constant meeting a `kCFARel` still
conflicts as it does today.

### 3.2 One assume-edge for the bound (`fde-checker.cc`)

The index bound is the only thing the value lattice cannot supply, and it is
the thing that makes the whole scheme safe (§4). Add a single edge-sensitive
fact:

* Track a per-register unsigned upper bound in `AbsState` (a small
  `std::map<int, uint64_t>` or a 16-entry array; it does not need to be part of
  `AbsVal`).
* When propagating the **fall-through** edge of `ja`/`jae`/`jnbe`/`jnb`, walk
  back from the branch over instructions that do not write EFLAGS. Capstone's
  `cs_regs_access` / `insn->detail->x86.eflags` makes "does this write flags"
  exact — do not use a mnemonic whitelist. If the flag-setter reaching the
  branch is `cmp $imm,%r`, record `ubound(r) = imm` on that edge (`imm` for
  `ja`/`jnbe`, `imm - 1` for `jae`/`jnb`).
* Preserve the bound across zero-extending moves of the same parent register
  (`movzbl %al,%eax` appears between the `ja` and the `movslq` in every GCC
  table). Drop it on any other write to the register. On `Join`, keep only if
  both sides agree — do not take the max, and do not report a conflict.

The `ja` must be the terminator of the block that dominates the `movslq`.
Relaxing that to "nearest preceding `cmp` on the index register" was measured
and is wrong: it picks up an unrelated `cmp` in libc's
`nss_database_check_reload_and_get`, which is a genuinely unbounded
data-driven dispatch with no check at all.

Entry count is `ubound + 1`.

### 3.3 Resolution and validation in `FDEChecker`, not `InsnSemantics`

Keep the semantics layer about registers. Have `TransferOutcome` (in
`insn-semantics.h`) gain:

```c++
  // Set when this is `jmp *%T` and T resolved to a PIC switch-table
  // dispatch. The table still has to be read and validated by the
  // caller, which owns the ELF image and the FDE's PC range.
  bool has_jump_table = false;
  uint64_t jump_table_addr = 0;
  uint64_t jump_table_entries = 0;
```

`FDEChecker` then reads and validates the table, **all-or-nothing**:

1. `4 * entries` lies entirely inside a file-backed, non-executable PT_LOAD.
   `ELFImage` needs a small helper for this; `LoadSegment` already carries
   `flags` and `filesz`, so no section table is required. (All 357 tables
   measured were in `.rodata`; requiring non-writable would also have worked,
   but file-backed + non-executable is the more robust rule and still excludes
   `.bss`.)
2. `entries <= 512`. Largest observed is 160.
3. Every `table_addr + (int32)entry` lands inside **some** FDE — not
   necessarily this one, see §6.
4. Every target decodes as an instruction start.

If **any** entry fails any check, discard the whole table and emit today's
`unresolved indirect jump` review. Truncating at the first failure would be
sound (under-approximation only costs coverage) but was never needed: across
357 tables and 10,832 entries there was not one failing entry.

### 3.4 Integration: a resolved table is just a list of direct targets

This is the point of the whole design — there is almost no new control-flow
code. In pass 1 of `FDEChecker`, where `outcome.has_direct_target` is handled:

* target inside `[cfi.pc_begin, cfi.pc_end)` → `propagate(target, state)`.
* target outside → route through the same cross-FDE handling a direct `jmp` out
  of the FDE already gets (`CheckExitState` with `is_tail_call=true`, or a
  dedicated review naming it — see §6, it is 4 sites in total).

In pass 2, `outcome.indirect_branch` stops being a review when the table
resolved. The `N bytes ... were not reached` gap reports disappear on their own
because the target bytes now get walked.

Re-resolve on every pass-1 visit of the `jmp` and union the targets into a
per-FDE set. The set only grows, so the fixpoint stays monotone and terminates;
the 512 cap bounds it. This also naturally handles a `jmp` reached with two
different table bases on two paths (not observed, but free).

## 4. Why this is trustworthy

For all **357 resolvable tables / 10,832 entries** across sqlite, libstdc++,
libc and libcrypto, every single entry landed on an instruction boundary inside
a valid FDE. Zero bad entries. Zero tables where the `cmp`-derived count
disagreed with what the table data supports.

That confidence comes from the bound, not from the validators. The contract is
"bless the easy cases with near-certainty and shout about everything else", and
this satisfies it because the failure directions are asymmetric:

* **Missing a target** costs coverage: the bytes come back as an unchecked gap,
  which is today's behaviour. Harmless.
* **Inventing a target** seeds a state at an address no execution reaches, and
  can manufacture a false `MISMATCH`. This is the only dangerous direction, and
  the bound plus the all-or-nothing rule is what closes it.

## 5. Two approaches that look simpler and are wrong

**Read entries until one fails validation, no bound.** Measured: it over-reads
in ~25% of tables, sometimes badly — libc declared 21 entries and greedy reading
took 47; libcrypto declared 84 and took 116. The extra entries pass every
validator because they belong to the *neighbouring* table of the same function
and still resolve to real instruction starts inside the same FDE. Do not do
this.

**The function-bounds golden rule** from
`../backtrace-test/doc/binary-unwind-analysis.adoc`. ~1% of tables (4 sites in
total) have targets in a *different* FDE. `libstdc++`'s `0x1e5d58` dispatches 21
ways, and 17 of those go to `[0xb98fa,0xb9921)` — 1.2 MB away, an ICF'd shared
throw block. Bounding by function or FDE range would reject that whole table.
The correct rule is "lands in *some* FDE", plus separate handling for targets
outside our own (§6).

## 6. Sharp edges

* **CET `notrack` prefix.** GCC emits `notrack jmp *%rax` on every one of
  libstdc++'s tables. Verify `disasm.cc` / Capstone decodes it as a plain
  `X86_INS_JMP` with the prefix attached, and that `Transfer` still classifies
  it via `X86_GRP_JUMP`. Check this first — it is cheap and it gates half the
  corpus.
* **Targets outside our FDE.** 3 of 52 tables in libstdc++, 1 of 74 in libc, 0
  elsewhere. Do not propagate into another FDE — `FDEChecker` is function-local
  by design and the other FDE gets its own walk. Emitting a review naming the
  out-of-FDE target is fine; it is 4 sites across four binaries.
* **`Join` and the new kinds** — see §3.1. Scope the carve-out to
  constant-meets-constant; widening it to any meet involving a new kind would
  suppress real CFA conflicts.
* **`kTop` is `Join`'s identity element, so a constant survives a merge where
  one path dropped it.** If path A carries `kConst(tbl)` and path B dropped the
  base to `kTop` through an unmodelled instruction, the merge reads
  `kConst(tbl)` (`abs-state.cc:140`). Usually that is the right answer and is
  exactly why the project chose that direction — the register really does still
  hold the table and only the modelling lost track. But it does mean the
  resolver can be handed a base that only one path justifies. **This is the
  load-bearing reason the validation in §3.3 is all-or-nothing:** a stale or
  wrong base yields entries that fail the in-FDE and instruction-start checks,
  and rejecting the whole table on the first failure turns that into a review
  instead of a bogus edge. Truncating at the first bad entry would keep the
  garbage prefix and seed real-looking targets from it.
* **`kBottom` is absorbing, and that costs coverage rather than correctness.**
  If a table base is `kConst(tbl1)` on one path and `kConst(tbl2)` on another,
  the pre-§3.1 behaviour joins to `kBottom` and *neither* table resolves;
  meeting to `kTop` does not rescue it either. Unioning resolved targets across
  pass-1 visits (§3.4) recovers whichever table was seen before the merge
  landed. How often two dispatch sequences tail-merge onto one `jmp` is not
  measured; if it shows up, it shows up as a review, which is the safe
  direction.
* **Sub-register index.** GCC compares `%al`/`%cl`/`%dl` and then indexes with
  the zero-extended 64-bit register. `InsnSemantics::DWARFRegOf` already maps
  sub-registers to their parent; the bound tracking must use the same mapping,
  and must *not* treat `movzbl %al,%eax` as a clobber of the bound.
* **`disp` in `movslq disp(%B,%I,4)`.** Non-zero displacements occur; the table
  starts at `base + disp`, not at `base`. The `add %B,%T` still adds the
  undisplaced `%B`, so `kTableEntry` must remember both the table address and
  the constant the offsets are relative to, and the `add` must check the latter.

## 7. Deliberately left as REVIEW

* **Genuinely unbounded dispatches**, 5–25% of matched patterns depending on the
  binary: computed-goto interpreter loops whose guard is data-driven, and
  dispatches whose bounds check was hoisted out of a loop. These keep today's
  message. Do not try to bound them by reading the table.
* **Non-PIE absolute tables**, `jmp *TBL(,%rax,8)` — 54 sites in `/usr/bin/gcc`
  alone. A different shape (8-byte absolute pointers, `X86_OP_MEM` operand on
  the `jmp` itself rather than a register), and blocked on the absolute-pointer
  encoding vaddr/bias bug recorded in `TODO`. Separate change.
* Everything already listed under "Known gaps" in `AGENT.md`.

## 8. Expected effect, and how to check it

`speedtest1` is the clean measurement: 87 FDEs contain a register-indirect jump,
82 of them have every site resolvable → **62 reviews should drop to about 6**,
and blessed should go from 1570 to roughly 1626 of 1634.

Resolvable share elsewhere, as an upper bound on how many of the indirect-jump
review FDEs can flip: libcrypto 75% (of 145), libstdc++ 64% (of 48), libc 56%
(of 32).

Regression protection to add:

* A fixture in `testdata/fixtures.S` with a hand-written PIC switch table:
  correct CFI in one function, deliberately stale CFI in a case body of another,
  so `fixtures-test.cc` pins both that targets get reached and that a real bug
  in a case body is caught as `MISMATCH`.
* A fixture whose table has no `cmp`/`ja` guard, pinning that it stays `REVIEW`
  rather than being resolved on a guess.
* `insn-semantics-test.cc` cases for the three new transfer rules and for the
  `add` with reversed operand order.
* `abs-state-test.cc` case for "disagreeing constants meet to `kTop` and record
  no conflict".
* Run `./robustness-sweep.sh` afterwards. Anything ABNORMAL is a bug in the
  tool. Watch specifically for any *new* `MISMATCH` — a new mismatch that is not
  hand-verifiable as a true positive means a bogus target got seeded, and the
  fix is to tighten, never to downgrade the severity.

Reproducing the measurements above: `bazel build :unwind-check`, then
`./bazel-bin/unwind-check --report_coverage_gaps <binary>` for the review
counts. The pattern-classification numbers came from an offline script over
`objdump -d --no-show-raw-insn` output cross-referenced with
`readelf -wf` FDE ranges; it is not checked in, and the numbers here are what it
produced on 2026-08-20 against this machine's `/lib/x86_64-linux-gnu/libc.so.6`,
`libstdc++.so.6` and `libcrypto.so.3`, plus a locally built
`~/src/External/sqlite/test/speedtest1`.

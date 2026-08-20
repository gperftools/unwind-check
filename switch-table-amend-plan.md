# Switch tables: amendments after the first pass

Two follow-ups from reviewing the initial implementation (see
`initial-switch-tables-plan.md`), both unverified against real disassembly
yet -- write-up first, confirm against `/bin/ls` before implementing.

## 1. Cross-register bound propagation (the byte-switch gap)

**Observed symptom:** at least one `REVIEW` in `/bin/ls` is a switch on a
`char`/`uint8_t` value that our resolver fails to bless, despite going
through what looks like the ordinary guarded pattern.

**Suspected cause.** `UpdateUBoundsAfterTransfer` (`fde-checker.cc`) only
preserves a register's bound across a widening `mov`/`movzx` when source
and destination resolve to the *same* DWARF register:

```cpp
if (d >= 0 && d == s && !InsnSemantics::IsFull64(dst.reg)) {
  return;  // preserve
}
```

That covers `movzbl %al,%eax`. It does **not** cover the equally plausible
shape where the compiler loads/compares one register and widens into a
*different* one for the address computation, e.g.:

```
movzbl (%rdi), %edx      ; load
cmpb   $N, %dl            ; compare on edx's low byte -> ubound[rdx] = N
ja     default
movzbl %dl, %eax          ; widen into a DIFFERENT register for the index
movslq (%rcx,%rax,4), %rsi
```

Here the bound lands on `ubound[rdx]`, survives untouched (nothing writes
`rdx`), but the `movslq` looks up `ubound[rax]` -- empty. Net effect:
normal dance, no resolution, purely a register-identity mismatch. No
sub-register *value* tracking is implicated; this is a structural gap in
which register number we credited.

**Fix.** Generalize the preserve case from "same register" to "propagate
the bound from source to destination" for any single-source
register-to-register `mov`/`movzx`:

```cpp
if (dst.type == X86_OP_REG && src.type == X86_OP_REG) {
  int d = InsnSemantics::DWARFRegOf(dst.reg);
  int s = InsnSemantics::DWARFRegOf(src.reg);
  if (d >= 0 && s >= 0) {
    std::optional<uint64_t> carried = state->UBound(s);
    if (carried.has_value()) {
      state->SetUBound(d, *carried);
      return;
    }
  }
}
```

Notes:

* This is still narrowly scoped to the `mov reg,reg` / `movzx reg,reg`
  shape -- it is not "never clear a bound on a sub-register write." An
  unrelated `movb $1,%al` (immediate source, not `X86_OP_REG`) still falls
  through to the generic clearing path. The risk profile is unchanged from
  today: we only ever *rename* a bound that's already been established by
  a real `cmp`, never invent one.
* The `d == s` widening case becomes a special case of this rule (`carried
  = ubound[d]` when `s == d`), so the existing `IsFull64` check can be
  dropped too -- it was only there to distinguish "this actually narrows/
  widens" from a full 64-bit `mov reg,reg`, but propagating the bound on a
  full 64-bit copy is equally correct and was arguably a missed case
  before (`mov %rdx,%rax` between guard and load, no narrowing at all,
  would previously have cleared `ubound[rax]` for no reason since `d != s`
  even though `IsFull64` would've been true anyway and hit the generic
  clear path regardless).
* Source register's own bound (`ubound[s]`) is left alone: a `mov` reads
  `s`, it doesn't consume or invalidate it.

**Out of scope, not proposed here:** a compare directly against a
memory operand (`cmpb $N,(%rdi)`) with the index register loaded from the
same location by a *separate* later instruction.

## 2. Snapshot the bound into `kTableEntry` instead of a live re-lookup

Currently `kJumpTarget`'s `IndexReg()` is an indirection: at the `jmp`, we
look up `state->UBound(v.IndexReg())` *live*, using whatever the settled
state says at that PC. Proposal: capture the bound once, into the
`kTableEntry` value itself, at the point the `movslq` builds it (it
already has the index register's current `UBound` available), and carry
that captured number forward through `kJumpTarget` instead of re-deriving
it later.

**Why this is worth doing**, independent of anything else:

* It closes a narrow theoretical gap: if an intervening instruction
  between the `add` and the `jmp` (the plan already notes sqlite has one:
  `mov %r9d,0xc(%rsp)`) happened to reuse the *same register number* for
  an unrelated `cmp`/guard before the `jmp` executes, a live lookup would
  silently pick up that unrelated bound instead of the one actually used
  to size this table. A snapshot taken at `movslq`-time is immune to
  anything that happens afterward -- by the time `add` runs, the index's
  job is done, so nothing later should be able to change what the table's
  size means.
* It makes `kTableEntry`/`kJumpTarget` self-contained: no state lookup
  needed at resolution time, one less moving part in `FDEChecker::Check`.

**Mechanically:** add a field (reuse the existing `AbsVal` widening
approach -- `aux` is already spoken for as the table's base constant, so
this needs one more field, or `aux` could pack both via e.g. a struct/pair
if we don't want to grow `AbsVal` again). At `MOVSXD`-handling time in
`insn-semantics.cc`, read `state->UBound(idx_reg)` and store it inside the
`kTableEntry` (as `std::optional<uint64_t>` or a sentinel). The `add`
handler carries it through into `kJumpTarget` unchanged. `Transfer`'s
`jmp *reg` case reads it directly off the value instead of calling
`state->UBound(v.IndexReg())`.

**Consequence for `AbsState::ubound`:** this does *not* let us delete the
per-register bound array -- it's still exactly how the bound gets from the
`cmp`/`ja` guard to the `movslq` that reads it (that hop remains
register-identity-keyed, per the brainstorm: the table-holding register
and the index register are generally different registers, so *something*
shaped like a per-register side table is unavoidable there). It only
moves the *last* read from "at the `jmp`, live" to "at the `movslq`,
once." Net effect is a smaller, more robust window rather than eliminating
the mechanism.

**Interaction with §1 above:** once cross-register propagation is in
place, this snapshot should be taken *after* whatever chain of
mov/movzx renames delivered the bound to the register the `movslq`
actually indexes with -- which it naturally is, since it reads
`state->UBound(idx_reg)` at `movslq`-processing time, after all prior
instructions (including any renames) have already run.

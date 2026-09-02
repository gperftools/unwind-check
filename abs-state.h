/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
// SPDX-License-Identifier: 0BSD
#ifndef ABS_STATE_H_
#define ABS_STATE_H_

#include <stdint.h>

#include <algorithm>
#include <cassert>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/strings/str_format.h"
#include "cfi-table.h"

namespace unwind_analysis {

// The bound lattice, shared by both bound fields below.
//
// A bound is an *inclusive* upper bound on an unsigned 64-bit value, so
// smaller is stronger: 0 says "this value is 0" and is the lattice's
// bottom, kBoundTop says nothing at all and is its top. Join is plain
// `max`, which is the only thing it can be -- if one path proves the
// value is at most 4 and another proves at most 7, all that survives the
// merge is "at most 7" -- and kBoundTop is max's identity, so an
// unbounded path correctly wipes out the other path's bound with no
// special case anywhere.
inline constexpr uint64_t kBoundTop = ~uint64_t{0};

// The largest value that fits in `bits` bits, as a bound. Every write to
// a 32-bit GPR destination zero-extends on x86-64, so `WidthBound(32)` is
// a fact the mere occurrence of such a write establishes.
inline constexpr uint64_t WidthBound(unsigned bits) {
  return bits >= 64 ? kBoundTop : (uint64_t{1} << bits) - 1;
}

// The anchor for the whole analysis: CFA is defined, once and for all,
// as the value rsp had on entry to the function plus 8 -- i.e. the
// x86-64 psABI's canonical frame address. It is a fixed symbolic
// quantity that we never redefine. Everything the analysis tracks is
// expressed relative to it, which is what makes a declared CFI rule
// directly checkable instead of something we have to re-derive.
//
// This is the *CFI* lattice: what a declared unwind rule can be checked
// against, and the only thing Join reports disagreements about. Switch
// table resolution rides in a separate lattice (TableVal, below) that no
// CFI row can ever consult -- see the split's rationale there.
struct AbsVal {
  enum class Kind : uint8_t {
    // Top of the lattice: truly unknown. No path has told us anything
    // about this value -- it has not been tracked, or precision was
    // deliberately dropped (an unmodelled instruction, a clobber). Top
    // is the meet's identity element: meeting it with anything yields
    // that thing back, because "anything is possible" contributes no
    // constraint of its own.
    kTop,
    // Bottom of the lattice: error/conflict. Two paths each claimed a
    // concrete, different value for this register or slot, so nothing
    // can be trusted here. Bottom is absorbing under meet -- once a
    // value drops to bottom it stays there, since the conflict that
    // produced it does not go away when a third path shows up.
    kBottom,
    kCFARel,   // the value is CFA + delta
    kOrigReg,  // the value is whatever DWARF register `reg` held on entry
    // Known to be *something else*: not CFA-relative, not any register's
    // entry value. A rip-relative `lea` result is the common case.
    //
    // This is a third state of knowledge, and it is not a synonym for
    // kTop. kTop is "I do not know what is in here", which answers a CFI
    // rule with a review; kOther is "I know, and it is definitely not
    // what you claimed", which answers with a mismatch. Both are "not the
    // value the row names", but only one is evidence -- `lea .LC0(%rip),
    // %rbx` where the CFI says rbx is untouched is a real CFI bug, while
    // an unmodelled `add %rax,%rbx` is just us giving up.
    //
    // Every RowChecker test is `is_unknown() -> review, else -> mismatch`,
    // so collapsing kOther into kTop would silently turn a whole class of
    // verified-false into could-not-verify.
    kOther,
  };

  Kind kind = Kind::kTop;
  int64_t delta = 0;
  uint8_t reg = 0;

  static AbsVal Top() {
    return {};
  }
  static constexpr AbsVal Bottom() {
    return AbsVal{Kind::kBottom, 0, 0};
  }
  static AbsVal CFARel(int64_t delta) {
    return AbsVal{Kind::kCFARel, delta, 0};
  }
  static AbsVal OrigReg(int reg) {
    return AbsVal{Kind::kOrigReg, 0, static_cast<uint8_t>(reg)};
  }
  static AbsVal Other() {
    return AbsVal{Kind::kOther, 0, 0};
  }

  bool is_top() const {
    return kind == Kind::kTop;
  }
  bool is_bottom() const {
    return kind == Kind::kBottom;
  }
  // Neither top nor bottom names a concrete value, so both read as
  // "cannot verify a declared CFI rule against this" to every call site
  // that just wants to know whether it has something to compare. kOther
  // is deliberately *not* one of them: see the comment on that kind.
  bool is_unknown() const {
    return kind == Kind::kTop || kind == Kind::kBottom;
  }
  bool IsCFARel(int64_t d) const {
    return kind == Kind::kCFARel && delta == d;
  }
  bool IsOrigReg(int r) const {
    return kind == Kind::kOrigReg && reg == r;
  }

  bool operator==(const AbsVal&) const = default;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const AbsVal& val) {
    switch (val.kind) {
      case Kind::kTop:
        sink.Append("unknown");
        return;
      case Kind::kBottom:
        sink.Append("conflict");
        return;
      case Kind::kCFARel:
        absl::Format(&sink, "CFA%+d", val.delta);
        return;
      case Kind::kOrigReg:
        absl::Format(&sink, "entry %s", DWARFRegName(val.reg));
        return;
      case Kind::kOther:
        sink.Append("an unrelated value");
        return;
    }
    sink.Append("?");
  }
};

// The *table* lattice: everything that exists only to resolve PIC
// switch-table dispatches, and nothing else.
//
// It is kept apart from AbsVal above rather than sharing one struct
// because the two answer different questions and are trusted to different
// depths. No CFI row can assert anything about a scratch register holding
// a `.rodata` pointer or a table-derived offset, so a disagreement here is
// lost precision, never the compiler-bug signal Join exists to report --
// which means this lattice has no conflict reporting at all, and AbsVal's
// join needs no carve-out to suppress it. Two different table values
// meeting at a merge are both kOther on the CFI side, i.e. the same
// identity, so there is nothing to report there either.
//
// Tracked for registers only. A table base or index that gets spilled and
// reloaded loses its table identity, which costs nothing measurable (see
// AGENT.md §4.3) and spares a second slot map.
struct TableVal {
  enum class Kind : uint8_t {
    // Nothing table-related known -- and, like AbsVal::kTop, the join's
    // identity element: a path that knows nothing contributes no
    // constraint, so meeting it with a resolved dispatch leaves the
    // dispatch standing. This is what a register starts as and what a
    // fresh write resets it to.
    kNone,
    // Two paths each claimed a different table value, so nothing here can
    // be trusted -- AbsVal::kBottom's counterpart, and absorbing for the
    // same reason. Keeping this apart from kNone is not tidiness: if
    // giving up landed on the identity element instead, a third
    // predecessor arriving later would be silently adopted, resurrecting a
    // concrete answer after two paths had already disagreed.
    kConflict,
    kConst,       // a known absolute address/constant, in `addr`
    kTableEntry,  // result of a table load: table base `addr`, index reg
                  // `index_reg`, and the undisplaced constant the table
                  // base was computed from in `base_const` (see the `add`
                  // transfer rule)
    kJumpTarget,  // a resolved `table + table[index]`: table addr `addr`,
                  // index reg `index_reg`
  };

  Kind kind = Kind::kNone;
  int64_t addr = 0;
  uint8_t index_reg = 0;
  uint64_t base_const = 0;

  // Two upper bounds on the number this register holds. Both are facts
  // about the full 64-bit value, and both live here rather than on AbsVal
  // because their only consumers are table resolution and the width proofs
  // that feed it.
  //
  // `value_bound` is everything we can prove about the number, from any
  // source: a zero-extending widen (`movzbl %al,%ecx` proves at most 255),
  // the bare fact that an instruction wrote a 32-bit register (every such
  // write zero-extends on x86-64, so the register is at most 0xffffffff),
  // or a guard. Its job is *proving widths*: it is what lets a narrow
  // `cmp $imm,%eax` say anything about rax at all, since without it the
  // guard constrains only the low 32 bits and the table load reads all 64.
  //
  // `table_bound` is the subset of that established by a
  // `cmp $imm,%r; ja default` guard and nothing else -- a bound the
  // *compiler* declared, not one inferred from an instruction's width.
  // Only this one may size a switch table. A width fact is honest but
  // useless as a table size (`movzbl` proving an index is at most 255
  // would resolve a 256-entry table out of whatever .rodata follows the
  // real one), and a wrong table size sends the walk to wrong targets.
  // Keeping them apart is also what keeps `table_bound == kBoundTop` a
  // meaningful "no compiler-declared bound" predicate, which is what
  // routes an unbounded dispatch to guessing recovery instead of silently
  // resolving it.
  //
  // For kTableEntry and kJumpTarget, `table_bound` means the bound
  // captured for the *index register* at `movslq` time, not a bound on
  // this (address-valued) entry. It is captured then, rather than
  // re-derived with a live lookup at the eventual `jmp`, because an
  // intervening instruction could reuse the same register number for an
  // unrelated guard and a live lookup would silently pick that up instead
  // of the one that actually sized this table. A snapshot taken when the
  // index's job is already done is immune to anything afterward.
  uint64_t value_bound = kBoundTop;
  uint64_t table_bound = kBoundTop;

  static TableVal None() {
    return {};
  }
  static TableVal Conflict() {
    return TableVal{Kind::kConflict, 0, 0, 0, kBoundTop, kBoundTop};
  }
  bool is_none() const {
    return kind == Kind::kNone;
  }
  bool is_conflict() const {
    return kind == Kind::kConflict;
  }
  static TableVal Const(int64_t value) {
    return TableVal{Kind::kConst, value, 0, 0, kBoundTop, kBoundTop};
  }
  // `index_bound` is the index register's table_bound, snapshotted here --
  // see the comment on table_bound for why it is taken now and not read
  // live at the `jmp`.
  static TableVal TableEntry(uint64_t table_addr, uint8_t index_reg, uint64_t base_const, uint64_t index_bound) {
    return TableVal{Kind::kTableEntry, static_cast<int64_t>(table_addr), index_reg, base_const, kBoundTop, index_bound};
  }
  static TableVal JumpTarget(uint64_t table_addr, uint8_t index_reg, uint64_t index_bound) {
    return TableVal{Kind::kJumpTarget, static_cast<int64_t>(table_addr), index_reg, 0, kBoundTop, index_bound};
  }

  bool IsConst() const {
    return kind == Kind::kConst;
  }
  int64_t ConstValue() const {
    assert(IsConst());
    return addr;
  }
  bool IsTableEntry() const {
    return kind == Kind::kTableEntry;
  }
  bool IsJumpTarget() const {
    return kind == Kind::kJumpTarget;
  }
  // Valid for kTableEntry and kJumpTarget.
  uint64_t TableAddr() const {
    assert(IsTableEntry() || IsJumpTarget());
    return static_cast<uint64_t>(addr);
  }
  int IndexReg() const {
    assert(IsTableEntry() || IsJumpTarget());
    return index_reg;
  }
  // Valid for kTableEntry only: the undisplaced constant `addr` was
  // derived from, which the `add %B,%T` transfer rule must match against
  // `%B` before it will resolve to a kJumpTarget.
  uint64_t TableBaseConst() const {
    assert(IsTableEntry());
    return base_const;
  }

  // True when a `cmp $imm,%r; ja default` guard proved a bound this value
  // may be used to size a switch table from -- see `table_bound` above for
  // why a `value_bound` alone does not qualify.
  bool HasTableBound() const {
    return table_bound != kBoundTop;
  }
  // Tightens both bounds to `b`, the effect of a guard proving this value
  // is at most `b`. Both, because a compiler-declared bound is evidence
  // about the number as well as evidence a table may be sized from.
  void ApplyGuardBound(uint64_t b) {
    value_bound = std::min(value_bound, b);
    table_bound = std::min(table_bound, b);
  }
  void ClearBounds() {
    value_bound = kBoundTop;
    table_bound = kBoundTop;
  }

  // True when two values name the same thing, regardless of whether their
  // bounds agree -- the same identity/auxiliary split AbsVal used to need
  // internally, now confined to the lattice that actually has bounds.
  bool SameIdentity(const TableVal& other) const {
    return kind == other.kind && addr == other.addr && index_reg == other.index_reg && base_const == other.base_const;
  }

  bool operator==(const TableVal&) const = default;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const TableVal& val) {
    switch (val.kind) {
      case Kind::kNone:
        sink.Append("nothing table-related");
        return;
      case Kind::kConflict:
        sink.Append("conflicting table values");
        return;
      case Kind::kConst:
        absl::Format(&sink, "const 0x%x", val.addr);
        return;
      case Kind::kTableEntry:
        absl::Format(&sink, "table[%s] entry (table@0x%x)", DWARFRegName(val.index_reg), val.TableAddr());
        return;
      case Kind::kJumpTarget:
        absl::Format(&sink, "jump target table@0x%x[%s]", val.TableAddr(), DWARFRegName(val.index_reg));
        return;
    }
    sink.Append("?");
  }
};

// The abstract state at one program point.
//
// `slots` holds only the stack locations whose contents we can name;
// anything else is simply absent, which reads as "unknown". Keys are
// offsets from the CFA, so a `push` at function entry writes slot -16,
// and the return address the call put there lives at slot -8.
struct AbsState {
  // The CFI lattice, for registers and for the stack slots we can name.
  AbsVal gpr[kNumGPRs];
  absl::btree_map<int64_t, AbsVal> slots;
  // The table lattice, registers only -- see TableVal. Indexed the same
  // way as gpr[], so tbl[r] is the switch-resolution half of register r.
  TableVal tbl[kNumGPRs];

  // Applies a guard's proven bound to register r in place. Deliberately
  // *not* routed through SetReg: tightening a bound is not a value write,
  // so it must not invalidate `last_cmp` the way an actual write to the
  // register does (see SetReg below), and it must not disturb the CFI half
  // at all. Out-of-range r is ignored, which is what the callers that pass
  // a DWARFRegOf() result want.
  void ApplyGuardBound(int r, uint64_t b) {
    if (r >= 0 && r < kNumGPRs) {
      tbl[r].ApplyGuardBound(b);
    }
  }
  // Records a width fact: r's full 64-bit value is at most `b`, proven by
  // something other than a compiler-declared guard (a zero-extending
  // write, typically). Never touches table_bound -- see TableVal for why
  // only a guard may size a table.
  void ApplyValueBound(int r, uint64_t b) {
    if (r >= 0 && r < kNumGPRs) {
      tbl[r].value_bound = std::min(tbl[r].value_bound, b);
    }
  }

  // The `cmp $imm,%reg` guard currently in play. It has two lives, and
  // `proven_bound` says which one it is living.
  //
  // Before a branch it is only a comparison: flags were set, nothing was
  // established. It is inert -- nothing may derive a bound from it -- and
  // any later EFLAGS write drops it, since the flags no longer answer for
  // this cmp. That is handled once up front in InsnSemantics::Transfer.
  //
  // After a branch has selected the in-range edge (in
  // InsnSemantics::TransferEdge, and only on that edge) it is a fact about
  // a value:
  // the low `width_bits` bits of `reg` are at most `proven_bound`. Flags no
  // longer matter to it, so an EFLAGS write no longer clears it -- and it
  // has to survive them, because the instructions between the branch and
  // the widen that consumes it are ordinary code.
  //
  // It is kept here, rather than folded into the register's own bounds,
  // precisely because it is *width-qualified*: `cmp $0xe,%esi` on an
  // argument register says nothing about rsi, whose upper half the ABI
  // leaves undefined, but everything about the `mov %esi,%eax` that reads
  // exactly those 32 bits and zero-extends them. Promoting it to a
  // full-register bound is possible only when something already proved the
  // register zero-extended; when it is not, this is where the fact waits
  // for a narrow read to collect it. See TableVal::value_bound.
  //
  // Either way, a write to `reg` invalidates it -- handled in
  // SetReg/ClobberReg below, without which `cmp $5,%eax; mov (%rbx),%rax;
  // ja default` would bound whatever landed in rax rather than what was
  // compared. There is exactly one EFLAGS, so exactly one of these, rather
  // than one per register.
  struct FlagsGuard {
    int reg = 0;
    uint8_t width_bits = 0;
    // The comparison's own operand, exactly as decoded. Never rewritten,
    // so it still says what the bound below was derived from once one
    // exists -- which is what the diagnostics print.
    uint64_t imm = 0;
    // The bound a branch established, or kBoundTop while none has. This
    // is the `proven` state: kBoundTop means "a comparison happened,
    // nothing is established yet", anything else means "the low
    // `width_bits` bits of `reg` are at most this".
    //
    // It cannot simply be `imm`, because at `cmp` time the bound is not
    // yet computable: `ja`/`jbe` split at `reg <= imm` but `jae`/`jb` at
    // `reg < imm`, and which one applies depends on a branch that has not
    // been seen. So the record genuinely starts as an operand and gains a
    // bound later; keeping the two in separate fields is what stops either
    // from having to mean both.
    //
    // A vacuous bound reads as no bound at all (a 64-bit `cmp $-1,%rax`
    // proves `rax <= kBoundTop`, which constrains nothing) -- the same
    // collapse the rest of the bound lattice makes.
    uint64_t proven_bound = kBoundTop;

    // Whether a branch has turned this comparison into a fact about a
    // value. See proven_bound.
    bool proven() const {
      return proven_bound != kBoundTop;
    }

    bool operator==(const FlagsGuard&) const = default;
  };
  std::optional<FlagsGuard> last_cmp;

  // The state on entry to a function: rsp is CFA-8 (the call pushed the
  // return address), every register still holds its own entry value, and
  // the return address is on the stack at CFA-8.
  static AbsState Entry();

  // The state to start an FDE's analysis from, read off the FDE's own
  // first CFI row -- or, for an exception landing pad, off the row
  // covering the pad's address, since a pad is reached only by the
  // unwinder rather than by falling or branching in from earlier code.
  //
  // Assuming Entry() would be wrong: plenty of FDEs cover a *fragment*
  // of a function rather than a whole one -- cold parts split out to
  // .text.unlikely, PLT stubs -- and those begin with several registers
  // already spilled and rsp well below the CFA. Seeding from the
  // declared row means the analysis verifies that the rest of the CFI
  // stays consistent with the code *relative to where the FDE starts*,
  // which is the strongest claim available without inter-procedural
  // information. For an FDE that really does start a function the
  // declared row is the canonical entry state anyway, so this is a
  // strict generalisation of Entry() -- and FDEChecker separately
  // verifies that claim wherever a function symbol says the FDE starts
  // one.
  //
  // `at_function_entry` decides what an *unmentioned* register
  // (RegRule::Kind::kUnset) seeds to. A row's silence about a register
  // is not the same claim everywhere: at a genuine function entry
  // nothing has executed yet, so silence trivially means "still holds
  // whatever the caller passed in" -- the same conclusion Entry()
  // reaches, just read off the CFI instead of assumed outright. At any
  // other seed point -- a `.cold` fragment reached by a jump after the
  // hot part has already run, a landing pad reached by the unwinder
  // after arbitrary code between the `try` and the `throw` -- the CFI's
  // silence only means nothing needed unwinding that register, not that
  // it still holds its function-entry value. There an unmentioned
  // register seeds to kTop instead. An *explicit* RegRule::Kind::kSameValue
  // is a real CFI assertion either way, and is trusted regardless of
  // `at_function_entry`.
  static AbsState SeedFromRow(const CFIRow& row, bool at_function_entry);

  const AbsVal& reg(int r) const {
    static constinit auto kInvalid = AbsVal::Bottom();
    if (r < 0 || r >= kNumGPRs) {
      return kInvalid;
    }
    return gpr[r];
  }
  const TableVal& table(int r) const {
    static constinit auto kNone = TableVal{};
    if (r < 0 || r >= kNumGPRs) {
      return kNone;
    }
    return tbl[r];
  }

  // The register writes. These are the only places a register's *value*
  // changes, which makes them the single choke point for invalidating
  // `last_cmp` when the compared register is overwritten. Join writes
  // gpr[]/tbl[] directly and bypasses them, on purpose: it does its own
  // last_cmp merge.
  //
  // Both halves always move together. The one-argument SetReg clears the
  // table half rather than leaving it alone, so a register that just got a
  // new value can never keep a stale table identity or a bound that
  // described what used to be there -- the failure this split would
  // otherwise make easy to write by accident.
  void SetReg(int r, const AbsVal& v, const TableVal& t) {
    assert(0 <= r && r < kNumGPRs);
    gpr[r] = v;
    tbl[r] = t;
    InvalidateLastCmpFor(r);
    if (r == kDWARFRsp && v.kind == AbsVal::Kind::kCFARel) {
      DropDeadSlots(v.delta);
    }
  }
  void SetReg(int r, const AbsVal& v) {
    SetReg(r, v, TableVal::None());
  }
  // A register that now holds a table-resolution value. Its CFI half is
  // kOther by construction: a `.rodata` pointer or a table-derived address
  // is definitely not any register's entry value and definitely not
  // CFA-relative, which is exactly what a CFI rule claiming otherwise
  // should be told.
  void SetTableReg(int r, const TableVal& t) {
    SetReg(r, AbsVal::Other(), t);
  }
  // A full-width register-to-register move: the one case where a value
  // keeps its identity *and* its bounds, so both halves are copied.
  void CopyReg(int dst, int src) {
    assert(0 <= src && src < kNumGPRs);
    SetReg(dst, gpr[src], tbl[src]);
  }
  void ClobberReg(int r) {
    SetReg(r, AbsVal::Top(), TableVal::None());
  }

  // Slot lookup; absent slots read as unknown.
  AbsVal Slot(int64_t offset) const;
  void SetSlot(int64_t offset, const AbsVal& v);

  // Drops every slot strictly below `rsp_delta`.
  void DropSlotsBelow(int64_t rsp_delta);

  // Drops the slots that moving the stack pointer to `rsp_delta` really
  // kills, leaving the red zone alone.
  //
  // This matters more than it looks. GCC routinely leaves a register's
  // `DW_CFA_offset` rule in force after the `pop` that restored it,
  // never emitting `DW_CFA_restore` -- so at the `ret` of an ordinary
  // function the CFI still says rbx lives at CFA-32, an address now
  // below rsp. That is safe in practice precisely because the kernel
  // honours the 128-byte red zone when delivering a signal, so the
  // spilled value is still there. Dropping those slots outright would
  // flag essentially every GCC-compiled function and bury the report.
  //
  // Calls are the exception and use DropSlotsBelow directly: no red zone
  // survives a call.
  void DropDeadSlots(int64_t rsp_delta);

  // The x86-64 psABI's red zone: the 128 bytes below rsp that a signal
  // handler must not disturb.
  static constexpr int64_t kRedZoneBytes = 128;

  // Drops `last_cmp` if it names register r -- see FlagsGuard above.
  void InvalidateLastCmpFor(int r) {
    if (last_cmp.has_value() && last_cmp->reg == r) {
      last_cmp = std::nullopt;
    }
  }

  bool operator==(const AbsState&) const = default;
};

// What disagreed when two paths met.
struct JoinConflict {
  // Register number, or kSlotConflict with `offset` set.
  static constexpr int kSlotConflict = -1;
  int reg = 0;
  int64_t offset = 0;
  AbsVal lhs;
  AbsVal rhs;

  std::string Describe() const;
};

// Meets `incoming` into `*state`. Components that agree survive;
// components that disagree drop to kBottom *and* are reported in
// `conflicts`. A component only one side has an opinion on (kTop on the
// other) takes that opinion, since kTop is the identity element.
//
// The reporting is the point. .eh_frame declares exactly one state per
// PC, so two edges reaching the same PC with different real stack states
// is either a gap in this analysis or the compiler bug we are hunting.
// Widening silently would hide both.
//
// Returns true when *state changed, i.e. the successor needs requeueing.
bool Join(const AbsState& incoming, AbsState* state, std::vector<JoinConflict>* conflicts);

}  // namespace unwind_analysis

#endif  // ABS_STATE_H_

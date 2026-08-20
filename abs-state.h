/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef ABS_STATE_H_
#define ABS_STATE_H_

#include <stdint.h>

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "cfi-table.h"

namespace unwind_analysis {

// The anchor for the whole analysis: CFA is defined, once and for all,
// as the value rsp had on entry to the function plus 8 -- i.e. the
// x86-64 psABI's canonical frame address. It is a fixed symbolic
// quantity that we never redefine. Everything the analysis tracks is
// expressed relative to it, which is what makes a declared CFI rule
// directly checkable instead of something we have to re-derive.
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
    // The three kinds below exist only to resolve PIC switch-table
    // dispatches (initial-switch-tables-plan.md §3.1). No CFI row ever
    // asserts anything about them, so a conflict between two of these
    // kinds is not a CFI/code disagreement -- see the carve-out in
    // Join().
    kConst,       // a known absolute address/constant, in `delta`
    kTableEntry,  // result of a table load: table base `delta`, index reg
                  // `reg`, and the undisplaced constant the table base was
                  // computed from in `aux` (see the `add` transfer rule)
    kJumpTarget,  // a resolved `table + table[index]`: table addr `delta`,
                  // index reg `reg`
  };

  Kind kind = Kind::kTop;
  int64_t delta = 0;
  uint8_t reg = 0;
  uint64_t aux = 0;

  static AbsVal Top() {
    return {};
  }
  static AbsVal Bottom() {
    return AbsVal{Kind::kBottom, 0, 0};
  }
  static AbsVal CFARel(int64_t delta) {
    return AbsVal{Kind::kCFARel, delta, 0};
  }
  static AbsVal OrigReg(int reg) {
    return AbsVal{Kind::kOrigReg, 0, static_cast<uint8_t>(reg)};
  }
  static AbsVal Const(int64_t value) {
    return AbsVal{Kind::kConst, value, 0};
  }
  static AbsVal TableEntry(uint64_t table_addr, uint8_t index_reg, uint64_t base_const) {
    return AbsVal{Kind::kTableEntry, static_cast<int64_t>(table_addr), index_reg, base_const};
  }
  static AbsVal JumpTarget(uint64_t table_addr, uint8_t index_reg) {
    return AbsVal{Kind::kJumpTarget, static_cast<int64_t>(table_addr), index_reg};
  }

  bool is_top() const {
    return kind == Kind::kTop;
  }
  bool is_bottom() const {
    return kind == Kind::kBottom;
  }
  // Neither top nor bottom names a concrete value, so both read as
  // "cannot verify a declared CFI rule against this" to every call site
  // that just wants to know whether it has something to compare.
  bool is_unknown() const {
    return kind == Kind::kTop || kind == Kind::kBottom;
  }
  bool IsCFARel(int64_t d) const {
    return kind == Kind::kCFARel && delta == d;
  }
  bool IsOrigReg(int r) const {
    return kind == Kind::kOrigReg && reg == r;
  }
  bool IsConst() const {
    return kind == Kind::kConst;
  }
  int64_t ConstValue() const {
    return delta;
  }
  bool IsTableEntry() const {
    return kind == Kind::kTableEntry;
  }
  bool IsJumpTarget() const {
    return kind == Kind::kJumpTarget;
  }
  // Valid for kTableEntry and kJumpTarget.
  uint64_t TableAddr() const {
    return static_cast<uint64_t>(delta);
  }
  int IndexReg() const {
    return reg;
  }
  // Valid for kTableEntry only: the undisplaced constant `table` was
  // derived from, which the `add %B,%T` transfer rule must match against
  // `%B` before it will resolve to a kJumpTarget.
  uint64_t TableBaseConst() const {
    return aux;
  }

  bool operator==(const AbsVal&) const = default;
  std::string ToString() const;
};

// The abstract state at one program point.
//
// `slots` holds only the stack locations whose contents we can name;
// anything else is simply absent, which reads as "unknown". Keys are
// offsets from the CFA, so a `push` at function entry writes slot -16,
// and the return address the call put there lives at slot -8.
struct AbsState {
  AbsVal gpr[kNumGPRs];
  std::map<int64_t, AbsVal> slots;

  // Per-register unsigned upper bound learned from a `cmp $imm,%r; ja
  // default` switch-table guard, valid only on the in-bounds
  // (fall-through) edge -- see initial-switch-tables-plan.md §3.2. This
  // is not part of AbsVal: no CFI row ever asserts anything about it, it
  // exists purely so FDEChecker can size-bound a resolved jump table.
  std::optional<uint64_t> ubound[kNumGPRs];

  std::optional<uint64_t> UBound(int r) const {
    return (r >= 0 && r < kNumGPRs) ? ubound[r] : std::nullopt;
  }
  void SetUBound(int r, uint64_t v) {
    if (r >= 0 && r < kNumGPRs) {
      ubound[r] = v;
    }
  }
  void ClearUBound(int r) {
    if (r >= 0 && r < kNumGPRs) {
      ubound[r] = std::nullopt;
    }
  }

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
    return gpr[r];
  }
  void SetReg(int r, const AbsVal& v) {
    gpr[r] = v;
  }
  void ClobberReg(int r) {
    gpr[r] = AbsVal::Top();
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

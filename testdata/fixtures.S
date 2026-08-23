/* -*- Mode: asm -*- */
/*
 * Hand-written CFI fixtures for unwind-check.
 *
 * Every .cfi_* directive here is written by hand precisely so that no
 * compiler version gets a vote: the expected verdict for each function
 * is a property of this file, not of whoever built it.
 *
 * Names carry the expectation. good_* must come out BLESSED, bad_* must
 * come out MISMATCH, review_* must come out REVIEW. fixtures-test.cc
 * asserts exactly that, and for the bad_* cases also asserts which
 * instruction the finding lands on.
 */

        .text

/* ---------------------------------------------------------------- */
/* A leaf that touches nothing. The CIE's initial row is already right.
   Hidden so intra-file jumps/calls to it resolve directly instead of
   through a PLT stub -- otherwise a shared-library build routes every
   `jmp good_leaf` through the PLT, which is untracked by .eh_frame and
   defeats the cross-FDE row check the tests below exist to exercise. */
        .globl  good_leaf
        .hidden good_leaf
        .type   good_leaf, @function
good_leaf:
        .cfi_startproc
        movl    %edi, %eax
        ret
        .cfi_endproc
        .size   good_leaf, .-good_leaf

/* ---------------------------------------------------------------- */
/* The textbook frame pointer prologue and epilogue. */
        .globl  good_frame_pointer
        .type   good_frame_pointer, @function
good_frame_pointer:
        .cfi_startproc
        pushq   %rbp
        .cfi_def_cfa_offset 16
        .cfi_offset %rbp, -16
        movq    %rsp, %rbp
        .cfi_def_cfa_register %rbp
        movl    %edi, %eax
        popq    %rbp
        .cfi_def_cfa %rsp, 8
        ret
        .cfi_endproc
        .size   good_frame_pointer, .-good_frame_pointer

/* ---------------------------------------------------------------- */
/* Several callee-saved spills plus a local frame, unwound correctly. */
        .globl  good_callee_saved
        .type   good_callee_saved, @function
good_callee_saved:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        pushq   %r12
        .cfi_def_cfa_offset 24
        .cfi_offset %r12, -24
        subq    $8, %rsp
        .cfi_def_cfa_offset 32
        movl    %edi, %eax
        addq    $8, %rsp
        .cfi_def_cfa_offset 24
        popq    %r12
        .cfi_def_cfa_offset 16
        popq    %rbx
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_callee_saved, .-good_callee_saved

/* ---------------------------------------------------------------- */
/* `leave` restoring rsp and rbp in one go. */
        .globl  good_leave
        .type   good_leave, @function
good_leave:
        .cfi_startproc
        pushq   %rbp
        .cfi_def_cfa_offset 16
        .cfi_offset %rbp, -16
        movq    %rsp, %rbp
        .cfi_def_cfa_register %rbp
        subq    $16, %rsp
        movl    %edi, %eax
        leave
        .cfi_def_cfa %rsp, 8
        ret
        .cfi_endproc
        .size   good_leave, .-good_leave

/* ---------------------------------------------------------------- */
/*
 * A conditional branch into a shared epilogue -- the exact shape that
 * broke clang -- but with the CFI kept correct across the merge. Both
 * paths reach the pop with rsp at CFA-16, so the single row there is
 * right for both and this must be blessed.
 */
        .globl  good_shared_epilogue
        .type   good_shared_epilogue, @function
good_shared_epilogue:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        testl   %edi, %edi
        je      .Lgse_join
        movl    $1, %eax
        jmp     .Lgse_join
.Lgse_join:
        popq    %rbx
        .cfi_def_cfa_offset 8
        .cfi_restore %rbx
        ret
        .cfi_endproc
        .size   good_shared_epilogue, .-good_shared_epilogue

/* ---------------------------------------------------------------- */
/*
 * clang bug shape #1, from spec/README: the stack adjustment common to
 * both arms of a branch gets hoisted above the branch, but its CFI
 * update stays behind in the arms. Between the add and the branch the
 * table claims 8 bytes more stack than there is.
 *
 * The finding must land on the `testl` right after the add.
 */
        .globl  bad_hoisted_add
        .type   bad_hoisted_add, @function
bad_hoisted_add:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        subq    $8, %rsp
        .cfi_def_cfa_offset 24
        addq    $8, %rsp
        /* No .cfi_def_cfa_offset 16 here -- that is the bug. */
        testl   %edi, %edi
        je      .Lbha_other
        .cfi_def_cfa_offset 16
        popq    %rbx
        .cfi_def_cfa_offset 8
        ret
.Lbha_other:
        .cfi_def_cfa_offset 16
        popq    %rbx
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   bad_hoisted_add, .-bad_hoisted_add

/* ---------------------------------------------------------------- */
/*
 * clang bug shape #2, from spec/README: the CFI for a push lands one
 * instruction late, so at the instruction in between the table is still
 * describing the stack as it was before the push.
 *
 * The finding must land on the `movq` between them.
 */
        .globl  bad_late_push_cfi
        .type   bad_late_push_cfi, @function
bad_late_push_cfi:
        .cfi_startproc
        pushq   %r12
        movq    %rsi, %r12
        .cfi_def_cfa_offset 16
        .cfi_offset %r12, -16
        popq    %r12
        .cfi_def_cfa_offset 8
        .cfi_restore %r12
        ret
        .cfi_endproc
        .size   bad_late_push_cfi, .-bad_late_push_cfi

/* ---------------------------------------------------------------- */
/*
 * A function whose first row is not the canonical entry state. A
 * function entered by `call` has the CFA at rsp+8 on its first
 * instruction -- but PLT trampolines carry function symbols too and are
 * entered by a jump, so this is flagged for a human rather than called a
 * bug outright.
 */
        .globl  review_unusual_entry_row
        .type   review_unusual_entry_row, @function
review_unusual_entry_row:
        .cfi_startproc
        .cfi_def_cfa_offset 32
        movl    %edi, %eax
        ret
        .cfi_endproc
        .size   review_unusual_entry_row, .-review_unusual_entry_row

/* ---------------------------------------------------------------- */
/*
 * The slot at CFA-16 really does hold a saved register -- just not the
 * one the table names. rbp went in; the CFI claims rbx came out of it.
 */
        .globl  bad_wrong_register_saved
        .type   bad_wrong_register_saved, @function
bad_wrong_register_saved:
        .cfi_startproc
        pushq   %rbp
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        popq    %rbp
        .cfi_def_cfa_offset 8
        .cfi_restore %rbx
        ret
        .cfi_endproc
        .size   bad_wrong_register_saved, .-bad_wrong_register_saved

/* ---------------------------------------------------------------- */
/*
 * Optimized code spills with `mov` into a frame carved out by `sub`
 * rather than with `push`, so the checker has to follow rsp-relative
 * stores as well as pushes.
 */
        .globl  good_mov_spill
        .type   good_mov_spill, @function
good_mov_spill:
        .cfi_startproc
        subq    $24, %rsp
        .cfi_def_cfa_offset 32
        movq    %rbx, 8(%rsp)
        .cfi_offset %rbx, -24
        movl    %edi, %eax
        movq    8(%rsp), %rbx
        addq    $24, %rsp
        .cfi_def_cfa_offset 8
        .cfi_restore %rbx
        ret
        .cfi_endproc
        .size   good_mov_spill, .-good_mov_spill

/* ---------------------------------------------------------------- */
/* A call in the middle: rsp must come back to where it was. */
        .globl  good_call
        .type   good_call, @function
good_call:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        call    good_leaf
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_call, .-good_call

/* ---------------------------------------------------------------- */
/* An indirect jump with an active stack frame: jump table inside a function. */
        .globl  review_indirect_jump
        .type   review_indirect_jump, @function
review_indirect_jump:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        testl   %edi, %edi
        je      .Lrij_out
        jmp     *%rsi
.Lrij_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   review_indirect_jump, .-review_indirect_jump

/* ---------------------------------------------------------------- */
/* A direct tail call with the frame cleanly dismantled. */
        .globl  good_tail_call
        .type   good_tail_call, @function
good_tail_call:
        .cfi_startproc
        movl    %edi, %eax
        jmp     good_leaf
        .cfi_endproc
        .size   good_tail_call, .-good_tail_call

/* ---------------------------------------------------------------- */
/* An indirect tail call (e.g. vtable / function pointer tail call). */
        .globl  good_indirect_tail_call
        .type   good_indirect_tail_call, @function
good_indirect_tail_call:
        .cfi_startproc
        movl    %edi, %eax
        jmp     *%rsi
        .cfi_endproc
        .size   good_indirect_tail_call, .-good_indirect_tail_call

/* ---------------------------------------------------------------- */
/* Return with stack pointer not restored to CFA-8. */
        .globl  bad_ret_stack_not_restored
        .type   bad_ret_stack_not_restored, @function
bad_ret_stack_not_restored:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        ret
        .cfi_endproc
        .size   bad_ret_stack_not_restored, .-bad_ret_stack_not_restored

/* ---------------------------------------------------------------- */
/* Return with wrong callee-saved register restored. */
        .globl  bad_ret_wrong_reg_restored
        .type   bad_ret_wrong_reg_restored, @function
bad_ret_wrong_reg_restored:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        pushq   %r12
        .cfi_def_cfa_offset 24
        popq    %rbx
        .cfi_def_cfa_offset 16
        popq    %r12
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   bad_ret_wrong_reg_restored, .-bad_ret_wrong_reg_restored

/* ---------------------------------------------------------------- */
/* Tail call with wrong callee-saved register restored. */
        .globl  bad_tail_call_wrong_reg_restored
        .type   bad_tail_call_wrong_reg_restored, @function
bad_tail_call_wrong_reg_restored:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        pushq   %r12
        .cfi_def_cfa_offset 24
        popq    %rbx
        .cfi_def_cfa_offset 16
        popq    %r12
        .cfi_def_cfa_offset 8
        jmp     good_leaf
        .cfi_endproc
        .size   bad_tail_call_wrong_reg_restored, .-bad_tail_call_wrong_reg_restored

/* ---------------------------------------------------------------- */
/* Return with untracked callee-saved register. */
        .globl  review_ret_callee_saved_untracked
        .type   review_ret_callee_saved_untracked, @function
review_ret_callee_saved_untracked:
        .cfi_startproc
        movq    $123, %rbx
        ret
        .cfi_endproc
        .size   review_ret_callee_saved_untracked, .-review_ret_callee_saved_untracked

/* ---------------------------------------------------------------- */
/*
 * A CFA given by a DWARF expression. The escape encodes
 * DW_CFA_def_cfa_expression with the two-byte program
 * "DW_OP_breg7 (rsp) 8". This version records expressions but does not
 * evaluate them.
 */
        .globl  review_cfa_expression
        .type   review_cfa_expression, @function
review_cfa_expression:
        .cfi_startproc
        movl    %edi, %eax
        .cfi_escape 0x0f, 0x02, 0x77, 0x08
        ret
        .cfi_endproc
        .size   review_cfa_expression, .-review_cfa_expression

/* ---------------------------------------------------------------- */
/*
 * A PIC switch table: lea the table base (in one block), cmp/ja bound
 * the index, movslq loads a table[index] int32 offset, add resolves it
 * to an absolute target, and an indirect jmp (with the CET `notrack`
 * prefix GCC actually emits on these) dispatches. The CFA never moves
 * across any case, so this should come out fully BLESSED only if the
 * checker actually resolves the table and walks every case body.
 */
        .section .rodata
        .align  4
.Lswitch_good_table:
        .long   .Lswitch_good_case0-.Lswitch_good_table
        .long   .Lswitch_good_case1-.Lswitch_good_table
        .long   .Lswitch_good_case2-.Lswitch_good_table
        .text

        .globl  good_switch_table
        .type   good_switch_table, @function
good_switch_table:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        movl    %edi, %eax
        cmpl    $2, %eax
        ja      .Lswitch_good_default
        leaq    .Lswitch_good_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        notrack jmp *%rdx
.Lswitch_good_case0:
        movl    $10, %eax
        jmp     .Lswitch_good_out
.Lswitch_good_case1:
        movl    $20, %eax
        jmp     .Lswitch_good_out
.Lswitch_good_case2:
        movl    $30, %eax
.Lswitch_good_default:
.Lswitch_good_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_switch_table, .-good_switch_table

/* ---------------------------------------------------------------- */
/*
 * A callee-saved register clobbered with a `.rodata` address and never
 * restored, with CFI that never says so.
 *
 * This is what AbsVal::kOther exists for. At the `ret` the analysis knows
 * exactly what rbx holds -- a rip-relative lea result -- and knows it is
 * definitely not rbx's entry value, so the CFI's silence is contradicted
 * rather than merely unverifiable. Collapsing that state into kTop would
 * turn this MISMATCH into a REVIEW, and nothing else in the suite would
 * notice.
 */
        .section .rodata
.Lother_blob:
        .long   0
        .text

        .globl  bad_lea_into_callee_saved
        .type   bad_lea_into_callee_saved, @function
bad_lea_into_callee_saved:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        leaq    .Lother_blob(%rip), %rbx
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   bad_lea_into_callee_saved, .-bad_lea_into_callee_saved

/* ---------------------------------------------------------------- */
/*
 * The other spelling of the same guard, and the harder half of it.
 *
 * Two things differ from good_switch_table above. The branch is `jbe`,
 * which jumps *into* the dispatch rather than away from it, so the bound
 * belongs to the taken edge and not to the fall-through. And the compare
 * is on %dil -- eight bits of an argument register, whose upper 56 bits
 * the psABI leaves undefined -- so nothing lets the guard be promoted to
 * a fact about %rdi at the branch. It has to ride along as a proven,
 * width-qualified fact until the `movzbl %dil,%eax` reads exactly the
 * bits it covered and zero-extends them, which is what makes it a bound
 * on all of %rax, which is what the table load indexes with.
 *
 * Blessed only if all of that works; a lost guard leaves an unresolved
 * indirect jump and unwalked case bodies instead.
 */
        .section .rodata
        .align  4
.Lswitch_jbe_table:
        .long   .Lswitch_jbe_case0-.Lswitch_jbe_table
        .long   .Lswitch_jbe_case1-.Lswitch_jbe_table
        .long   .Lswitch_jbe_case2-.Lswitch_jbe_table
        .text

        .globl  good_switch_table_jbe
        .type   good_switch_table_jbe, @function
good_switch_table_jbe:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        cmpb    $2, %dil
        jbe     .Lswitch_jbe_dispatch
        movl    $0, %eax
        jmp     .Lswitch_jbe_out
.Lswitch_jbe_dispatch:
        movzbl  %dil, %eax
        leaq    .Lswitch_jbe_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        notrack jmp *%rdx
.Lswitch_jbe_case0:
        movl    $10, %eax
        jmp     .Lswitch_jbe_out
.Lswitch_jbe_case1:
        movl    $20, %eax
        jmp     .Lswitch_jbe_out
.Lswitch_jbe_case2:
        movl    $30, %eax
.Lswitch_jbe_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_switch_table_jbe, .-good_switch_table_jbe

/* ---------------------------------------------------------------- */
/*
 * The strict half of the same fork: `jb` puts the in-range case at
 * `index < 3`, i.e. a bound of 2, on the taken edge. Getting the
 * off-by-one wrong here sizes the table at 3 or 1 entries instead of 3,
 * which shows up as an unwalked case body or a target read past the
 * table's end.
 */
        .section .rodata
        .align  4
.Lswitch_jb_table:
        .long   .Lswitch_jb_case0-.Lswitch_jb_table
        .long   .Lswitch_jb_case1-.Lswitch_jb_table
        .long   .Lswitch_jb_case2-.Lswitch_jb_table
        .text

        .globl  good_switch_table_jb
        .type   good_switch_table_jb, @function
good_switch_table_jb:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        movl    %edi, %eax
        cmpl    $3, %eax
        jb      .Lswitch_jb_dispatch
        movl    $0, %eax
        jmp     .Lswitch_jb_out
.Lswitch_jb_dispatch:
        leaq    .Lswitch_jb_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        notrack jmp *%rdx
.Lswitch_jb_case0:
        movl    $10, %eax
        jmp     .Lswitch_jb_out
.Lswitch_jb_case1:
        movl    $20, %eax
        jmp     .Lswitch_jb_out
.Lswitch_jb_case2:
        movl    $30, %eax
.Lswitch_jb_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_switch_table_jb, .-good_switch_table_jb

/* ---------------------------------------------------------------- */
/* Same shape, but one case body pushes a register without updating the
 * CFI -- the stale CFI this whole feature exists to catch, now reachable
 * only through a resolved switch table. */
        .section .rodata
        .align  4
.Lswitch_bad_table:
        .long   .Lswitch_bad_case0-.Lswitch_bad_table
        .long   .Lswitch_bad_case1-.Lswitch_bad_table
        .text

        .globl  bad_switch_table_case
        .type   bad_switch_table_case, @function
bad_switch_table_case:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        movl    %edi, %eax
        cmpl    $1, %eax
        ja      .Lswitch_bad_default
        leaq    .Lswitch_bad_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        jmp     *%rdx
.Lswitch_bad_case0:
        movl    $10, %eax
        jmp     .Lswitch_bad_out
.Lswitch_bad_case1:
        pushq   %rbx
        movl    $20, %eax
        popq    %rbx
.Lswitch_bad_default:
.Lswitch_bad_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   bad_switch_table_case, .-bad_switch_table_case

/* ---------------------------------------------------------------- */
/* Same table-load shape, but with no cmp/ja bound guarding the index --
 * must stay REVIEW rather than being resolved on a guess at some assumed
 * bound. */
        .section .rodata
        .align  4
.Lswitch_review_table:
        .long   .Lswitch_review_case0-.Lswitch_review_table
        .long   .Lswitch_review_case1-.Lswitch_review_table
        .text

        .globl  review_switch_table_unguarded
        .type   review_switch_table_unguarded, @function
review_switch_table_unguarded:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        movl    %edi, %eax
        leaq    .Lswitch_review_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        jmp     *%rdx
.Lswitch_review_case0:
        movl    $1, %eax
        jmp     .Lswitch_review_out
.Lswitch_review_case1:
        movl    $2, %eax
.Lswitch_review_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   review_switch_table_unguarded, .-review_switch_table_unguarded

/* ---------------------------------------------------------------- */
/*
 * Cross-FDE verification of jump-out edges: when an unconditional jump (or
 * a resolved switch-table entry) leaves this FDE for an address covered by
 * some *other* FDE, the state is checked against that FDE's own declared
 * row instead of being guessed at via the tail-call ABI convention. This
 * is the shared target for the next two fixtures: no symbol of its own
 * (playing the role of a `.cold` fragment reached only by a jump), and its
 * first row is deliberately not the tail-call-compatible CFA-8 -- %rbx is
 * already spilled and the frame is only half torn down, exactly the shape
 * a jump into a `.cold` fragment has.
 */
.Lcold_fragment_target:
        .cfi_startproc
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        movl    $1, %eax
        popq    %rbx
        .cfi_def_cfa_offset 8
        .cfi_restore %rbx
        ret
        .cfi_endproc

/* A jump to .Lcold_fragment_target whose state genuinely matches what it
 * declares (%rbx spilled, CFA at rsp+16) -- not tail-call-ABI-compliant,
 * but correctly verified against the target FDE instead of only earning a
 * REVIEW the way the old ABI-only heuristic would. */
        .globl  good_jump_to_cold_fragment
        .type   good_jump_to_cold_fragment, @function
good_jump_to_cold_fragment:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        movl    %edi, %eax
        jmp     .Lcold_fragment_target
        .cfi_endproc
        .size   good_jump_to_cold_fragment, .-good_jump_to_cold_fragment

/* Same target, but the jump happens before %rbx is actually spilled -- the
 * state genuinely contradicts .Lcold_fragment_target's declared row, which
 * the old heuristic could not have caught (rsp not at CFA-8 was only ever
 * a REVIEW for a tail call) but the cross-FDE row comparison reports as a
 * real MISMATCH. */
        .globl  bad_jump_to_cold_fragment
        .type   bad_jump_to_cold_fragment, @function
bad_jump_to_cold_fragment:
        .cfi_startproc
        movl    %edi, %eax
        jmp     .Lcold_fragment_target
        .cfi_endproc
        .size   bad_jump_to_cold_fragment, .-bad_jump_to_cold_fragment

/* A jump whose target has no FDE at all (unlike .Lcold_fragment_target
 * above) -- the fallback ABI-based tail-call check still applies here,
 * unchanged, and still only REVIEWs since rsp isn't at CFA-8. */
.Lno_fde_target:
        ret

        .globl  review_tail_call_no_target_fde
        .type   review_tail_call_no_target_fde, @function
review_tail_call_no_target_fde:
        .cfi_startproc
        pushq   %rbx
        .cfi_def_cfa_offset 16
        .cfi_offset %rbx, -16
        movl    %edi, %eax
        jmp     .Lno_fde_target
        .cfi_endproc
        .size   review_tail_call_no_target_fde, .-review_tail_call_no_target_fde

/* ---------------------------------------------------------------- */
/*
 * The same cross-FDE verification, reached through a resolved switch table
 * instead of a direct jump: one case is a shared fragment outside this
 * FDE's own range (again playing the role of a `.cold` case shared across
 * functions), and it is checked against that fragment's declared row.
 */
.Lswitch_cold_target:
        .cfi_startproc
        .cfi_def_cfa_offset 16
        movl    $20, %eax
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc

        .section .rodata
        .align  4
.Lswitch_cold_table:
        .long   .Lswitch_cold_case0-.Lswitch_cold_table
        .long   .Lswitch_cold_target-.Lswitch_cold_table
        .text

        .globl  good_switch_table_into_cold
        .type   good_switch_table_into_cold, @function
good_switch_table_into_cold:
        .cfi_startproc
        subq    $8, %rsp
        .cfi_def_cfa_offset 16
        movl    %edi, %eax
        cmpl    $1, %eax
        ja      .Lswitch_cold_out
        leaq    .Lswitch_cold_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        jmp     *%rdx
.Lswitch_cold_case0:
        movl    $10, %eax
.Lswitch_cold_out:
        addq    $8, %rsp
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   good_switch_table_into_cold, .-good_switch_table_into_cold

/* Same shape, but the CFA is not adjusted before the dispatch, so the
 * state at the jump contradicts .Lswitch_cold_target's declared row. */
        .section .rodata
        .align  4
.Lswitch_cold_bad_table:
        .long   .Lswitch_cold_bad_case0-.Lswitch_cold_bad_table
        .long   .Lswitch_cold_target-.Lswitch_cold_bad_table
        .text

        .globl  bad_switch_table_into_cold
        .type   bad_switch_table_into_cold, @function
bad_switch_table_into_cold:
        .cfi_startproc
        movl    %edi, %eax
        cmpl    $1, %eax
        ja      .Lswitch_cold_bad_out
        leaq    .Lswitch_cold_bad_table(%rip), %rcx
        movslq  (%rcx,%rax,4), %rdx
        addq    %rcx, %rdx
        jmp     *%rdx
.Lswitch_cold_bad_case0:
        movl    $10, %eax
.Lswitch_cold_bad_out:
        ret
        .cfi_endproc
        .size   bad_switch_table_into_cold, .-bad_switch_table_into_cold

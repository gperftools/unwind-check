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
/* A leaf that touches nothing. The CIE's initial row is already right. */
        .globl  good_leaf
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
/* An indirect jump: this version does not resolve jump tables. */
        .globl  review_indirect_jump
        .type   review_indirect_jump, @function
review_indirect_jump:
        .cfi_startproc
        testl   %edi, %edi
        je      .Lrij_out
        jmp     *%rsi
.Lrij_out:
        ret
        .cfi_endproc
        .size   review_indirect_jump, .-review_indirect_jump

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

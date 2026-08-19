# Binary .eh_unwind checker

See ../backtrace-test/AGENT.md and ../backtrace-test/doc/binary-unwind-analysis.adoc

## Goal for first iteration

* x86-64, Linux (elf etc), GNU only for now.
* using bazel
* using capstone-engine (https://www.capstone-engine.org/)
**  use libcapstone-dev installed locally. No need to invent special bazel integration, yet
* C++ 20; with abseil-cpp; modified Google c++ style (like in the backtrace-test project referred above)
* "stealing" i.e. copying code from backtrace-test is allowed (e.g. for eh-frame-reader perhaps). But prefer abseil bits for e.g. stuff like FunctionRef or CHECK. Yes copying is suboptimal (code divergence), but okay for now.
** in any case don't make _any_ modifications outside of this directory or /tmp

Main philosophy: bless all easy cases. Flag anything wrong or beyond available heuristics for human to review (with light diagnostics why we're failing to bless)

The main binary is given ELF binary (.so or normal). It checks .eh_frame stuff. Fails if it is not there. Then for each FDE do checks.

* bounds check FDE range (pc range) against executable PT_LOADs
* Do an abstract interpretation as described in the doc above and try to "prove" the code covered by FDE is correct, w.r.t. matching instructions and CFI.

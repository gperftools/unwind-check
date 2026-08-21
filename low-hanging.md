A set of "trivial"/low-hanging-fruit changes. How to use it. Pick
_one_ incomplete item. Consult AGENT.md for general context. Work on
the selected item, get it "done", ensure that all the tests updated
(when necessary) and all pass. AGENT.md updated and so
on. Then mark item as done (e.g. "* (DONE)" ) and git commit.

If the selected item is too confusing/impossible/wrong. Mark it as
(SKIP) and don't select it again.

* (DONE) remove references to switch-tables plans in comments. Those plans
  are obsolete and files are gone (double check and remove if
  necessary).

* Disassembler::Text should return absl::StatusOr (zydis formatter may fail
  for whatever reason).

* Disassembler::DecodeOne should probably not use ptr to itself and
  risk clobbering instr_ after unrelated decodes (e.g. in
  ResolveJumpTable etc). Have it decode into &out parameter and
  returns true/false. Rename it as well into Decode to avoid any
  confusion.

* in fde-checker.cc pending_pushes stuff is wrong (decrement instead
  of drop in the drain loop). just make hash of addr -> bool
  instead. and keep the entries for efficiency, but set to false on
  dequeue

* consider some sort of reserve call for all kinds of containers in
  the Check. Slight efficiency win. Just give them few K of capacity.

* double check if say storing {x,y,z}mm field over set of slots is
  clobbring them. Probably not. Make sure we clobber the slots from
  wide writes like these.

* StrFormat explicitly doesn't need size prefixes since it does C++
  magic and knows exact argument type. Like Go. So drop those 'll'-s
  and explicit casts all over the code when StrFormat-ting.

* DWARFRegOf should not be linear scan

* various reg args, e.g. ReadRead, DWARFRegOf should perhaps be of
  relevant zydis type: ZydisRegister. It is nice dense type btw with
  ZYDIS_REGISTER_MAX_VALUE available

* AbsState slots should be btree not std::map

* create ZydisFormatter stuff once (new into static variable)

* add assert()-s for stuff like accessing ConstValue on the AbsVal
  that isn't kConst. This should not "pollute" any code other then those
  accessor methods. So everything is still relatively readable.

* SetReg should automagically detect update of RSP and clobber read
  zone etc. (Then avoid checks of rsp and calls to DropDeadSlots when updating
  rsp in Transfer)

* Transfer() Handling of ADD/SUB addition/subtraction should be
  unsigned (compilers like to screw up the signed overflows)

* around syscall and related instructions. Same for e.g. int $80 or
  whatevs. Make sure we conservately clobber registers. Over-clober is
  better than under-clobber, but e.g. important regs like RSP probably
  worth doing right.

* replace <Various>::ToString() with AbslStringify

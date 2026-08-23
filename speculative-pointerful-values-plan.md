# Speculative: pointerful, backend-agnostic values

Status: **pure speculation, not a plan of record.** Nothing here should be
acted on while the large abstract-state refactor is under review — this is a
brainstorm transcript, written down so the ideas survive even if this
particular thread of thought doesn't get picked back up for a long time.

## 1. The problem this is about

The abstract-state values used during the dataflow walk get copied around a
lot ("all over," per the observation that kicked this off). CPU cost of that
isn't a real concern for this tool, but it's a natural itch given the
maintainer's background (gperftools), and it's worth a real design pass
rather than dismissing it. The question: could we make these values
immutable, heap-allocated, and reference-semantics (a pointer/handle rather
than a copied value), and if so, what's the cheapest way to manage their
lifetime?

Three lifetime-management strategies were on the table from the start:

1. **Refcounting** — non-atomic, since the tool is single-threaded. No
   `std::shared_ptr`/atomics overhead.
2. **A garbage collector** — off-the-shelf, conservative, since this is a
   batch/offline tool free to pay some memory overhead for simplicity.
3. **Arena allocation** — bump-allocate per some natural scope (e.g. per
   function/FDE, matching how the tool already processes one function at a
   time), never individually free, drop the whole arena at scope exit.

## 2. GC survey

### Boehm GC (bdwgc) — the obvious first candidate

- **Not on the Bazel Central Registry.** Checked directly:
  `registry.bazel.build/modules/bdwgc` and `.../boehm-gc` both 404, and the
  module list has no gc/boehm/bdwgc entry. No `bazel_dep` shortcut.
- Upstream itself has **no Bazel support** anywhere (CMake, autotools,
  `Makefile.direct`, an experimental Zig build — nothing else).
- **The actually-convenient path**: this project already has precedent for
  *not* bazel-integrating a C dependency — Zydis is linked bare via
  `-lZydis -lZycore` against the system `libzydis-dev` package, per
  `AGENT.md`. Boehm is packaged the same way (`libgc-dev` on
  Debian/Ubuntu). `apt install libgc-dev`, `-lgc`, `#include <gc/gc.h>` — no
  new bazel plumbing needed. This is a stronger argument for Boehm than
  almost anything else raised in this whole conversation: it fits the
  project's own established pattern for exactly this kind of dependency.
- Caveats: conservative stack/heap scanning (treats any pointer-shaped bit
  pattern as a possible root — usually harmless here, just delays
  collection); whole-process singleton collector (fine for a single-purpose
  batch binary); call `GC_INIT()` explicitly at `main()` even though many
  platforms auto-init.

### Alternatives surveyed and why they don't win

| Project | Verdict |
|---|---|
| [Ravenbrook MPS](https://github.com/Ravenbrook/mps) | Real, mature (30 years, BSD-2, production use in Open Dylan), incremental/generational, has an "ambiguous roots" pool for conservative scanning. But its API (arenas/pools/formats) is built for *writing a language runtime*, not dropping into an existing C++ tool. Overkill. Not on BCR. |
| [ivmai/tinygc](https://github.com/ivmai/tinygc) | Written by Ivan Maidanski, bdwgc's *current* upstream maintainer — tempting on "trust the author" grounds. **Ruled out on investigation**: its own README says "TinyGC is NOT designed for speed" — it's an embedded/8-16-bit fallback for when real Boehm can't even be ported, explicitly meant for debugging/testing/benchmarking as a temporary swap-in, not for actual use. 9 commits total, origins ~2006–2010 out of the JCGO project, no evidence of ongoing hardening. Ivan's care went into small-footprint API-compatibility, not speed or battle-testing. Doesn't fit "fast and robust." |
| [GJDuck/GC](https://github.com/GJDuck/GC) | Modern, lightweight (<1000 lines, vendorable directly into source), reserves a huge virtual address range up front, already single-threaded (matches this project). Real disqualifier: **no automatic root discovery** — roots must be registered manually, unlike Boehm/tgc's automatic stack scanning. That's a genuine integration cost, not a drop-in. |
| [orangeduck/tgc](https://github.com/orangeduck/tgc) | Single-header, ~500 lines, mark-and-sweep, automatic conservative stack scanning, destructors supported. Simplest "just works like Boehm" option to vendor. Toy-grade maturity — fine for a spike, not for something to rely on long-term. |
| [mkirchner/gc](https://github.com/mkirchner/gc) | Similar niche to tgc, "simple, zero-dependency GC for C." No strong reason to prefer over tgc. |

**Conclusion on plain GC**: Boehm remains the only serious off-the-shelf
candidate, on the strength of maturity plus the `libgc-dev` shortcut. Nothing
else in the survey clears the bar of "proven, fast enough, still
maintained" simultaneously — tinygc and GJDuck/GC come closest but each fails
on a different axis (speed-not-a-goal; manual roots).

## 3. Arena and refcounting: off-the-shelf building blocks

### Arenas

- **`google::protobuf::Arena` is public API**, not internal-only, and
  behaves like the internal-Google pattern remembered from experience:
  `arena.Create<T>(args...)` is a pure bump allocation for trivially
  destructible `T` (no bookkeeping at all), and automatically registers the
  destructor to run at arena teardown for non-trivial `T` (`OwnDestructor<T>`
  under the hood). No `.proto`-generated messages required — works on
  arbitrary types.
  - protobuf **is on BCR** (`bazel_dep(name = "protobuf", version = ...)`,
    ~70 versions up to 36.0), and it's built on abseil, which this project
    already depends on — so pulling it in just for `arena.h` isn't as heavy
    a dependency addition as it might sound.
  - Caveat: worth timing a `bazel build` with it pulled in, since the full
    protobuf target graph might be heavier to build than the runtime cost
    would suggest, independent of whether that runtime cost is fine.
- Smaller/hobbyist standalone arena allocators exist (`gaailiunas/arena-alloc`,
  `tsoding/arena`, `dillonhuff/arena_allocator`, etc.) — mentioned for
  completeness, none has protobuf's mileage, worth reaching for only if
  pulling in even the arena-only slice of protobuf turns out to be
  unpalatable.

### Refcounting

- **`boost::local_shared_ptr<T>`** — the non-atomic sibling of
  `shared_ptr`. Same API/ownership semantics, plain (non-atomic)
  increment/decrement on the control block. Exactly the "refcounting but
  skip the atomics since single-threaded" ask.
- **`boost::intrusive_ptr<T>`** — pushes the count into the object itself
  via ADL (`intrusive_ptr_add_ref`/`_release`), avoiding the separate
  control-block allocation `shared_ptr`/`local_shared_ptr` need (one heap
  allocation per object instead of two). Probably the tighter fit if
  objects are already arena- or otherwise custom-allocated, since there's
  no separate control block to place at all.

## 4. A build-time-selectable memory-model abstraction

The idea floated: design a small abstraction that can be configured at
build time to back onto GC, refcounting, *or* arena allocation, with the
rest of the codebase written once against a uniform interface.

**Prior art to actually look at if this gets picked back up**: Blink/V8's
Oilpan (`cppgc`) — `GarbageCollected<T>`, `Member<T>` (in-heap reference),
`Persistent<T>` (stack/global root). This project's version would be
strictly simpler since single-threaded means no write barriers at all
(Boehm being conservative and non-moving sidesteps the need for barriers
that a real tracing/moving GC like Oilpan requires).

### The four things that need abstracting

```cpp
// mem.h — the only header that changes per backend

template <class T> using Ptr = /* backend-specific */;

template <class T, class... Args>
Ptr<T> MakeObj(Args&&... args);

template <class T> using Vec = std::vector<T, /* backend allocator */>;
// (and Str, Map, etc., if variable-length/shared substructures need it)

class Scope { /* RAII: "this batch of allocations dies together" */ };
```

**GC backend** — `Ptr<T>` is just `T*`, no wrapper at all:
```cpp
template <class T> using Ptr = T*;
template <class T, class... Args>
Ptr<T> MakeObj(Args&&... args) {
  return new (GC_MALLOC(sizeof(T))) T(std::forward<Args>(args)...);
}
```
`Scope` is a no-op (maybe a `GC_gcollect()` hint at boundaries).

**Arena backend** — also `T*`, arena owns lifetime:
```cpp
template <class T> using Ptr = T*;
template <class T, class... Args>
Ptr<T> MakeObj(Args&&... args) { return current_arena().Create<T>(args...); }
```
`Scope` is the real thing — constructs/destroys the arena.

**Refcount backend** — the only one where `Ptr<T>` isn't a bare pointer:
```cpp
template <class T> using Ptr = boost::intrusive_ptr<T>;
template <class T, class... Args>
Ptr<T> MakeObj(Args&&... args) { return Ptr<T>(new T(std::forward<Args>(args)...)); }
```
`Scope` is a no-op.

**Key observation**: GC and arena collapse to the identical representation —
the only real difference between them is what tears memory down and when.
Two of the three "modes" cost nothing at the type level; the whole exercise
is really about whether refcounting's non-trivial pointer type stays
source-compatible with the other two, which `intrusive_ptr`'s operator
overloads make true for free.

### The sharp edge: hidden allocations underneath

If a state object contains a `std::vector`/`std::string`/`absl::btree_map`
with a heap-owned buffer, and the GC backend is built via *surgical*
`GC_MALLOC` calls only at `MakeObj` sites (not full malloc/new redirection),
that inner buffer is allocated by plain `malloc`/`new` and is invisible to
the collector as something to *reclaim* — nothing ever frees it, pure leak.

Two ways this is normally solved, and *both are real, standard, bdwgc
features* (not hacks):

1. **`gc_allocator<T>`/`gc_cpp.h`** — STL-compatible allocator, route
   individual containers through it: `std::vector<T, gc_allocator<T>>`.
2. **Whole-process malloc/new redirection** — the "let it manage the entire
   heap" mode the maintainer expected initially:
   - `REDIRECT_MALLOC` is a **compile-time bdwgc build option** that
     redirects `malloc`/`calloc`/`realloc`/`free` process-wide to
     `GC_malloc`/`GC_realloc`/`GC_free`. Real, standard, not a hack — but
     it's a property of *how bdwgc itself was built* (Debian's
     `libgc-dev` almost certainly isn't built this way by default), and
     it's process-wide, so it affects every linked-in library the same way
     tcmalloc taking over global `malloc`/`free` does (same class of risk,
     familiar territory from the gperftools side).
   - **Simpler and sufficient on this platform**: just override global
     `::operator new`/`::operator delete`. This is `gc_cpp.h`'s actual
     documented default behavior — link `-lgccpp` and it overrides global
     new/delete unless you opt out (linking `gctba` instead, or defining
     `GC_NEW_ABORTS_ON_OOM`/similar). No malloc redirection needed at all.
     Since `std::allocator` (and hence `std::vector`, `std::string`'s heap
     path, `std::map`, protobuf/abseil containers) all ultimately call
     `::operator new`, this one override sweeps essentially all C++-level
     allocation into GC-managed memory transparently. The
     MSVC-specific pain around this (per-DLL CRT heaps, debug-heap hooks)
     is a non-issue here — GNU/Linux amd64, one binary, one CRT, one
     libstdc++, fully well-defined.
   - **Remaining gap either way**: anything that calls `malloc()` directly
     rather than via C++ `new` (a plain C library linked in — Zydis is the
     one candidate here) bypasses an operator-new-only override.
     Worth checking whether Zydis does any internal heap allocation at all,
     or is purely stack-buffer-driven from the caller's side (suspected the
     latter — decode results go into a caller-provided struct — which would
     make this a non-issue in practice).
3. **Known quirk regardless of which override path is used**:
   `std::vector`'s `end()` iterator points one-past-the-last-element, which
   can alias into the *start* of the next heap block. Conservative scanning
   sees that bit pattern as a plausible pointer into that block and keeps it
   alive spuriously. Not a correctness problem (a conservative GC never
   frees something live), just extra retention slop — bdwgc's own
   integration notes flag `std::vector` by name for this reason.

### The other discipline this forces

`Ptr<T>`'s destructor must never be relied on for anything except memory
reclamation — no "release a lock," no "log on death," no ordering
assumptions. Automatically true under GC and arena builds (destructors of
freed-later-or-never-individually-freed objects don't run predictably, or
at all); if the refcount build is the only one where a stray side-effecting
dtor happens to "work," it becomes a landmine the day someone rebuilds
under GC or arena. Worth a `static_assert` or lint at `MakeObj` call sites
to catch this early.

### A bonus property, if this is ever built

Three independently-testable memory models of the same logic, for free.
Refcount+ASan is the strictest for catching genuine lifetime bugs (a
dangling `Ptr<T>` shows up as a UAF immediately); GC is the most forgiving
(masks a lot of would-be bugs by never freeing early) and closest to the
speed target; arena sits in between. Running the suite under all three (or
refcount+ASan in CI, GC in the perf-sensitive path) turns "which backend" into
a differential-testing tool rather than a one-time decision to get right
upfront.

## 5. The specific container problem: `absl::btree_map` and arenas

Starting point: the abstract state stores stack slot values in
`absl::btree_map<int64_t, AbsVal> slots` (this is real, current code —
`abs-state.h:258`), and slots get built up/torn down as the walk proceeds.
Can this "embrace" an arena?

- **Mechanically yes**: `absl::btree_map<Key, Value, Compare, Alloc>` takes
  a real allocator template parameter (`Alloc` defaults to
  `std::allocator<std::pair<const Key,Value>>`; supplying a custom one
  requires also naming `Compare` explicitly since it's positional). Plug in
  an arena allocator whose `deallocate()` is a no-op and every btree node
  comes from the arena.
- **But this does not make the type trivially destructible**, and that
  matters for the `protobuf::Arena::Create<T>` fast path specifically.
  `is_trivially_destructible_v<T>` is a *structural* property — does `T`
  (or any member/base) declare its own destructor — not a behavioral one.
  `absl::btree_map`, like `std::vector`/`std::map`, always declares its own
  destructor (it has to walk live elements and call `deallocate`,
  regardless of what that allocator actually does at runtime). So
  `is_trivially_destructible_v<btree_map<K,V,Compare,ArenaAlloc>>` is
  `false` no matter how "no-op" the allocator is, and any outer struct
  containing that btree as a member inherits non-trivial destructibility
  transitively. `Arena::Create<T>` checks exactly this trait to decide
  whether to skip `OwnDestructor` registration — so any arena-allocated
  object holding a btree member gets registered, allocator notwithstanding.
- **The only way to dodge registration entirely**: step below the
  STL/absl container abstraction — `Arena::CreateArray<T>(arena, n)` gives
  a raw `T*` with no wrapping class, hence nothing to declare a destructor.
  A struct of `{T* data; size_t size;}` sitting inline *is* trivially
  destructible. Costs dynamic growth and btree's log-n lookup, but for
  build-once immutable data, a flat sorted array + binary search is often a
  wash or a win over a btree anyway (better cache locality, no per-node
  overhead), and is genuinely trivial.
- **Important reassurance, independent of the above**: registering a
  destructor is a one-time cost paid *at construction* (a small bookkeeping
  node in the arena's cleanup list, one indirect call at teardown). It does
  **not** make copies of a `Ptr<T>` to that object expensive — those stay a
  plain pointer copy regardless. So this only matters if the
  btree-containing field is constructed very frequently (many short-lived
  arena objects, each paying registration), not if it's just held and
  copied around a lot. Worth profiling before assuming the registration
  cost is worth designing around.

## 6. The better answer: port the existing persistent-btree demo

Rather than fighting `absl::btree_map` into arena-friendliness, there's an
existing hand-written persistent (immutable, path-copying) B-tree at
`~/src/gperftools-demo/suffix-btree-persistent.cc` that's a much closer fit,
architecturally, to begin with.

### Why it's already close to the right shape

- `Node` is a **raw fixed-size buffer** (`alignas(std::string_view) char
  storage[kInternalSize]`) with placement-new, not a wrapped STL container.
  Leaf and internal nodes share one size class deliberately, which is a
  simplification for allocation, not an oversight.
- The one backend-sensitive piece is fully isolated in `NodePtr` — a
  non-atomic intrusive-refcounted smart pointer, immutable, non-null. All
  algorithm code (`Rec`, `SplitLeaf`/`SplitInternal`, `TryFastPath`,
  `Validate`, `MakeInternal`/`MakeLeaf`) only ever talks through `NodePtr`'s
  `->`/`*`/`.Get()` and span accessors — never assumes refcounting directly
  except in one place (below).

### What ports over cleanly per backend

- **Refcount backend**: this demo *is* that backend already, close to
  verbatim.
- **GC backend**: `Ptr<Node>` collapses to bare `Node*`. `Node`'s custom
  destructor (whose only job is walking children to decref them) can be
  deleted outright — with nothing to refcount, `Node` becomes trivially
  destructible by construction. Bonus: this raw-storage layout is
  *especially* good for Boehm, because conservative scanning doesn't need
  type descriptors at all — it just scans the allocated block's raw bytes
  for pointer-shaped values, so the `NodePtr`s embedded in `storage[]` get
  traced automatically with zero layout work.
- **Arena backend**: same trivial-dtor collapse as GC; `new Node(...)`
  becomes `Arena::CreateArray<char>`-style raw bytes (or a dedicated arena
  `Allocate(size)`) with placement-new on top, again no `OwnDestructor`
  registration needed.

### What is *not* a mechanical port

1. **`TryFastPath`'s `refcount == 1` check is intrinsically
   refcounting-only.** It's the optimization that lets an insert mutate a
   child pointer in place when the whole path to the root is uniquely
   owned, instead of rebuilding the path — per the demo's own comment,
   this is what makes it "roughly competitive with imperative, polished
   abseil btree code." GC and arena backends have no cheap way to prove
   unique ownership — there's no refcount to read — so this fast path
   simply doesn't exist for them; every insert takes the full
   rebuild-the-path-to-root cost under those two backends. This is a real,
   knowing trade-off to make, not just plumbing, if this ever gets built:
   either accept slower inserts under GC/arena, or find some other
   (non-free) way to detect uniqueness for those backends.
2. **Arena backend has a memory-growth wrinkle specific to a persistent
   structure.** Every insert builds a new O(log n) chain and abandons the
   old one. Refcounting/GC reclaim the abandoned nodes continuously as
   things proceed. A bulk arena reclaims nothing until the *entire* arena
   is torn down — so if many inserts happen within one function's/one
   arena's scope, peak memory under the arena backend could be
   *materially higher* than under the other two backends for this specific
   structure. Worth a rough gut-check against expected insert volume per
   arena scope before assuming arena is a free upgrade here specifically.

### On "should be less memory than abseil btree, and no worse than any
existing 3rd-party persistent btree"

- **The core claim is correct, and not a new result.** Path-copying to
  avoid a full-container copy on update is Driscoll/Sarnak/Sleator/Tarjan's
  1989 "Making Data Structures Persistent" technique — O(1) amortized extra
  space per update for general pointer-based tree structures, provably
  near-optimal. Not reinventing something inferior.
- **Best real-world comparison point**: LMDB's B+tree — copy-on-write,
  path-copying, decades in production for MVCC snapshot isolation. Same
  algorithm, applied to mmap'd pages instead of in-memory nodes. Being "no
  worse than" existing persistent B-trees is a low bar cleared by doing the
  standard, proven thing.
- **Caveat 1 — HAMT is a real competing option if sorted order isn't
  needed.** Persistent hash array-mapped tries (Clojure's
  `PersistentHashMap`, C++ `immer::champ`) use bitmap-indexed *sparse*
  nodes — storage sized to actual occupancy via a popcount bitmap, not a
  fixed max-width buffer. The demo's fixed `kInternalSize` per node
  (deliberate, for a uniform allocator size class) means a sparsely-filled
  node still reserves full-width storage. If nothing downstream needs
  sorted/range iteration over slot values, a HAMT could edge out this
  design on memory. (See §7 below — for this project specifically, this
  turned out to not really matter either way, for a different reason.)
- **Caveat 2 — "less memory" depends on the backend actually reclaiming
  superseded nodes.** True for refcounting/GC (nodes that fall off the tree
  each update get collected promptly, so live memory during a long update
  sequence stays close to O(depth) extra per step). **Not automatically
  true for the arena backend** — see the arena wrinkle above; across many
  updates within one arena scope, every superseded version could pile up
  simultaneously, potentially exceeding what a naive "copy the mutable
  abseil btree once per step, free the old one" approach would use.

## 7. `immer` — a library that already *is* this abstraction

[immer](https://github.com/arximboldi/immer) (Juanpe Bolívar's C++
persistent/immutable data structures library) turned out to already
implement almost exactly the build-time-selectable memory model from §4,
as a first-class, documented feature — not something to build from
scratch.

### The `memory_policy` template already covers all three backends

`immer::memory_policy<HeapPolicy, RefcountPolicy, ...>` is a template
parameter on every container:

- **Refcounting**: `refcount_policy` (atomic, thread-safe default) vs.
  **`unsafe_refcount_policy`** — literally the non-atomic,
  single-threaded-safe-only variant, already named that way in the source
  (`immer/memory_policy.hpp`).
- **GC**: ships a real `gc_heap` (`immer/heap/gc_heap.hpp`) that routes
  allocation through `GC_malloc`/`GC_malloc_atomic` — Boehm integration
  already written. Select via
  `immer::memory_policy<immer::heap_policy<immer::gc_heap>, immer::no_refcount_policy, ...>`.
  Its own docs repeat the same caveat worked out independently above:
  "destructors of contained objects will never be called" under this heap
  — the same discipline (keep contained types side-effect-free /
  effectively trivial) applies here too; using immer doesn't dodge it.
- **Arena-ish**: `free_list_heap_policy<cpp_heap>` /
  `unsafe_free_list_heap_policy<cpp_heap>` — pooled, size-classed
  allocation with a recycling free list, not true bulk-teardown arena
  semantics. Not identical to a `protobuf::Arena`-style scope, but
  `HeapPolicy` is a documented, small extension point (just needs
  `allocate`/`deallocate`) — writing a real arena-backed one is a
  contained task if this gets picked back up, not a fight with the
  library's grain.

### Caveats

- **Not on BCR** (checked directly, 404). Same story as bdwgc/MPS. But
  it's **header-only** (template library, no compiled artifact), so
  vendoring is genuinely trivial — drop the `immer/` include tree into
  `third_party/`, a five-line `cc_library(hdrs = glob(...), includes =
  ["."])`, done. Much cheaper integration than Boehm alone would have been.
- **`immer::map`/`immer::set` are CHAMP tries — unordered.** Confirmed:
  hash-bucket iteration order only, no sorted iteration, no range queries.
  So immer does not hand over a persistent B-tree/sorted-map at all — it's
  purely the HAMT branch of the design space. It would only replace the
  slots structure in the case where ordering genuinely isn't needed (see
  §8), and is not a competitor to the ported-demo-btree plan for anything
  that does need order.

## 8. Applying all this to the actual `slots` field

This is where the speculation connected back to real code rather than
staying abstract. Checked against the current implementation
(`abs-state.h:258`, `abs-state.cc:163-188`, `insn-semantics.cc:359,385`):

- `slots` is `absl::btree_map<int64_t, AbsVal>` — offset-keyed stack-slot
  values within one function's frame.
- `Slot()`/`SetSlot()` are simple point lookups/updates.
- `DropSlotsBelow(rsp_delta)` does `slots.erase(slots.begin(),
  slots.lower_bound(rsp_delta))` — an ordered prefix-erase. Called on
  *every* `CALL`, `SYSCALL`, and interrupt instruction — frequent, not a
  rare operation.

**Question raised**: does this data actually need ordered storage, or would
an unordered (hash-based, e.g. immer's CHAMP) persistent map do? Instinct
was: probably not needed, since most stack updates touch only a few (often
one) slot at a time, and `DropSlotsBelow` is the only operation that looks
like it wants order.

**The nuance worth remembering**: the instinct is right, but for a subtler
reason than "ordering doesn't matter here."

- Ordering *does* matter for `DropSlotsBelow`'s asymptotic behavior under
  persistence specifically. "Erase everything below a threshold" is a range
  operation. A sorted structure can share the whole surviving subtree by
  pointer (O(depth) touched nodes). A hash-based persistent structure has
  no equivalent — hashing scrambles key order, so there's no way to skip a
  subtree based on "these keys are all below the threshold"; every live
  entry has to be visited and tested individually — O(n) per call, on
  every single call instruction, versus O(log n + boundary) for a sorted
  structure.
- **But** `n` here (live tracked slots per one function's frame) is
  realistically single digits to maybe low double digits even in
  heavily-inlined code — bounded by how many distinct stack-resident values
  a compiler keeps CFI-relevant at once, not by function size. At that
  scale, O(n) linear-scan-and-filter and O(log n) tree navigation are both
  noise; the tree's asymptotic advantage only shows up once n reaches the
  hundreds+, which this structure almost certainly never does.
- **A third option that sidesteps the whole ordered-vs-hash question**: at
  single-digit-to-low-double-digit sizes, a flat immutable array of
  `(offset, AbsVal)` pairs — linear scan for `Slot()`/`SetSlot()`, linear
  filter-and-rebuild for `DropSlotsBelow` — likely beats *both* a persistent
  btree and a persistent HAMT outright: no pointer-chasing, no hashing, just
  a tight cache-friendly scan. Also by far the simplest thing to make
  backend-polymorphic (wrap one contiguous buffer in `Ptr<T>`), with zero
  B-tree-node-splitting logic to port.

**Before doing anything**: instrument `slots.size()` at the
`DropSlotsBelow` call sites across a representative sample of real
binaries, to confirm the single-digit assumption actually holds (including
worst-case, heavily-inlined functions). If it does, as expected, the flat
array is probably the right answer for this specific field, and the whole
btree-vs-immer detour turns out to be solving a problem this field doesn't
actually have. If some pathological function turns up with a much larger
live-slot count, that's the point to revisit whether ordering earns its
keep after all.

## 9. Where this leaves things

Nothing here is committed to. In priority order, if this gets revisited:

1. **Measure first**: instrument real slot counts (§8) before choosing any
   data structure for `slots` specifically. This might make most of the
   rest of this document moot for that field, though the general
   memory-model question (GC vs refcount vs arena) is independent of it and
   applies to whatever *does* turn out to be pointerful/shared.
2. **If a build-time-selectable memory model is still wanted for other
   state**: prototype against `immer`'s `memory_policy` (§7) rather than
   hand-rolling the `Ptr<T>`/`MakeObj` abstraction from §4 — it already
   exists, is exercised, and covers refcount + GC out of the box; only a
   real arena `HeapPolicy` would need writing.
3. **If ordered, persistent, arena/GC-friendly storage is ever actually
   needed somewhere** (i.e. §8's instrumentation finds a field where it
   does matter): port `~/src/gperftools-demo/suffix-btree-persistent.cc`
   rather than fighting `absl::btree_map` into arena-friendliness — but
   budget for the `TryFastPath` refcount-only fast path not carrying over
   to GC/arena builds, and check insert-volume-per-arena-scope before
   assuming arena wins on memory for a persistent/churny structure.
4. **Boehm GC remains the strongest plain-GC candidate** if a GC backend is
   wanted independent of immer, on the strength of the `libgc-dev`
   shortcut matching this project's existing Zydis-integration pattern
   (§2), plus the `gc_cpp.h` global-operator-new-override path (§4) being
   simpler than full malloc redirection and sufficient on GNU/Linux amd64.

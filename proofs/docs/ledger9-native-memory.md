# Ledger9 native proving storage

This proposal applies storage changes to the published `midnight-proofs` 0.8.2 source (`f5e6e16d`) consumed by Ledger9 9.1.0.1. Default proof and key encodings remain unchanged.

The goal is to reduce peak resident memory on large native proofs. Mapped
storage can trade disk I/O and latency for memory; enabling the Cargo feature
alone does not change a request's policy. The released heap prover and
verifier remain the compatibility baseline.

The same Ledger9 graph uses `midnight-circuits` 7.3.0 with `midnight-zk-stdlib` 2.4.0. The 0.8.2 source snapshot still carried circuits 7.2.3 in its workspace, which made aggregation and strict Clippy resolve two incompatible circuit types. The circuits subtree in this proposal is aligned to the published 7.3.0 crate source (crates.io checksum `79ba23314560e105bb1da33551199ae9abaa25188589d8308caddbcd8d1f3448`). Keep that release-source alignment distinct from the native storage implementation when reviewing.

The published stdlib 2.4.0 also changed seven example verifying keys. Its example code, circuit goldenfiles, and verifier-key fixtures are copied from the published crate, rather than regenerated under this optimization branch. These release changes are recorded in `zk_stdlib/CHANGELOG.md`; the native memory API does not change the released proof or key encoding.

`native-memory` is the consumer-facing feature. It includes the lower-level `disk-spill` and `mmap` features. `memmap2`, `tempfile`, and `libc` are restricted to non-Wasm targets. Wasm can compile with the umbrella feature enabled; a request for mapped storage returns `Unsupported`. The default feature set and `ProverConfig::heap()` keep the released heap path.

On a native build with the feature, a caller can create a `ProverContext` with `ProverConfig::mapped_key()` or `ProverConfig::mapped_key_and_cosets()`. Cosets spill at or above `coset_spill_floor_k` (default `k=18`); `spill_dir` selects the temporary volume. A request-local `CancelToken` is checked at prover phase boundaries. Cancelling one context does not cancel another proof, and cancellation cannot retract commitments already written.

Mapped fixed columns and spilled cosets use typed polynomial views and the common serializer. A requested spill failure is returned to the caller rather than silently falling back to an unbounded heap allocation. The mapped SRS reader validates its backing before exposing it; consumers must keep that backing immutable while mapped.

## Design and ownership

```text
serialized key -> policy-aware key init -> heap or mapped fixed columns
                                         |
parameters -----------------------------+-> prover phases -> proof transcript
request ProverContext -------------------+       |
       CancelToken ------------------------------+
                                        extended cosets: heap or temporary map
```

[`ProverConfig`](../src/config.rs) holds the requested key and coset
storage policy. [`ProverContext`](../src/plonk/context.rs) attaches that
policy and an optional cancellation token to one proof. The legacy
[`create_proof`](../src/plonk/prover.rs) entry point keeps its heap path and
result type; `create_proof_with_context` exposes storage and cancellation
errors. The stdlib offers the corresponding
[`prove_with_context`](../../zk_stdlib/src/lib.rs) path.

```rust
use midnight_proofs::config::{CancelToken, ProverConfig, ProverContext};

let cancel = CancelToken::new();
let mut policy = ProverConfig::mapped_key_and_cosets();
policy.coset_spill_floor_k = 18;
let context = ProverContext::new(policy).with_cancel(cancel.clone());
// Pass &context to context-aware key initialization and proving.
// The request owner can later call cancel.cancel().
```

| Policy | Proving key | Extended cosets | Availability |
| --- | --- | --- | --- |
| `heap()` | Heap | Heap | Default; native and Wasm |
| `mapped_key()` | Temporary native mapping | Heap | Explicit native request |
| `mapped_key_and_cosets()` | Temporary native mapping | Mapping at or above the configured `k` floor | Explicit native request |

A mapped-key request needs serialized key bytes; an initialized heap key
cannot be silently converted to mapped storage. Coset-only spill can reuse a
heap-initialized key. Below the floor, cosets stay on the heap.
[`mmap_pk.rs`](../src/plonk/mmap_pk.rs) reserves backing space before
writing and retains mappings for the lifetime of their typed views.
[`cosets.rs`](../src/plonk/cosets.rs) streams transformed polynomials into
that storage. A failed requested spill returns an error.

Universal parameters have a separate, explicitly unsafe mmap reader in
[`ParamsKZG`](../src/poly/kzg/params.rs). It checks companion layout,
bounds, and alignment before exposing typed slices. Its caller must
guarantee that no process modifies, truncates, or replaces the mapped file
while a view exists. Ledger owns this trust boundary; a mutable shared cache
does not meet it.

## Compatibility and target contract

The `native-memory` feature in [`proofs/Cargo.toml`](../Cargo.toml)
includes `disk-spill` and `mmap`; `memmap2`, `tempfile`, and `libc`
are native target dependencies. A Wasm build may enable the umbrella
feature in a unified graph, but `ProverConfig::ensure_supported()` returns
`Unsupported` for a requested native policy. Heap proving still works.
The IR, proving-key, proof, transcript, and verifier encodings do not
change with this storage choice.

`CancelToken` is shared only with its clones. Key admission and prover
phase boundaries check it; a single low-level key read is not interruptible.
Cancellation cannot undo transcript commitments already written. Discard
the transcript after any proving error, and do not resume it. Separate
requests must use separate tokens.

## Qualification

- Preserve proof and key compatibility with released 0.8.2 artifacts, including per-`k` parameters and keys.
- Check native default, native `native-memory`, Wasm default, Wasm `native-memory`, and Wasm all-features builds. Mapped policy on Wasm must return `Unsupported`.
- Verify the Ledger9 V3 TypeScript/Wasm-to-native proof exchange against exact pinned commits. The local small-circuit exchange passed; released per-`k` fixtures remain a separate gate.
- Measure high-`k` peak memory and latency in separate processes on intended native and mobile targets. A forced spill below `k=18` is a functional stress case, not evidence of memory savings.

Record source heads, target/device, policy, peak RSS, elapsed time, and disk
use for each run. The contribution can be reviewed upstream in stages:
published-source alignment, storage primitives and unsafe boundary,
context-aware API, then consumer integration. Tracking:
[ZK #5](https://github.com/betsudo/midnight-zk/issues/5) and
[Ledger #14](https://github.com/betsudo/midnight-ledger/issues/14).

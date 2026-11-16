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
// Pass &context to context-aware proving. A consumer can use
// context.config when reading a serialized proving key.
// The request owner can later call cancel.cancel().
```

| Policy | Proving key | Extended cosets | Availability |
| --- | --- | --- | --- |
| `heap()` | Heap | Heap | Default; native and Wasm |
| `mapped_key()` | Temporary native mapping | Heap | Explicit native request |
| `mapped_key_and_cosets()` | Temporary native mapping | Mapping at or above the configured `k` floor | Explicit native request |

The mapped key reader accepts serialized key bytes. The Ledger consumer
bridge rejects attempts to retroactively map an initialized heap key;
coset-only spill can reuse that heap key. Below the floor, cosets stay on
the heap.
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

`CancelToken` is shared only with its clones. The proofs crate checks it
at prover phase boundaries. Ledger's policy-aware key admission also checks
it, but a single low-level key read is not interruptible.
Cancellation cannot undo transcript commitments already written. Discard
the transcript after any proving error, and do not resume it. Separate
requests must use separate tokens.

## Qualification

- Preserve proof and key compatibility with released 0.8.2 artifacts, including per-`k` parameters and keys.
- Check native default, native `native-memory`, Wasm default, Wasm `native-memory`, and Wasm all-features builds. Mapped policy on Wasm must return `Unsupported`.
- Verify the Ledger9 V3 TypeScript/Wasm-to-native proof exchange against exact pinned commits. Local k=4/k=6 checks now use official per-`k` parameters and an independently published SDK testkit key; exact-head CI, deployed dApp key coverage, and high-`k` capacity remain separate gates.
- Measure high-`k` peak memory and latency in separate processes on intended native and mobile targets. A forced spill below `k=18` is a functional stress case, not evidence of memory savings.

Record source heads, target/device, policy, peak RSS, elapsed time, and disk
use for each run. The contribution can be reviewed upstream in stages:
published-source alignment, storage primitives and unsafe boundary,
context-aware API, then consumer integration. Tracking:
[ZK #5](https://github.com/betsudo/midnight-zk/issues/5) and
[Ledger #14](https://github.com/betsudo/midnight-ledger/issues/14).

## Upstream contribution slices

The merged fork head is `fb558e2e`; Ledger9 pins its source commit
`505156ec`. These are working integration references. The proofs 0.8.2
source base is the published crate's recorded commit `f5e6e16d`.
An upstream proposal needs its own reviewable series, with each row checked
against its stated parent. The hashes below map existing fork commits to
responsibilities; they are not a claim that every intermediate parent has
already passed upstream CI.

| Proposed review unit | Existing source commits | Contract to preserve |
| --- | --- | --- |
| SRS loading and mapping | `57a9671b`, `aa8934cc` | Keep the released SRS encoding; validate the companion before mapping and document the immutable trusted-file obligation. |
| Polynomial views and mapped key storage | `45ae4616`, `09ccbe7a`, `fa454600`, `18335330` | Use one owned/mapped serializer, preserve tagged key bytes, and avoid building cosets while merely loading a key. |
| Streamed cosets and bounded MSM | `15c8a545`, `bfa9383b`, `4368fc9c` | Spill only by explicit native policy, fail a required spill instead of falling back, and keep x86 and aarch64 MSM gates separately verified. |
| Request policy and stdlib API | `698f3130`, `737df6f1`, `a63bd8b5` | Preserve the heap entry point, use a request-local cancellation token, and reject native-only policy on Wasm. |
| Mapped storage error provenance | `cdbbce71` | Distinguish backing-store failure from malformed client key bytes without changing the proof or key format. |

Keep the published circuits 7.3.0 and stdlib 2.4.0 alignment
(`4952bea5`, `81cbfe23`, `505156ec`) in a separate release-integration
unit. It fixes the fork workspace's mixed circuit traits and copies the
official stdlib verifier fixtures; it is not a prover memory algorithm.
The fork CI formatter pin and local dependency revisions also stay outside
the upstream library proposal. This separation lets a reviewer assess
the unsafe mapping and memory policy without interpreting unrelated
release-source changes as new behavior.

The published 0.8.3 source (`98d1e964`) and the current upstream `main`
have a different proof/key transcript boundary. Rebase a proposed slice
onto the chosen upstream target only after its 0.8.2 Ledger9 artifact gate
is recorded; then rerun exact-head native, Wasm, serialization, proof,
and failure-path checks on that target. A passing 0.8.3 build alone does not
establish 0.8.2 key compatibility. An SRS-only 0.8.3 port would be an
incomplete proposal without the key, coset, context, and consumer gates.

The cross-repository landing order is proofs storage/context API, Ledger
provider and trait prerequisites, ZKIR V3 context adapter, then the final
Ledger consumer. The official k=4 parameter and locally generated
published-source V3 key smoke is under [Ledger PR #39](https://github.com/betsudo/midnight-ledger/pull/39).
The same PR exercises an independently published [Midnight JS testkit](https://github.com/midnightntwrk/midnight-js/tree/66096e0e35d46709ae3227349d71a7652e06422e/testkit-js/testkit-js-e2e/src/contract/compiled/counter)
Compact 0.36.1 counter key against the official k=6 parameter, including
Node/Wasm-to-native proof verification. These small circuits establish
artifact compatibility; deployed dApp key coverage and repeatable high-k
resident-memory evidence remain open. The executable acceptance gates
and proposal ownership are in [ZK #12](https://github.com/betsudo/midnight-zk/issues/12)
and [Ledger #30](https://github.com/betsudo/midnight-ledger/issues/30).

The proposed upstream PR targets, checked on 2026-11-16, are
`midnightntwrk/midnight-zk:main` (`3cff06af`) for the proofs library,
`midnightntwrk/midnight-ledger:ledger-9` (`b8f5e143`) for both Ledger units,
and `midnightntwrk/midnight-zkir:main` (`405b162f`) for the V3 adapter. The
published proofs 0.8.2 source remains the artifact baseline, not the target
branch for a new upstream PR. Before submission, refresh each upstream head,
port the slices to its APIs, and run the release-artifact and failure-path
gates on the rebased result. In particular, current ZK `main` has a newer
transcript boundary; a green build there cannot substitute for the Ledger9
0.8.2 proof/key compatibility result. If that compatibility cannot be
preserved on `main`, agree on an upstream maintenance target with its owners
before opening the proofs PR. Do not present the dependent Ledger or ZKIR
patches as standalone buildable PRs until their prerequisite APIs are
available on their target branches.

# Memory optimization port from proofs 0.8.2 to 0.8.3

This is the future upstreaming track for [betsudo/midnight-zk#5](https://github.com/betsudo/midnight-zk/issues/5). It does **not** change the released Ledger9 consumer. Ledger 9.1.0.1 and the current `ledger-9` integration use the optimized proofs 0.8.2 source at betsudo SHA `397b2424b972b3ec338722839c109f01c2fcf9f1`. This plan starts from upstream `main` `20b10959d918528e93c5482503762d3dcb889f39`, whose proofs manifest says 0.8.3. Recheck that head before implementation. Ledger8 and proofs 0.7 are out of scope.

## Compatibility boundary

Upstream's [proofs changelog](CHANGELOG.md) says #513 changed the challenge and commitment order for **every** proof; pre-change proofs no longer verify. The upstream 0.8.3 baseline reused the 0.8.2 `VerifyingKey` version byte `0x03` despite a different serialized payload and transcript representation. This local port uses `0x04` for the new VK/PK payload, so the old key format rejects at its header. The 0.8.3 `ParamsKZG` stores four affine bases (`g`, `g_lagrange`, delta, double delta), plus cached residue bases, where the 0.8.2 patched line stores two projective bases (`g`, lazily initialized `g_lagrange`). Its ordinary parameter file still writes two primary bases and proved byte-identical for one deterministic k=5 fixture in all three `SerdeFormat` modes; production SRS files remain unqualified. Treat proofs, VKs, PKs, and mmap companions as version-specific. Do not repin released Ledger9 to 0.8.3 or reuse a 0.8.2 companion.

## Patch disposition

| 0.8.2 patched commits | Disposition on 0.8.3 | Reason and gate |
| --- | --- | --- |
| `eb5cb8b6`, `8c22138e`, `f8d59793`, `1c6c3153` (SRS mapping, polynomial views, companion safety, heap keygen) | Redesign and port | `params.rs` now owns four affine bases and a residue cache. Map only immutable, layout-checked affine blocks; derive or cache secondary bases under a documented memory policy. Preserve trusted-directory, no-clobber publication and malformed/truncated companion tests. Recheck default heap keygen against #2. |
| `f3848297` (mapped proving-key loader) | Redesign and port | `ProvingKey` has new phase-0 storage and is no longer `Clone`; the old serialized-key offsets are invalid. Keep mapped views behind an explicit trusted-file API and test keygen, read, prove, and verification under heap and mapped policies. |
| `51b79fab`, `bbf1ef79`, `535dd7b9`, `1bb7f303` (streamed cosets and spill errors) | Redesign and port | The new `ProverTrace` and generic argument/logup/permutation groups replace the old fixed/advice/instance loops. Stream each required extended-domain polynomial at its new owner, keep spill files alive through evaluation, reserve blocks before mapping, and fall back to heap with an explicit warning on recoverable file failure. Inject failure at both spill stages. |
| `2ffcab7a`, `a1a8c1c2` (typed policy and request cancellation) | Port additive API | Keep the compatibility proving entry point, add explicit per-request context, and thread it through all new trace/evaluation phases. Cancel one concurrent proof without affecting another. Ledger's external ZKIR 3.2.1 and stdlib 2.4.0 currently call the compatibility entry point, so their boundary needs a separate API decision before claiming request isolation through v3. |
| `c082a96d`, `d967b2dc` (memory phases and parallel loops) | Rebase by phase, then measure | Old phase names and loops do not match 0.8.3. Instrument actual new phases and compare k/rows, peak RSS, spill bytes, and latency on the same circuit and host. Avoid a timing-only success claim. |
| `9aa3730a`, `072413ad`, `166efcfb`, `397b2424` (MSM thresholds and chunking) | Re-evaluate, do not copy thresholds blindly | Upstream now uses affine `msm_specific` and has its own fix #544. Preserve exact group results and the x86 fast-path correction from #2; benchmark the aarch64 and x86 gates before selecting them. |
| `e0386785`, `0e8de81b`, `56475e2c` (capability features and CI) | Port | Keep `mmap` and `disk-spill` opt-in, reject unsupported wasm capability requests, and run default, each feature, both features, and wasm gates at the exact new head. |

`main-patched` at `8132af48` is an older upstreaming vehicle (68 upstream commits behind this baseline), not the Ledger9 consumer. It contains related concepts but is not a sound merge base for these structural changes. Preserve it and the optimized 0.8.2 head until a separate reviewed replacement passes the gates below.

## Implementation sequence and acceptance gates

### Local implementation status

The `sync/proofs-0.8.3-memory` code branch begins with lazy materialization of the two derived affine bases (`LagrangeDelta` and `LagrangeDoubleDelta`). `ParamsKZG` now builds them on first use, while parameter generation, deserialization, and downsizing keep both caches empty. This avoids allocating those two full-size bases during an ordinary parameter read that does not use them. The serialized parameter format and commitment values are unchanged. The parameter round-trip, downsize invalidation, and both delta commitment identity tests passed. This is a first memory-policy step, **not** mmap or streamed spill. It does not qualify the new branch as a Ledger9 consumer.

The next local step adds native `mmap` and `disk-spill` capability features and a mapped **affine** `g`/`g_lagrange` storage path. The new `MDNGHTV3` companion is intentionally incompatible with the 0.8.2 projective companion. It checks magic, version, curve/layout identity, exact counts, canonical ranges, alignment and file length before constructing mapped slices. A sealed `PlainBytes` contract restricts direct byte views to the audited BLS12-381 affine layout. `read_mmap_arc` is unsafe because the caller must keep its private backing file immutable; this header is not a content digest. Publication uses a temporary file and `persist_noclobber` to avoid replacing a live inode. The ordinary `read_custom` heap path and wire format remain available.

Local gates for the affine mmap iteration: eight parameter/companion tests passed with `mmap` and with `disk-spill`; five default-feature parameter tests passed. The PLONK API test also generated and verified a proof with mapped parameters and a proving key generated from them. Default browser-Wasm `cargo check` passed using Homebrew LLVM as the C compiler for `blst`; the `mmap` Wasm check failed at this crate's intended capability error.

The next local iteration implements `disk-spill` for the 0.8.3 prover. `create_proof_with`, `keygen_pk_with`, and `ProvingKey::read_with_policy` accept a typed per-call memory policy while the old APIs remain. Advice, instance, phase-0 fixed/permutation, permutation products, lookup helper/aggregator/multiplicities, and trash extended cosets now use read-only polynomial views. A spill-configured key omits its extended fixed/permutation caches, and each needed coset is transformed and written to an unnamed reserved tempfile one polynomial at a time. A file creation or reservation failure warns and rebuilds the affected batch on the heap. The heap path retains parallel lookup transforms; the spill path serializes lookups so multiple large transformations do not overlap. Trash cosets are read in constraint-system order. The PLONK API test generated and verified proofs with a spill-configured key, a deserialized spill-configured key, and a missing spill directory fallback; the direct coset tests compare heap/spill values and check fallback. The reservation seam was fault-injected with `ENOSPC` after opening a tempfile and returned an error without exposing a mapping or leaving a named file. Both default and opt-in feature checks passed locally. This does not yet include a large-k RSS/disk/time baseline, cancellation context, external consumer migration, or current-head CI; it is not a Ledger9 consumer qualification.

The next local iteration adds `ProverContext` and a request-owned `CancelToken` to the 0.8.3 prover, with checkpoints between trace, commitment, evaluation, and opening stages. `create_proof_with_context` is additive; both the original `create_proof` and policy-only `create_proof_with` retain their signatures. The 2.4.0 stdlib source on this branch exposes an additive `prove_with_context` and keeps `prove` on its process policy. A synthetic SRS test proved and verified through both stdlib entry points and confirmed a pre-cancelled context returns `Error::Cancelled`; a concurrent low-level proof using a different context completed. A second low-level test pauses inside proof synthesis, cancels that request after `trace.start`, and asserts the next checkpoint returns `Error::Cancelled` while an independent proof using the same parameters and key completes. The focused `test_create_proof` gate passed with `dev-curves` alone and with `dev-curves,disk-spill`. This verifies in-flight cancellation between stages, but does not show interruption inside a long-running stage. The external ZKIR v3 boundary, large-k memory measurements, and current-head CI remain open for this 0.8.3 branch. The released Ledger9 consumer stays pinned to 0.8.2, so this 0.8.3 code is not yet part of that release line.

An isolated ZKIR 3.2.1 library check against this local 0.8.3 source and
Ledger9 transient-crypto 3.1.0 reached a concrete migration boundary. Cargo
needed local patches for curves, circuits, proofs, stdlib, and transient-crypto,
including the upstream Git source of proofs, plus a temporary lockfile update
from transient-crypto 3.0.0 to 3.1.0. With those patches resolved to one local
proofs 0.8.3 source, `cargo check -p midnight-zkir --lib` failed in Ledger9
transient-crypto: four uses of `MidnightVK` need the new `PCS` type parameter;
`ParamsKZG::read_custom_lazy` is absent; `verify` and `batch_verify` take an
additional `PCS` type argument; and two mmap-reader calls require an explicit
unsafe boundary (with one more warning in an unsafe function). These are the
first compiler errors, not an exhaustive port inventory. A dedicated
transient-crypto/ZKIR adapter and cross-version artifact gates are required
before considering a Ledger9 0.8.3 consumer. The released Ledger9 0.8.2 pin
remains in place. The temporary ZKIR lockfile and build target were removed
after this check.

The 0.8.3 parameter type now supports the missing seekable
`ParamsKZG::read_custom_lazy` boundary. It skips the serialized affine
Lagrange block and derives that basis from `g` only on first use; ordinary
`read_custom` and mapped companions still initialize it eagerly. `max_k` and
downsizing do not force a lazy basis, and downsizing clears all derived caches.
All three serialization modes round-tripped byte-for-byte after lazy reading;
the malformed truncated stream was rejected. Nine opt-in parameter tests, six
default-feature parameter tests, and the opt-in PLONK API proof test passed.
This restores an API expected by the local Ledger9 parameter loader but does
not yet port its other 0.8.3 stdlib and safety differences or establish a
large-k memory benefit.

The local 0.8.3 adapter stack (`midnight-proofs` `3aff69f9`, Ledger9
`transient-crypto` `c21aeb5a`, and ZKIR v3 `ead311c`) passed all 53 ZKIR
library tests and three focused heap/mmap/spill proof and cost tests after
rebasing ZKIR onto upstream `zkir-v3` `f7b433d` (3.2.1). A subsequent
Ledger9 proof-server build with those three local sources exposed the remaining
consumer boundary. After patching *all* ZKIR v3 references to the adapted local
crate, Cargo compiled v3 but failed in Ledger9's in-tree ZKIR v2 2.2.0 with 15
errors: the new stdlib requires a `PCS` generic for `MidnightPK` and `prove`,
adds an argument to `cost_model`, removes the ECC coordinate methods used by
the v2 VM, and adds `nb_arith_cols` to `ZkStdLibArch`. The focused server proof
test therefore did not run. Betsudo Ledger issue #30 already requires the v2
route to stay green; this is a future 0.8.3 consumer migration gate, not a
reason to change the released Ledger9 0.8.2 pin. Reproduce it with the local
0.8.3 proofs, stdlib, circuits, transient-crypto, and ZKIR v3 path patches and
`cargo test -p midnight-proof-server --features zkir3-context --test
zkir3_mapped_params zkir3_heap_and_mapped_params_produce_the_same_valid_proof`.

Ledger9 branch `sync/ledger9-proofs-083-v2-compat` subsequently fixed the
in-tree v2 API break and passed three fixture-free v2 proofs plus an opt-in v3
HTTP proof with forced coset spill. That run preceded the local mapped-key
port. The broader server test now compiles with the local key policy. Its first
run verified both proofs but found different bytes despite identical seeded
caller RNGs: quotient-limb blinding still drew directly from `OsRng`. The
prover now passes the caller RNG through finalisation. The Ledger9 v3 heap
versus mapped-parameter/forced-spill comparison, the policy-cache test, and
the Compact-generated v3 counter proof passed against the local branch.
This used temporary path patches for proofs, curves, circuits, stdlib and
ZKIR v3, including a patch for an external SHA3 circuit's Git-sourced proofs
dependency. It does not establish a released-package build or current-head
CI. The earlier 0.8.2 key mapper's forged `Vec` views were not copied into
0.8.3.

The opening-query path now carries read-only `PolynomialView` descriptors
through both KZG and fflonk while preserving `ProverQuery::new` for owned
callers. The phase-0 coefficient group, `fixed_values`, and `sigmas.values`
have owned-or-mapped storage, with typed views for lookup, trash, and
permutation reads. Keygen and
`read_with_policy` now honor `ProverConfig::mapped_key()` and
`mapped_key_and_cosets()`; the ordinary heap policy remains the default.
The PLONK API test generates and verifies with mapped key columns, checks
identical serialization, rejects a wrong public statement, and checks that a
missing mapping directory rejects the key load. The mapped read now reserves
storage and deserializes fixed and permutation Lagrange columns one at a time
into read-only mappings. It checks serialized counts and row lengths against
the verifying key before accepting each batch; a focused test covers the
round trip, wrong counts and lengths, and truncated input. The mapped read
also transforms each fixed and permutation column to phase-0 coefficient form
and writes it to a reserved read-only mapping before processing the next
column. The PLONK API gate verifies byte-identical seeded proofs from the
generated mapped key, deserialized mapped keys with and without coset spill,
and a deserialized heap key; it also verifies mapped FFLONK keys. Keygen still
builds its Lagrange inputs on the heap, and key loading still creates three
extended-domain Lagrange
polynomials on the heap. Load-time peak memory is therefore not yet proven
to be bounded by one column. Reservation fault injection, load/proof RSS and
disk measurements, released dependency alignment, broader Ledger9 consumer
gates, and current-head CI remain before qualification.

The local `sync/proofs-083-phase0-stream` build gate passed native
`cargo check -p midnight-proofs` with default features, `mmap`, and
`disk-spill`. Browser Wasm `wasm32-unknown-unknown` passed with default and
no-default features using Homebrew LLVM 20.1.6 as `CC` for `blst`. Opting
into `mmap` or `disk-spill` on Wasm failed only at the crate's intended
capability `compile_error!` declarations. This checks the proofs crate at a
local head. `cargo check -p midnight-zk-stdlib --target
wasm32-unknown-unknown` also passed at this head and resolved
`midnight-proofs` from this workspace. These checks do not replace
exact-head CI.

The external ZKIR v3 browser consumer also passed `cargo check --locked
-p midnight-zkir-wasm --target wasm32-unknown-unknown` with ZKIR adapter
`ead311c`, Ledger transient-crypto adapter `c21aeb5`, and this proofs
branch at `a4438343`. The disposable build patched the local ZK proofs,
curves, circuits, stdlib, and Ledger base/serialize/storage/transient crates
into ZKIR's Cargo graph, including the Git-sourced proofs dependency in
`sha3-circuit`. Its temporary lockfile was updated from transient-crypto
3.0.0 to 3.1.0; the resulting Wasm graph contained only proofs 0.8.3 and
did not enable `mmap` or `disk-spill`. This is a browser **compile** gate,
not a browser runtime proof, a released-package build, or current-head CI.

The fixture from betsudo proofs 0.8.2 `397b2424` uses a k=5 circuit and
a deterministic synthetic SRS. Its proof verifies under 0.8.2. The local
0.8.3 test rejects its VK and PK at the distinct version byte in all three
serialization modes and rejects its proof using the new circuit's VK. Its
ordinary parameter bytes load, round-trip unchanged, and match a seeded
0.8.3 setup in Processed, RawBytes, and RawBytesUnchecked modes.
The fixtures and provenance live in `proofs/tests/fixtures/legacy_082`.
This does not qualify production SRS files or all cross-version circuit
shapes.

After that key-version change, the local adapter stack at proofs `120539fe`,
Ledger transient-crypto `c21aeb5`, and ZKIR v3 adapter `9976f4c` passed
all 53 ZKIR library tests, the three `proofs_083_memory` tests, and the
`midnight-zkir-wasm` browser compile check. The focused tests now require
seeded heap and mapped/spilled proofs to have identical bytes for both the
small v3 IR and the Compact-generated Ledger9 counter, while verifying each
proof and rejecting a wrong public input. Cargo used temporary local path
patches and a transient-crypto 3.1.0 lock update; this is not a released
dependency graph, browser runtime proof, or current-head CI. The edited
ZKIR test passed `rustfmt --check`; workspace-wide formatting still reports
differences in unrelated upstream files.

1. Create a code branch from the recorded 0.8.3 baseline. Add the capability features and read-only affine SRS storage with a new, versioned companion format. Test ordinary parameter and companion round trips, corrupt/truncated input, and immutable publication. No serialized 0.8.2 artifact is accepted by accident.
2. Port the policy-aware key loader and keygen behavior to the new phase-0 key. Prove and verify the same generated circuit with heap and mapped parameters. Test the default heap path for the #2 regression.
3. Port streamed coset construction to each new 0.8.3 trace/evaluation owner. Force spill at a known `k`, assert that the spill arm ran, inject storage failures at creation and reservation, and verify both normal and fallback proofs. Measure disk bytes and RSS as well as time. The local code, fault injection, and small-circuit proof gates are in place; measurements remain.
4. Add explicit request context without breaking the compatibility `prove` entry point. Test cancellation of one concurrent proof while another completes. The local proof test now covers pre-cancelled and in-flight requests; the separate Ledger9/ZKIR v3 integration branch exercises the boundary through local path patches. An HTTP request lifecycle and released ZKIR API remain separate gates.
5. Compare 0.8.2 and 0.8.3 proof/VK/key/parameter wire behavior with fixtures and reject unsupported cross-version combinations. Keep Ledger9 pinned to 0.8.2 until its own release line selects and qualifies a newer proof stack.
6. Run native and browser-wasm feature gates, formatting, and exact-head CI. Record host, circuit/compiler version, commits, k/rows, latency, peak RSS, spill bytes, and cleanup of disposable targets. A local result is not current-head CI.

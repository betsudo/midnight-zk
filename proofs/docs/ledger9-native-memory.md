# Ledger9 native proving storage

This proposal applies storage changes to the published `midnight-proofs` 0.8.2 source (`f5e6e16d`) consumed by Ledger9 9.1.0.1. Default proof and key encodings remain unchanged.

The same Ledger9 graph uses `midnight-circuits` 7.3.0 with `midnight-zk-stdlib` 2.4.0. The 0.8.2 source snapshot still carried circuits 7.2.3 in its workspace, which made aggregation and strict Clippy resolve two incompatible circuit types. The circuits subtree in this proposal is aligned to the published 7.3.0 crate source (crates.io checksum `79ba23314560e105bb1da33551199ae9abaa25188589d8308caddbcd8d1f3448`). Keep that release-source alignment distinct from the native storage implementation when reviewing.

`native-memory` is the consumer-facing feature. It includes the lower-level `disk-spill` and `mmap` features. `memmap2`, `tempfile`, and `libc` are restricted to non-Wasm targets. Wasm can compile with the umbrella feature enabled; a request for mapped storage returns `Unsupported`. The default feature set and `ProverConfig::heap()` keep the released heap path.

On a native build with the feature, a caller can create a `ProverContext` with `ProverConfig::mapped_key()` or `ProverConfig::mapped_key_and_cosets()`. Cosets spill at or above `coset_spill_floor_k` (default `k=18`); `spill_dir` selects the temporary volume. A request-local `CancelToken` is checked at prover phase boundaries. Cancelling one context does not cancel another proof, and cancellation cannot retract commitments already written.

Mapped fixed columns and spilled cosets use typed polynomial views and the common serializer. A requested spill failure is returned to the caller rather than silently falling back to an unbounded heap allocation. The mapped SRS reader validates its backing before exposing it; consumers must keep that backing immutable while mapped.

## Qualification

- Preserve proof and key compatibility with released 0.8.2 artifacts, including per-`k` parameters and keys.
- Check native default, native `native-memory`, Wasm default, Wasm `native-memory`, and Wasm all-features builds. Mapped policy on Wasm must return `Unsupported`.
- Verify the Ledger9 V3 TypeScript/Wasm-to-native proof exchange against exact pinned commits. The local small-circuit exchange passed; released per-`k` fixtures remain a separate gate.
- Measure high-`k` peak memory and latency in separate processes on intended native and mobile targets. A forced spill below `k=18` is a functional stress case, not evidence of memory savings.

Tracking: [ZK #5](https://github.com/betsudo/midnight-zk/issues/5) and [Ledger #14](https://github.com/betsudo/midnight-ledger/issues/14).

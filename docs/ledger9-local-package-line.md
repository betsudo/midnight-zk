# Local Ledger9 optimized package line

The released Ledger 9.1.0.1 graph remains on the reviewed optimized proofs
0.8.2 commit. This branch stages a separate, local source line for the
upstream ZK 0.8.3-era port and external ZKIR v3 adapter. Ledger8 is excluded.

As checked on 2026-11-13, crates.io already published `midnight-curves`
0.3.1, `midnight-circuits` 7.3.0, and `midnight-proofs` 0.8.3. The current
upstream-derived sources differ from those published packages, and the
published proofs 0.8.3 has no `mmap` or `disk-spill` feature. Reusing those
version numbers would make a source-qualified result ambiguous.

| Crate | This local candidate | Published version at the check |
| --- | --- | --- |
| `midnight-curves` | 0.3.2 | 0.3.1 |
| `midnight-circuits` | 7.3.1 | 7.3.0 |
| `midnight-proofs` | 0.8.4 | 0.8.3 |
| `midnight-zk-stdlib` | 2.5.0 | 2.4.0 |

The minimum dependencies in this workspace and the local Ledger/ZKIR
consumers select the candidate versions, avoiding a silent crates.io fallback
for the current v2/v3 prover. The older 0.7 proof stack remains intentional
for V0/V1. The native mapping and spill features stay opt-in, and the Wasm
target must resolve neither feature nor `memmap2`.

The versions are provisional local candidates, not published packages or an
authorization to release them. The Ledger and external ZKIR builds need
explicit Cargo path patches for this source stack until each dependency can
be pinned by an immutable betsudo commit or a reviewed release. The 0.8.2
Compact v3 key/proof artifacts are incompatible with this source line; stored
keys require a versioned conversion or regeneration policy before rollout.
Exact-head CI and released-package qualification remain open.

## Focused native safety gate

On the local 0.8.4 source based on `ef4cc33e`, the locked proof workspace
passed `cargo test --offline --locked -p midnight-proofs --features disk-spill
mmap_pk::test::` (8 tests) and the `affine_mmap_companion` filter (3 tests).
The spill tests cover round trips, zero-fill fallback, reservation errors
before exposing a mapping, empty batches, mapped lifetime, and malformed
length/count rejection. The companion tests cover round trip/downsize,
damaged or older layouts, and no-replace publication. A default-feature
`cargo check --offline --locked -p midnight-proofs` also passed.

These focused checks validate the local code paths; they do not simulate an
actual full filesystem or an external process rewriting a trusted mapped
file. The caller's immutable-file obligation remains part of the unsafe
mapping contract.

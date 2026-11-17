# Ledger 9 hash-circuit source closure

The Ledger 9 Git graph carries bounded source copies of the two Apache-2.0 hash-circuit packages used by `midnight-zk-stdlib`:

| Package | Version | crates.io checksum | Upstream source commit |
| --- | --- | --- | --- |
| `blake2b_halo2` | `0.2.0` | `db0e2335f7864c16821ade9dcc5918780306ca9fdf3876dd2fd2c82d820aa9da` | `eryxcoop/blake2b_halo2@6ed2fa2b0dfda00d92cc75a7d728fa4b1a6320a1` |
| `sha3-circuit` | `0.2.0` | `4237ceb913f4dcf6219c5303d37122c8cd3734cbe1314274158a8eb609dedac8` | `alexandroszacharakis8/sha3-circuit@1001480298d9eb61ea3b62447802ef2b7404f388` |

The Rust sources, tests, license, and README are copied from those published crates without semantic edits. Their local manifests replace version-only Midnight dependencies with version-plus-path dependencies on this repository's `midnight-curves` and `midnight-proofs` packages. This lets a Git dependency on `midnight-zk-stdlib` resolve the complete active Ledger 9 proof graph from one Git source; an application-root `[patch.crates-io]` table is no longer part of the consumer contract.

These packages are `publish = false`. A future registry release must coordinate publishable helper versions instead of relying on these repository-relative paths. Rollback is mechanical: restore the two registry dependencies in `zk_stdlib/Cargo.toml`, remove these workspace members, and restore the temporary consumer-root patch contract documented by issue #14.

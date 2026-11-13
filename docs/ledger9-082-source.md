# Ledger9 ZK 0.8.2 source alignment

Ledger 9.1.0.1 resolves `midnight-proofs` 0.8.2, `midnight-circuits` 7.3.0, and `midnight-zk-stdlib` 2.4.0. This branch keeps the fork's optimized proofs 0.8.2 implementation and replaces the local circuits and stdlib source with the exact published 7.3.0 and 2.4.0 crate contents. The original, pre-normalization `Cargo.toml.orig` from each crate is used as its workspace manifest. The released package checksums recorded in the Ledger tag's `Cargo.lock` are:

| Package | crates.io checksum |
| --- | --- |
| `midnight-circuits` 7.3.0 | `79ba23314560e105bb1da33551199ae9abaa25188589d8308caddbcd8d1f3448` |
| `midnight-zk-stdlib` 2.4.0 | `73819f4cd779e365545109dbbd759fe0055df4ea73f6e0ddb873281c1c8014ec` |

The published circuit source and original manifest compare byte-for-byte with this branch, excluding Cargo's registry metadata and crate-local `LICENSE` copy (the workspace license remains). The stdlib source and original manifest also compare byte-for-byte except for the two `prove_with_context` adapter files, the additive context test, and this changelog entry. The adapter keeps the prior `prove` signatures and delegates them to process defaults. No expected verifying keys were regenerated.

The upstream `main` tree at `24a1eb5a` is **not** the released 7.3.0/2.4.0 source: it already uses the later 0.8.3/FFLONK API despite retaining those crate version labels. Transplanting that tree onto proofs 0.8.2 fails to compile. The released crate contents are the reference for this stable compatibility line; upstream `main` continues separately.

Local checks after source alignment: `cargo check -p midnight-zk-stdlib -p midnight-circuits -p midnight-aggregation`, the release-mode `context_prove` test, all 14 release-mode `check_vks` tests using CI's Filecoin SRS fixture, release-mode aggregation tests, and strict Clippy for aggregation and stdlib all pass. This does not yet qualify Ledger's V2/V3 serialized fixture compatibility, wasm, or exact-head CI.

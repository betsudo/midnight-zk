# Ledger9 optimization contribution review map

This page is a review handoff for the opt-in native proving work in the
`betsudo` forks. The compatibility baseline is Ledger `ledger-9.1.0.1`,
published `midnight-proofs` 0.8.2, and published ZKIR 3.2.1 source.
Ledger8 and Ledger10 are outside this series. The fork integration branches
are working references; they are not upstream submissions.

## PRs and ownership

| PR | Delivery role | Contribution | Boundary to review |
| --- | --- | --- | --- |
| [ZK #11](https://github.com/betsudo/midnight-zk/pull/11) | Integrated into `integration/ledger9/proofs-0.8.2` | Adds opt-in `native-memory`: mapped SRS and proving-key storage, streamed coset spill, request context, and cooperative cancellation. Aligns circuits 7.3.0 and stdlib 2.4.0 to their published sources. | The default heap API and proof/key encodings remain compatible. Native-only dependencies are target gated; requested mapped storage on Wasm returns `Unsupported`. Review release alignment separately from memory changes. |
| [ZKIR #3](https://github.com/betsudo/midnight-zkir/pull/3) | Integrated into `integration/ledger9/zkir-3.2.1` | Forwards one request-owned V3 context through key initialization and proving, with exact ZK and Ledger API pins. | Legacy `prove` and tagged formats remain unchanged. A mapped key needs serialized bytes; an initialized heap key can be reused for heap or coset-only spill. |
| [Ledger #38](https://github.com/betsudo/midnight-ledger/pull/38) | Integrated into `integration/ledger9/ledger-9.1.0.1` | Adds bounded HTTP ingress and queued-work admission, policy-aware parameter/key loading, cancellation, and the V3 consumer adapter. | The Cargo feature supplies native capability; CLI policy selects it per request. V2 and Wasm retain heap routes. The mapped SRS companion directory must be operator-owned and immutable while mapped. |
| [Ledger #39](https://github.com/betsudo/midnight-ledger/pull/39) | Qualification follow-up | Adds official k=4/k=6 parameter fixtures, an independently published SDK testkit V3 key, heap/mapped/spill assertions, and Node/Wasm-to-native proof verification. | This is a small-circuit compatibility gate, not a high-`k` memory benchmark or deployed-dApp key test. |
| [ZK #13](https://github.com/betsudo/midnight-zk/pull/13) | Upstream-plan follow-up | Maps the merged source commits into five upstream review units and records the cross-repository landing order. | This is documentation, not a port to current upstream `main`; the newer proof transcript must be reconciled before an upstream PR. |

The first three PRs are the delivered optimization graph. The last two
make its evidence and upstream proposal easier to review. Dependency pins
in the integration graph are fork-local; they are not part of the proposed
upstream library API.

## Design in one path

```text
HTTP request -> bounded ingress -> queued job -> V3 ProverContext
                                               |      |
                                               |      +-> request cancellation
                                               +-> heap or native mapped policy
                                                        |
                             parameter provider -> ZKIR -> proofs
                                                        |
                                             proof -> released verifier
```

The default request uses heap storage. A native build with `native-memory`
may explicitly request a mapped key, mapped universal parameters, and
coset spill. A required spill or mapping failure returns an error instead
of silently switching to a large heap allocation. Cancellation is scoped
to one request and checked at phase boundaries; it cannot undo transcript
bytes already written. The proof-server caps body readers and queued
closures before accepting more decoded work.

The unsafe SRS mapping contract is narrow but important: no process may
modify, truncate, or replace a published companion file while a mapping is
alive. The operator must supply a private immutable directory. Temporary
key and coset spill files are a different, request-scoped storage boundary.
See [native proving storage](ledger9-native-memory.md),
[ZKIR V3 context](https://github.com/betsudo/midnight-zkir/blob/556f3c4457a3b5e5ee544eca9e4893ebbde2b446/docs/ledger9-v3-context.md),
and [Ledger integration](https://github.com/betsudo/midnight-ledger/blob/372b1bcf47d75018ddb482eba528763374a547ea/docs/ledger9-optimization.md)
for the component details.

## Reproducible compatibility evidence

The [Ledger #39 fixtures](https://github.com/betsudo/midnight-ledger/pull/39)
use the official Ledger9 k=4 SRS (SHA-256
`232f401fad10c7ddf8828d2aa4c85c6506c5da09795998cecaeb9f75fc8f6ada`)
with a key generated locally from published ZKIR 3.2.1 source. The k=6
SRS (SHA-256
`cf2ad6be7d0fedf5bec2aaa35f6be4aca33053d74268fdf5aa54fcb2891ea6df`)
is paired with the independently published Midnight JS Compact 0.36.1
testkit counter key (SHA-256
`6fa13f54b055be31d4809c59dfd96b08e809641f43bc0d83951cbfb4162ac010`).
The key and IR hashes match the published SDK manifest. Native Ledger9
verifies proofs produced from the published key under heap, mapped SRS/key,
and forced coset spill. In an opt-in local test, a ZKIR 3.2.1 Node/Wasm
proof using that key and the Compact TypeScript preimage also verified in
native Ledger9; ordinary hosted CI does not run that cross-runtime test.

At Ledger #39 head `2b3ee462`, the focused `native-memory` V3 test ran
seven passing cases with two intentional ignores, and the feature-enabled
`wasm32-unknown-unknown` Ledger9 check passed. The full
[build-and-test run](https://github.com/betsudo/midnight-ledger/actions/runs/43834105721)
passed eight jobs; [coverage](https://github.com/betsudo/midnight-ledger/actions/runs/43834104987)
passed separately. These are fork-head results, not CI on a future
upstream rebasing.

## What still needs review

- Confirm the immutable companion-file obligation and failure behavior at
  every unsafe mapping boundary. Inspect key identity, atomic publication,
  and no-clobber behavior in Ledger's policy-aware cache.
- Check that native feature activation never changes a default heap request
  or exposes host storage primitives to Wasm. Verify request-local
  cancellation and admission accounting under expiry and disconnect.
- Reproduce high-`k` resident memory, latency, and spill bytes on intended
  server and mobile targets before claiming a capacity or speed benefit.
  The k=4/k=6 cases establish format and interoperability only.
- Add a deployed-dApp V3 key if production artifact coverage is required.
  The current independent key is an SDK testkit artifact.
- Port the five library units in [native proving storage](ledger9-native-memory.md#upstream-contribution-slices)
  to the chosen upstream target and rerun proof, key, native, Wasm, and
  failure-path gates there. Current upstream ZK `main` has a newer
  transcript boundary than the Ledger9-pinned 0.8.2 release.

The upstream landing order is ZK storage/context APIs, Ledger provider and
trait prerequisites, ZKIR V3 context adapter, then the Ledger consumer.
[ZK #12](https://github.com/betsudo/midnight-zk/issues/12) tracks the
proposal series; [Ledger #30](https://github.com/betsudo/midnight-ledger/issues/30)
tracks V3 artifact/policy acceptance; [Ledger #12](https://github.com/betsudo/midnight-ledger/issues/12)
owns high-`k` benchmark evidence. Check the linked PRs for current CI,
review, and merge state.

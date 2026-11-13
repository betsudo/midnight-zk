# Proofs 0.8.2 compatibility fixtures

These Processed and RawBytes files were generated with the signed betsudo
`midnight-zk` commit `397b2424b972b3ec338722839c109f01c2fcf9f1`
(`midnight-proofs` 0.8.2). They use the `MyCircuit` definition in
`proofs/tests/vk_serialization.rs`, `k = 5`, and synthetic `ParamsKZG<Bls12>`
from `StdRng::seed_from_u64(0)`. The proof used
`StdRng::seed_from_u64(1)` and verified with the 0.8.2 key and parameters
before capture. These deterministic test parameters are **not trusted SRS**.

| File | SHA-256 |
| --- | --- |
| `params-082.bin` | `20cf7862c12b7318dac4ade15567dcadc5ff1e34678ceef76fbb2f2ae9c97127` |
| `params-082-raw.bin` | `bd7f32b1d3b41471b5a17e69e79b4fd7600f0c187aca4e58b1e99005a882d958` |
| `pk-082.bin` | `aa2439a39cfe23e4dfbc3d82d0107b2c96606e5ed4b3c7542484dd7bed59ac85` |
| `pk-082-raw.bin` | `e249d20b02bda70d30ad83322d270c2b5fcc883ada0e47ebc56dac3792009fe4` |
| `proof-082.bin` | `1abdf21499da14b86a9bd3ac320106aa904ddb38c93cc565d647e34c17152114` |
| `vk-082.bin` | `942ff28310c3144c5476300b8109848ec9d32cb3b3ad69bdf5b7e254252ef7d2` |
| `vk-082-raw.bin` | `443c525ce5883eaa6396984109b283da4cd1b7abc5a098fb82be541eff9af59e` |

The corresponding test checks the precise boundary of these samples:
0.8.3 rejects the old VK, PK, and proof; it reads and round-trips this
ordinary parameter file in Processed, RawBytes, and RawBytesUnchecked
formats. RawBytesUnchecked writes the same bytes as RawBytes and differs
only in validation on read, so the test uses the same raw fixtures for
both. The result does not establish compatibility for other circuits or
production SRS files.

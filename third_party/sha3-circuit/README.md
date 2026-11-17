# SHA3/Keccak implementation for Halo2 

A chip to implement the [keccak-f[1600]](https://keccak.team/keccak_specs_summary.html) permutation and two gadgets to implement the [sha3-256 hash function](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and the [keccak256 hash function](https://keccak.team/files/Keccak-reference-3.0.pdf) in halo2.

The chip is based on [a single lookup](docs/lookup.md) and it uses [packed arithmetic techniques](docs/techniques.md#packed-arithmetic).

## Usage

For basic usage check out the example and the intergration test.

## Techniques

For an in-depth explanation on how the chip works and the underlying techniques, start [here](./docs/intro.md).

## Benchmarks

We run benchmarks for computing a preimage for various input sizes. The benchmarks were done in a Lenovo Thinkpad X1 Xtreame Gen5 laptop with an Intel Core i7-12700H cpu and 32GB of RAM. 

The benchmarks are done for a 2^14 lookup table implementation. The circuit uses 10 advice columns and 9 fixed columns. All the constraints access at most the rotations $X$, $\omega X$ and $\omega^2 X$.

For all the preimage bit lenghts the verification key size is 902 bytes and the proof size is 5408 bytes. The verification time is ~4.5ms.

| Preimage size in bytes | Number of rows | Prover time 
|------------------------|----------------|-------------
|   100                  |     2^14       | 1.8 s    
|   200                  |     2^14       | 2.1 s    
|   300                  |     2^14       | 2.4 s    
|   400                  |     2^14       | 2.5 s    
|   500                  |     2^15       | 3.8 s    
|   750                  |     2^15       | 4.5 s    
|   1000                 |     2^16       | 6.9 s    
|   2000                 |     2^16       | 9.1 s    
|   3000                 |     2^17       | 15.4 s    
|   5000                 |     2^18       | 26.7 s    
|   10000                |     2^19       | 53.9 s    


## Disclaimer

This project is provided "as is" and is intended for educational and experimental purposes only. The library has not been audited. It is not production-ready and may contain bugs or incomplete features. Use at your own risk.

The authors and contributors are not responsible for any damage, loss of data, or other issues that may arise from using this software.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Acknowledgments

Special thanks to [@John-Gong-Math](https://github.com/John-Gong-Math) and [@iquerejeta](https://github.com/iquerejeta) for contributions, discussions and feedback on the project.

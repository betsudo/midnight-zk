# blake2b_halo2
This repo holds an optimized Blake2b implementation in Halo2 prover.
> ⚠️ **Security Warning**  
> This code has **not been audited**. Use at your own risk.  


* We are using [this halo2 version](https://github.com/midnightntwrk/midnight-zk) to build our circuits.
* The cargo version should be 1.84.0 or higher (no need for nightly).

 Under the directory ```blake2b_halo2```  there are Halo2 chips that implement primitives for operating modulo 2⁶⁴, a chip for the Blake2b operation and tests for the above.

## Documentation

We have a [documentation](https://hackmd.io/@BjOWve_hTxGZidE1ii0HJg/HkVu20JFkx) where you can find more detail about 
out Blake2b implementation. You can also find more detailed explanations of all our gates.


# Trying the implementation
The executable in ```examples/interface``` allows you to try the halo2 implementation of Blake2b.
Just fill the ```examples/inputs.json``` file with the message, key and desired output length (in bytes) and run the following command:

```cargo run --release --example interface```

# Running the tests

We have unit tests for all our auxiliar chips and the vector tests for the Blake2b implementation. All the tests should be executed on the ```blake2b_halo2``` directory.

To run tests of our Halo2 implementation':

```cargo test --release test_hashes_in_circuit_```

Those tests use the same test vector than the plain Rust implementation. Running the above tests can take some time since there are 512 tests in the test vector, and each one repeats all the static procedures (like creating big lookup tables), but it shouldn't take more than 2 minutes in release mode.

To test the auxiliar chips:

```cargo test --release -- --skip test_hashes_in_circuit_```

# Benchmarking
Just run

```cargo bench```

The report should be found in ```/target/criterion/report/index.html```. 

There are 5 targets for benchmarking: mocked proving, verification key generation, proving key generation, proof generation and verification. Each one will compare all the optimizations over inputs of different size. Running all the benchmarks can take quite some time, so if you want to run one specific target use:

```cargo bench --bench <TARGET_NAME>```

where <TARGET_NAME> is one of the following:
* mocked_proving
* vk_generation
* pk_generation
* proof_generation
* verification
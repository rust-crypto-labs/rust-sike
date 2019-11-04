`rust-sike` is a Rust implementation of the SIKE isogeny-based key encapsulation suite [(SIKE)][1], a post-quantum candidate submitted to the NIST standardization process [(NIST)][2].

### Why `rust-sike`?

The SIKE submission already comes with reference implementations, including optimised versions for different platforms. Additional implementations by Microsoft and Cloudflare are available. All these libraries are written in C, with occasional platform-specific assembly instructions, which allows them to reach maximum performance.

`rust-sike` is concerned with providing high *correctness* guarantees: adherence to the SIKE specification, memory and type safety, and reproducibility across platforms. Extensive testing and documentation is a desired. Performance is a longer-term concern.

### Status

#### Supported algorithms

`rust-sike` currently supports both algorithms from the SIKE suite: a public-key encryption primitive, and a key-encapsulation mechanism build from this primitive.

Under the hood, isogeny computations are performed using optimised, but not strategy-optimised, algorithms. 
The updated specification (17 april 2019) is used as a basis for implementation.

#### Supported parameters

`rust-sike` currently supports the `p434` parameters.

### References and documentation

[1]: https://sike.org/
[2]: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

- (SIKE) https://sike.org/
- (NIST) https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

`rust-sike` is a Rust implementation of the SIKE isogeny-based key encapsulation suite (SIKE [1]), a post-quantum candidate submitted to the NIST standardization process [2].

### Why `rust-sike`?

The SIKE submission already comes with reference implementations, including optimised versions for different platforms. Additional implementations by Microsoft and Cloudflare are available. All these libraries are written in C, with occasional platform-specific assembly instructions, which allows them to reach maximum performance.

`rust-sike` is concerned with providing high *correctness* guarantees: adherence to the SIKE specification, memory and type safety, and reproducibility across platforms. Extensive testing and documentation is a desired. Performance is a longer-term concern.

### Status

#### Supported algorithms

`rust-sike` currently supports both algorithms from the SIKE suite: a public-key encryption primitive (`PKE`), and a key-encapsulation mechanism (`KEM`) build from this primitive.

Under the hood, isogeny computations are performed using optimised tree-traversal algorithms.
The updated specification (17 april 2019) is used as a basis for implementation.

#### Supported parameters

`rust-sike` currently supports all the parameters described in the NIST submission: `p434`, `p503`, `p610`, and `p751`.

#### Unsupported features

* Key compression and decompression are currently not supported

### References and documentation

* [1]: https://sike.org/
* [2]: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography

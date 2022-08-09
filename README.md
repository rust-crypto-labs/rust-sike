# rust-sike

`rust-sike` is a Rust implementation of the SIKE isogeny-based key encapsulation suite (SIKE [1]), a post-quantum candidate submitted to the NIST standardization process [2].

**WARNING: As of July 30th 2022, SIDH (supersingular Diffie-Hellman), the underlying quantum-resistant mechanism of SIKE, has been found to be vulnerable to an efficient key recovery attacks [3] (recovery time ranging from one hour to less than a day depending on the security level on a single core). Therefore SIDH/SIKE should not be considered as secure and `rust-sike` should only be used for test or research purpose and under no circumstances for any production code**

## Why `rust-sike`?

The SIKE submission already comes with reference implementations, including optimised versions for different platforms. Additional implementations by Microsoft and Cloudflare are available. All these libraries are written in C, with occasional platform-specific assembly instructions, which allows them to reach maximum performance. At the time of writing these implementations match an older version of the SIKE specification.

`rust-sike` is concerned with providing high *correctness* guarantees: adherence to the SIKE specification, memory and type safety, and reproducibility across platforms. Extensive testing and documentation is desired. Performance matters but is a longer-term concern.

## Status

### Supported features and algorithms

* Key encapsulation mechanism (`KEM`)
* Public-key encryption (`PKE`)
* All the parameters described in the NIST submission: `p434`, `p503`, `p610`, and `p751`.
* Optimised tree-traversal strategies

The updated specification (April 17th 2019) is used as a basis for implementation.

### Unsupported features and caveats

* Key compression and decompression are currently not supported (future work)
* The implementation is not guaranteed to be constant time
* The implementation is not `no_std` compatible (for non-essential reasons)

## References and documentation

* <https://sike.org/>
* <https://csrc.nist.gov/Projects/Post-Quantum-Cryptography>
* <https://eprint.iacr.org/2022/975>

[1]: https://sike.org/
[2]: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography
[3]: https://eprint.iacr.org/2022/975

//! Utils for SHAKE

use tiny_keccak::Keccak;

/// SHAKE-256 wrapper
///   * Input: `input` string and `len`gth of the desired output
///   * Output: an array of length `len`.
///
/// # Examples
/// ```rust
/// let result = shake256(&[1, 2, 3, 4, 5], 32);
/// println!("{:?}", result);
/// ```
pub fn shake256(input: &[u8], len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    Keccak::shake256(input, &mut buffer);
    buffer.to_vec()
}

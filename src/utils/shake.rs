//! Utils for SHAKE

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// SHAKE-256 wrapper
///   * Input: `input` string and `length` of the desired output
///   * Output: an array of length `len`.
//
// # Example
// ```
// let result = shake256(&[1, 2, 3, 4, 5], 32);
// println!("{:?}", result);
// ```
#[inline]
pub fn shake256(input: &[u8], len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    let mut shake = Shake256::default();
    shake.update(input);
    shake.finalize_xof().read(&mut buffer);
    buffer
}

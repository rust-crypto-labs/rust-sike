//! Utils for conversions

use crate::ff::{
    ff_p434::PrimeFieldP434, ff_p503::PrimeFieldP503, ff_p751::PrimeFieldP751, ff_p610::PrimeFieldP610, QuadraticExtension,
};
use num_bigint::{BigInt, Sign};

/// String to `u64` conversion
pub fn str_to_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect(&format!("Incorrect value: {}", s))
}

/// String to an element of the quadratic extension field conversion
pub fn str_to_p434(s0: &str, s1: &str) -> QuadraticExtension<PrimeFieldP434> {
    QuadraticExtension::from(
        PrimeFieldP434::from_string(s0),
        PrimeFieldP434::from_string(s1),
    )
}

/// String to an element of the quadratic extension field conversion
pub fn str_to_p503(s0: &str, s1: &str) -> QuadraticExtension<PrimeFieldP503> {
    QuadraticExtension::from(
        PrimeFieldP503::from_string(s0),
        PrimeFieldP503::from_string(s1),
    )
}

/// String to an element of the quadratic extension field conversion
pub fn str_to_p751(s0: &str, s1: &str) -> QuadraticExtension<PrimeFieldP751> {
    QuadraticExtension::from(
        PrimeFieldP751::from_string(s0),
        PrimeFieldP751::from_string(s1),
    )
}

/// String to an element of the quadratic extension field conversion
pub fn str_to_p610(s0: &str, s1: &str) -> QuadraticExtension<PrimeFieldP610> {
    QuadraticExtension::from(
        PrimeFieldP610::from_string(s0),
        PrimeFieldP610::from_string(s1),
    )
}

/// String to `BigInt` conversion
pub fn str_to_bigint(s: &str) -> BigInt {
    BigInt::parse_bytes(s.as_bytes(), 16).expect(&format!("Cannot convert to integer: {:?}", s))
}

/// Bytes to `BigInt` conversion
pub fn bytes_to_bigint(b: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, b)
}

/// Concatenates a list of arrays into one array
///
/// # Examples
/// ```rust
/// let a = [1, 2];
/// let b = [3, 4];
/// let a_and_b = concatenate(&[&a, &b]);
/// assert_eq!(a_and_b, [1, 2, 3, 4]);
/// ```
pub fn concatenate(arrays: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![];
    for &array in arrays {
        result.extend(array);
    }
    result
}

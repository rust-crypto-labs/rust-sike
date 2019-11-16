//! Utils for conversions

use crate::ff::{
    PrimeFieldP434, PrimeFieldP503, PrimeFieldP610, PrimeFieldP751, QuadraticExtension,
};

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

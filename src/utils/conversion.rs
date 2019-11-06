use crate::ff::{ff_p434::PrimeField_p434, QuadraticExtension};
use num_bigint::{BigInt, Sign};

pub fn str_to_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect(&format!("Incorrect value: {}", s))
}

pub fn str_to_p434(s0: &str, s1: &str) -> QuadraticExtension<PrimeField_p434> {
    QuadraticExtension::from(
        PrimeField_p434::from_string(s0),
        PrimeField_p434::from_string(s1),
    )
}

pub fn str_to_bigint(s: &str) -> BigInt {
    BigInt::parse_bytes(s.as_bytes(), 16).expect(&format!("Cannot convert to integer: {:?}", s))
}

pub fn bytes_to_bigint(b: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, b)
}

pub fn concatenate(arrays: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![];
    for &array in arrays {
        result.extend(array);
    }
    result
}

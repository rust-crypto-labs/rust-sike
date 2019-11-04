use crate::ff::{PrimeField_p434, QuadraticExtension};
use num_bigint::BigInt;

use std::str::FromStr;

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
    unimplemented!()
}

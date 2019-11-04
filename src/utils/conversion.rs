use crate::ff::{PrimeField, QuadraticExtension};

use std::str::FromStr;

pub fn str_to_u64(s: &str) -> u64 {
    u64::from_str_radix(s, 16).expect(
        &format!("Incorrect value: {}", s)
    )
}

pub fn str_to_p434(s0: &str, s1: &str) -> QuadraticExtension<PrimeField> {
    QuadraticExtension::from(
        PrimeField::from_string(s0),
        PrimeField::from_string(s1)
    )
}

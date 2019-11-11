//! Finite field for SIKEp610
//!
//! Implementation of the finite field of order SIKE_P610_P used in SIKEp610

use crate::constants::cs_p610::SIKE_P610_P;
use crate::ff::FiniteField;
use crate::utils::conversion;

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};

use once_cell::sync::Lazy;

use std::fmt::Debug;
use std::ops::Mul;

static P610_PRIME: Lazy<BigInt> = Lazy::new(|| conversion::str_to_bigint(SIKE_P610_P));

/// Finite field defined by the prime number SIKE_P610_P
#[derive(Clone, PartialEq)]
pub struct PrimeFieldP610 {
    val: BigInt,
}

impl PrimeFieldP610 {
    /// Parse a string into and element of the finite field
    pub fn from_string(s: &str) -> Self {
        let val = conversion::str_to_bigint(s).mod_floor(&P610_PRIME.clone());

        Self { val }
    }
}

impl Debug for PrimeFieldP610 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (_, bytes) = self.val.to_bytes_be();
        write!(f, "{:?}", bytes)
    }
}

impl FiniteField for PrimeFieldP610 {
    fn is_zero(&self) -> bool {
        self.val == BigInt::zero()
    }

    fn dimension() -> usize {
        1
    }

    fn order() -> BigInt {
        P610_PRIME.clone()
    }

    fn zero() -> Self {
        Self {
            val: BigInt::zero(),
        }
    }

    fn one() -> Self {
        Self { val: BigInt::one() }
    }

    fn neg(&self) -> Self {
        Self {
            val: &P610_PRIME.clone() - &self.val,
        }
    }

    fn inv(&self) -> Self {
        let two = BigInt::one() + BigInt::one();
        let p = &P610_PRIME.clone();
        Self {
            val: self.val.modpow(&(p - two), p),
        }
    }

    fn add(&self, other: &Self) -> Self {
        let sum = &self.val + &other.val;
        Self {
            val: sum.mod_floor(&P610_PRIME.clone()),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    fn mul(&self, other: &Self) -> Self {
        let prod = self.val.clone().mul(&other.val);

        Self {
            val: prod.mod_floor(&P610_PRIME.clone()),
        }
    }

    fn div(&self, other: &Self) -> Self {
        self.mul(&other.inv())
    }

    fn equals(&self, other: &Self) -> bool {
        self.sub(&other).is_zero()
    }

    fn to_bytes(self) -> Vec<u8> {
        let (_, bytes) = self.val.to_bytes_be();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let val = BigInt::from_bytes_be(Sign::Plus, bytes).mod_floor(&P610_PRIME.clone());
        Self { val }
    }
}

//! Finite field for SIKEp503
//!
//! Implementation of the finite field of order SIKE_P503_P used in SIKEp503

use crate::constants::cs_p503::SIKE_P503_P;
use crate::ff::FiniteField;
use crate::utils::conversion;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use num_traits::{One, Zero};

use once_cell::sync::Lazy;

use std::fmt::Debug;

static P503_PRIME: Lazy<BigUint> = Lazy::new(|| conversion::str_to_bigint(SIKE_P503_P));

/// Finite field defined by the prime number SIKE_P503_P
#[derive(Clone, PartialEq)]
pub struct PrimeFieldP503 {
    val: BigUint,
}

impl PrimeFieldP503 {
    /// Parse a string into and element of the finite field
    pub fn from_string(s: &str) -> Self {
        let val = conversion::str_to_bigint(s).mod_floor(&P503_PRIME.clone());

        Self { val }
    }
}

impl Debug for PrimeFieldP503 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.val.to_bytes_be();
        write!(f, "{:?}", bytes)
    }
}

impl PrimeFieldP503 {
    #[inline]
    fn order() -> &'static BigUint {
        &*P503_PRIME
    }
}

impl FiniteField for PrimeFieldP503 {
    #[inline]
    fn is_zero(&self) -> bool {
        self.val == BigUint::zero()
    }

    #[inline]
    fn dimension() -> usize {
        1
    }

    #[inline]
    fn zero() -> Self {
        Self {
            val: BigUint::zero(),
        }
    }

    #[inline]
    fn one() -> Self {
        Self {
            val: BigUint::one(),
        }
    }

    #[inline]
    fn neg(&self) -> Self {
        Self {
            val: Self::order() - &self.val,
        }
    }

    #[inline]
    fn inv(&self) -> Self {
        let two = BigUint::from_u8(2).unwrap();
        Self {
            val: self.val.modpow(&(Self::order() - two), Self::order()),
        }
    }

    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self {
            val: (&self.val + &other.val).mod_floor(Self::order()),
        }
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    #[inline]
    fn mul(&self, other: &Self) -> Self {
        Self {
            val: (&self.val * &other.val).mod_floor(Self::order()),
        }
    }

    #[inline]
    fn div(&self, other: &Self) -> Self {
        self.mul(&other.inv())
    }

    #[inline]
    fn equals(&self, other: &Self) -> bool {
        self.sub(&other).is_zero()
    }

    fn to_bytes(self) -> Vec<u8> {
        self.val.to_bytes_be()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            val: BigUint::from_bytes_be(bytes).mod_floor(Self::order()),
        }
    }
}

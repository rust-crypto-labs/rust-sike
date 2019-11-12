//! Finite fields
//!
//! Provides the standard structure for finite fields and their quadratic extensions.
//! It also includes specific finite fields implementation used for SIKE

use num_bigint::BigInt;
use std::fmt::Debug;

pub mod ff_p434;
pub mod ff_p503;
pub mod ff_p610;
pub mod ff_p751;

/// Finite field element
pub trait FiniteField {
    /// Check if the element is the additive identity of the field
    fn is_zero(&self) -> bool;

    /// Returns the dimension of the finite field
    fn dimension() -> usize;

    /// Returns the order
    fn order() -> BigInt;

    /// Returns the additive identity of the field
    fn zero() -> Self;

    /// Returns the multiplicative identity of the field
    fn one() -> Self;

    /// Returns the additive inverse of the element
    fn neg(&self) -> Self;

    /// Returns the multiplicative inverse of the element
    fn inv(&self) -> Self;

    /// Defines the addition of two elements
    fn add(&self, other: &Self) -> Self;

    /// Defines the substraction of two elements
    fn sub(&self, other: &Self) -> Self;

    /// Defines the multiplication of two elements
    fn mul(&self, other: &Self) -> Self;

    /// Defines the divison of two elements
    fn div(&self, other: &Self) -> Self;

    /// Checks if two elements are equal
    fn equals(&self, other: &Self) -> bool;

    /// Converts the element to a bytes representation
    fn to_bytes(self) -> Vec<u8>;

    /// Converts a bytes representation to an element of the finite field
    fn from_bytes(bytes: &[u8]) -> Self;
}

/// Given a specific finite field 𝔽ₚ, represents an element of
/// its quadratic extension 𝔽ₚ(i) as `x = a + ib`, (`i² = -1`)
#[derive(Clone, Copy, PartialEq)]
pub struct QuadraticExtension<F: FiniteField> {
    a: F,
    b: F,
}

impl<F: FiniteField + Debug> Debug for QuadraticExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} + i {:?}", self.a, self.b)
    }
}

impl<F: FiniteField> QuadraticExtension<F> {
    /// Generates an element of the quadratic extension given two elements of the base field: `z = a + i b`.
    pub fn from(a: F, b: F) -> Self {
        Self { a, b }
    }
}

impl<F: FiniteField + Debug> FiniteField for QuadraticExtension<F> {
    fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }

    fn dimension() -> usize {
        2 * F::dimension()
    }

    fn order() -> BigInt {
        F::order() * F::order()
    }

    fn zero() -> Self {
        Self {
            a: F::zero(),
            b: F::zero(),
        }
    }

    fn one() -> Self {
        Self {
            a: F::one(),
            b: F::zero(),
        }
    }

    fn neg(&self) -> Self {
        Self {
            a: self.a.neg(),
            b: self.b.neg(),
        }
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            a: self.a.add(&other.a),
            b: self.b.add(&other.b),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    fn div(&self, other: &Self) -> Self {
        self.mul(&other.inv())
    }

    fn mul(&self, other: &Self) -> Self {
        let m1 = self.a.mul(&other.a);
        let m2 = self.b.mul(&other.b);

        let m3 = self.a.mul(&other.b);
        let m4 = other.a.mul(&self.b);

        Self {
            a: m1.sub(&m2),
            b: m3.add(&m4),
        }
    }

    fn inv(&self) -> Self {
        let asq = self.a.mul(&self.a);
        let bsq = self.b.mul(&self.b);
        let inv_norm = asq.add(&bsq).inv();

        Self {
            a: inv_norm.mul(&self.a),
            b: inv_norm.mul(&self.b.neg()),
        }
    }

    fn equals(&self, other: &Self) -> bool {
        self.a.equals(&other.a) && self.b.equals(&other.b)
    }

    fn to_bytes(self) -> Vec<u8> {
        use crate::utils::conversion::concatenate;

        let part1 = self.a.to_bytes();
        let part2 = self.b.to_bytes();

        // Left padding to the nearest power of 2
        let p21 = part1.len().next_power_of_two();
        let p22 = part2.len().next_power_of_two();
        let len = std::cmp::max(p21, p22);

        let pad1 = vec![0; len - part1.len()];
        let pad2 = vec![0; len - part2.len()];

        concatenate(&[&pad1, &part1, &pad2, &part2])
    }

    /// Element from byte representation (ref `ostofp2` Algorithm 1.2.4.)
    fn from_bytes(bytes: &[u8]) -> Self {
        let n = bytes.len() / 2;
        let a = F::from_bytes(&bytes[..n]);
        let b = F::from_bytes(&bytes[n..]);
        Self::from(a, b)
    }
}

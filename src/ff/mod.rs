use num_bigint::BigInt;
use std::fmt::Debug;

pub mod ff_p434;

pub trait FiniteField {
    fn is_zero(&self) -> bool;
    fn dimension() -> usize;
    fn order() -> BigInt;
    fn zero() -> Self;
    fn one() -> Self;
    fn neg(&self) -> Self;
    fn inv(&self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn div(&self, other: &Self) -> Self;
    fn equals(&self, other: &Self) -> bool;

    fn to_bytes(self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}



#[derive(Clone, Copy, PartialEq)]
pub struct QuadraticExtension<F: FiniteField> {
    a: F,
    b: F,
}

impl<F: FiniteField + std::fmt::Debug> std::fmt::Debug for QuadraticExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} + i {:?}", self.a, self.b)
    }
}

impl<F: FiniteField> QuadraticExtension<F> {
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

    /// Algorithm 1.2.4. ostofp2
    fn from_bytes(bytes: &[u8]) -> Self {
        let n = bytes.len() / 2;
        let a = F::from_bytes(&bytes[..n]);
        let b = F::from_bytes(&bytes[n..]);
        Self::from(a, b)
    }
}

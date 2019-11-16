//! Montgomery curve

use crate::{ff::FiniteField, isogeny::PublicKey};

/// Montgomery M_{A,1} Curve defined by (A : C) in projective cooridnates
pub struct Curve<K> {
    /// Coefficient A
    pub a: K,

    /// Coefficient C
    pub c: K,
}

impl<K: FiniteField + Clone> Curve<K> {
    /// Clone the curve
    pub fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            c: self.c.clone(),
        }
    }

    /// Build a curve from coefficients
    #[inline]
    pub fn from_coeffs(a: K, c: K) -> Self {
        Self { a, c }
    }

    /// Curve with equation y² = x³ + 6x² + x (ref 1.3.2)
    #[inline]
    pub fn starting_curve() -> Curve<K> {
        let one = K::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let six = three.add(&three);

        Curve::from_coeffs(six, one)
    }

    /// Convert a curve (A : C) to (A' : C') ~ (A + 2C : 4C)
    #[inline]
    pub fn curve_plus(&self) -> Curve<K> {
        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);
        
        let a = two.mul(&self.c).add(&self.a);
        let c = four.mul(&self.c);

        Curve::from_coeffs(a, c)
    }

    /// Given convert a curve (A : C) to (A' : C') ~ (A + 2C : A - 2C)
    #[inline]
    pub fn curve_plus_minus(&self) -> Curve<K> {
        let one = K::one();
        let two = one.add(&one);
        
        let a = two.mul(&self.c).add(&self.a);
        let c = self.a.sub(&two.mul(&self.c));

        Curve::from_coeffs(a, c)
    }


    /// Montgomery j-invariant (ref Algorithm 9 p.56)
    #[inline]
    pub fn j_invariant(&self) -> K {
        let j = self.a.mul(&self.a); // 1.
        let t1 = self.c.mul(&self.c); //2.
        let t0 = t1.add(&t1); // 3.
        let t0 = j.sub(&t0); // 4.
        let t0 = t0.sub(&t1); //5.

        let j = t0.sub(&t1); // 6.
        let t1 = t1.mul(&t1); //7.
        let j = j.mul(&t1); // 8.
        let t0 = t0.add(&t0); // 9.
        let t0 = t0.add(&t0); // 10.

        let t1 = t0.mul(&t0); // 11.
        let t0 = t0.mul(&t1); // 12.
        let t0 = t0.add(&t0); // 13.
        let t0 = t0.add(&t0); // 14.
        let j = j.inv(); // 15.
        let j = t0.mul(&j);

        j
    }

    /// Generates a curve from three elements of 𝔽ₚ(i), or returns None
    /// (ref `cfpk` Algorithm 1.2.1 )
    #[inline]
    pub fn from_public_key(pk: &PublicKey<K>) -> Option<Curve<K>> {
        let (x_p, x_q, x_r) = (&pk.x1, &pk.x2, &pk.x3);

        // 1.
        if x_p.is_zero() || x_q.is_zero() || x_r.is_zero() {
            return None;
        }

        // 2.
        let one = K::one();
        let two = one.add(&one);
        let four = two.add(&two);

        let num = K::one()
            .sub(&x_p.mul(&x_q))
            .sub(&x_p.mul(&x_r))
            .sub(&x_q.mul(&x_r));
        let num = num.mul(&num);
        let denom = four.mul(&x_p).mul(&x_q).mul(&x_r);
        let frac = num.div(&denom);
        let a = frac.sub(&x_p).sub(&x_q).sub(&x_r);
        let c = one;

        // 3, 4.
        Some(Curve::from_coeffs(a, c))
    }
}

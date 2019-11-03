pub trait FiniteField {
    fn is_zero(&self) -> bool;
    fn dimension() -> usize;
    fn order() -> u128; // TODO: replace by BigInt
    fn zero() -> Self;
    fn one() -> Self;
    fn neg(&self) -> Self;
    fn inv(&self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn div(&self, other: &Self) -> Self;
}

#[derive(Clone)]
pub struct PrimeField {}

impl FiniteField for PrimeField {
    fn is_zero(&self) -> bool {
        unimplemented!()
    }
    fn dimension() -> usize {
        unimplemented!()
    }
    fn order() -> u128 {
        unimplemented!()
    }
    fn zero() -> Self {
        unimplemented!()
    }
    fn one() -> Self {
        unimplemented!()
    }
    fn neg(&self) -> Self {
        unimplemented!()
    }
    fn inv(&self) -> Self {
        unimplemented!()
    }
    fn add(&self, _other: &Self) -> Self {
        unimplemented!()
    }
    fn sub(&self, _other: &Self) -> Self {
        unimplemented!()
    }
    fn mul(&self, _other: &Self) -> Self {
        unimplemented!()
    }
    fn div(&self, _other: &Self) -> Self {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct QuadraticExtension<F: FiniteField> {
    a: F,
    b: F,
}

impl<F: FiniteField> FiniteField for QuadraticExtension<F> {
    fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }

    fn dimension() -> usize {
        2 * F::dimension()
    }

    fn order() -> u128 {
        F::order()
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
        let m1 = self.a.mul(&self.b);
        let m2 = other.a.mul(&other.b);

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
            b: inv_norm.mul(&self.b.inv()),
        }
    }
}

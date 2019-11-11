//! Points in projective coordinates

use crate::ff::FiniteField;
use std::fmt::{Debug, Formatter, Result};

/// Point defined by (X: Z) in projective coordinates
#[derive(Clone)]
pub struct Point<K: FiniteField + Clone> {
    /// X coordinate in projective space
    pub x: K,
    /// Z coordinate in projective space
    pub z: K,
}

impl<K: FiniteField + Clone + Debug> Debug for Point<K> {
    /// A point is represented as (x : z)
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "({:?}:{:?})", self.x, self.z)
    }
}

impl<K: FiniteField + Clone> Point<K> {
    /// Returns the points (x : 1)
    pub fn from_x(x: K) -> Self {
        Self { x, z: K::one() }
    }
}

impl<K: FiniteField + Clone> PartialEq<Self> for Point<K> {
    /// Two points are equal if (z != 0 and x/z) match, or if z = 0 for both
    fn eq(&self, other: &Self) -> bool {
        let other_zero = other.z.is_zero();
        if self.z.is_zero() {
            if other_zero {
                true
            } else {
                false
            }
        } else if other_zero {
            false
        } else {
            self.x.div(&self.z).equals(&other.x.div(&other.z))
        }
    }
}

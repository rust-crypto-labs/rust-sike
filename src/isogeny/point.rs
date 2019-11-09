use crate::ff::FiniteField;
use std::fmt::{Debug, Formatter, Result};

/// Point defined by (X: Z) in projective coordinates
#[derive(Clone)]
pub struct Point<K: FiniteField + Clone> {
    pub x: K,
    pub z: K,
}

impl<K: FiniteField + Clone + Debug> Debug for Point<K> {
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

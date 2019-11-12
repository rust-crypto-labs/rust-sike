//! Public key material

use crate::ff::FiniteField;

/// Public key
/// 
/// The public key is a curve, but can be represented as a triple of points, of which only
/// the x-coordinate is stored. 
#[derive(Clone)]
pub struct PublicKey<K: FiniteField> {
    /// First point
    pub x1: K,

    /// Second point
    pub x2: K,

    /// Third point
    pub x3: K,
}

impl<K: FiniteField + std::fmt::Debug> std::fmt::Debug for PublicKey<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}, {:?}, {:?}", self.x1, self.x2, self.x3)
    }
}

impl<K: FiniteField> PublicKey<K> {
    /// Converts the public key to a sequence of bytes (for each point)
    pub fn to_bytes(self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (self.x1.to_bytes(), self.x2.to_bytes(), self.x3.to_bytes())
    }

    /// Creates a new public key for given three points (represented as bytes)
    pub fn from_bytes(part1: &[u8], part2: &[u8], part3: &[u8]) -> Self {
        Self {
            x1: K::from_bytes(part1),
            x2: K::from_bytes(part2),
            x3: K::from_bytes(part3),
        }
    }
}

impl<K: FiniteField> std::cmp::PartialEq for PublicKey<K> {
    fn eq(&self, other: &Self) -> bool {
        self.x1.equals(&other.x1) && self.x2.equals(&other.x2) && self.x3.equals(&other.x3)
    }
}

//! Public parameters

use crate::utils::strategy;

/// Public parameters
#[derive(Clone)]
pub struct PublicParameters<K> {
    /// Security parameter (curve-dependent)
    pub secparam: usize,

    /// Tree-traversal strategy for the 2-torsion
    pub e2_strategy: Option<strategy::Torsion2Strategy>,

    /// Tree-traversal strategy for the 3-torsion
    pub e3_strategy: Option<strategy::Torsion3Strategy>,

    /// Exponent of 2 in the prime modulus
    pub e2: u64,

    /// Exponent of 3 in the prime modulus
    pub e3: u64,

    /// x-coordinate of the point P2
    pub xp2: K,

    /// x-coordinate of the point Q2
    pub xq2: K,

    /// x-coordinate of the point R2
    pub xr2: K,

    /// x-coordinate of the point P3
    pub xp3: K,

    /// x-coordinate of the point Q3
    pub xq3: K,

    /// x-coordinate of the point R3
    pub xr3: K,
}

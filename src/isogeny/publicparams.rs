//! Public parameters

use crate::constants::{cs_p434::*, cs_p503::*, cs_p610::*, cs_p751::*};
use crate::ff::{
    QuadraticExtension,
    {
        ff_p434::PrimeFieldP434, ff_p503::PrimeFieldP503, ff_p610::PrimeFieldP610,
        ff_p751::PrimeFieldP751,
    },
};
use crate::utils::{conversion::*, strategy};

/// Public parameters
#[derive(Clone)]
pub struct PublicParameters<K> {
    /// Security parameter (curve-dependent)
    pub secparam: usize,

    /// Size of K_2 keyspace for sk2 generation;
    pub keyspace2: u64,

    /// Size of K_3 keyspace fir sk3 generation;
    pub keyspace3: u64,

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

/// Load params for SIKE_p434
pub fn sike_p434_params(
    strat2tor: Option<strategy::Torsion2Strategy>,
    strat3tor: Option<strategy::Torsion3Strategy>,
) -> Result<PublicParameters<QuadraticExtension<PrimeFieldP434>>, String> {
    Ok(PublicParameters {
        secparam: 128,
        keyspace2: str_to_u64(SIKE_P434_NKS2),
        keyspace3: str_to_u64(SIKE_P434_NKS3),
        e2_strategy: strat2tor,
        e3_strategy: strat3tor,
        e2: str_to_u64(SIKE_P434_E2),
        e3: str_to_u64(SIKE_P434_E3),
        xp2: str_to_p434(SIKE_P434_XP20, SIKE_P434_XP21)?,
        xq2: str_to_p434(SIKE_P434_XQ20, SIKE_P434_XQ21)?,
        xr2: str_to_p434(SIKE_P434_XR20, SIKE_P434_XR21)?,
        xp3: str_to_p434(SIKE_P434_XP30, SIKE_P434_XP31)?,
        xq3: str_to_p434(SIKE_P434_XQ30, SIKE_P434_XQ31)?,
        xr3: str_to_p434(SIKE_P434_XR30, SIKE_P434_XR31)?,
    })
}

/// Load params for SIKE_p503
pub fn sike_p503_params(
    strat2tor: Option<strategy::Torsion2Strategy>,
    strat3tor: Option<strategy::Torsion3Strategy>,
) -> Result<PublicParameters<QuadraticExtension<PrimeFieldP503>>, String> {
    Ok(PublicParameters {
        secparam: 192,
        keyspace2: str_to_u64(SIKE_P503_NKS2),
        keyspace3: str_to_u64(SIKE_P503_NKS3),
        e2_strategy: strat2tor,
        e3_strategy: strat3tor,
        e2: str_to_u64(SIKE_P503_E2),
        e3: str_to_u64(SIKE_P503_E3),
        xp2: str_to_p503(SIKE_P503_XP20, SIKE_P503_XP21)?,
        xq2: str_to_p503(SIKE_P503_XQ20, SIKE_P503_XQ21)?,
        xr2: str_to_p503(SIKE_P503_XR20, SIKE_P503_XR21)?,
        xp3: str_to_p503(SIKE_P503_XP30, SIKE_P503_XP31)?,
        xq3: str_to_p503(SIKE_P503_XQ30, SIKE_P503_XQ31)?,
        xr3: str_to_p503(SIKE_P503_XR30, SIKE_P503_XR31)?,
    })
}

/// Load params for SIKE_p610
pub fn sike_p610_params(
    strat2tor: Option<strategy::Torsion2Strategy>,
    strat3tor: Option<strategy::Torsion3Strategy>,
) -> Result<PublicParameters<QuadraticExtension<PrimeFieldP610>>, String> {
    Ok(PublicParameters {
        secparam: 192,
        keyspace2: str_to_u64(SIKE_P610_NKS2),
        keyspace3: str_to_u64(SIKE_P610_NKS3),
        e2_strategy: strat2tor,
        e3_strategy: strat3tor,
        e2: str_to_u64(SIKE_P610_E2),
        e3: str_to_u64(SIKE_P610_E3),
        xp2: str_to_p610(SIKE_P610_XP20, SIKE_P610_XP21)?,
        xq2: str_to_p610(SIKE_P610_XQ20, SIKE_P610_XQ21)?,
        xr2: str_to_p610(SIKE_P610_XR20, SIKE_P610_XR21)?,
        xp3: str_to_p610(SIKE_P610_XP30, SIKE_P610_XP31)?,
        xq3: str_to_p610(SIKE_P610_XQ30, SIKE_P610_XQ31)?,
        xr3: str_to_p610(SIKE_P610_XR30, SIKE_P610_XR31)?,
    })
}

/// Load params for SIKE_p751
pub fn sike_p751_params(
    strat2tor: Option<strategy::Torsion2Strategy>,
    strat3tor: Option<strategy::Torsion3Strategy>,
) -> Result<PublicParameters<QuadraticExtension<PrimeFieldP751>>, String> {
    Ok(PublicParameters {
        secparam: 256,
        keyspace2: str_to_u64(SIKE_P751_NKS2),
        keyspace3: str_to_u64(SIKE_P751_NKS3),
        e2_strategy: strat2tor,
        e3_strategy: strat3tor,
        e2: str_to_u64(SIKE_P751_E2),
        e3: str_to_u64(SIKE_P751_E3),
        xp2: str_to_p751(SIKE_P751_XP20, SIKE_P751_XP21)?,
        xq2: str_to_p751(SIKE_P751_XQ20, SIKE_P751_XQ21)?,
        xr2: str_to_p751(SIKE_P751_XR20, SIKE_P751_XR21)?,
        xp3: str_to_p751(SIKE_P751_XP30, SIKE_P751_XP31)?,
        xq3: str_to_p751(SIKE_P751_XQ30, SIKE_P751_XQ31)?,
        xr3: str_to_p751(SIKE_P751_XR30, SIKE_P751_XR31)?,
    })
}

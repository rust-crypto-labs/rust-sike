use crate::utils::strategy;

#[derive(Clone)]
pub struct PublicParameters<K> {
    pub secparam: usize,
    pub e2_strategy: Option<strategy::Torsion2Strategy>,
    pub e3_strategy: Option<strategy::Torsion3Strategy>,
    pub e2: u64,
    pub e3: u64,
    pub xp2: K,
    pub xq2: K,
    pub xr2: K,
    pub xp3: K,
    pub xq3: K,
    pub xr3: K,
}

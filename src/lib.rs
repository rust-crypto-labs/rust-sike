mod ff;
mod kem;
mod pke;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn test_strategy_2tor() {
        use crate::utils::strategy;

        let n4 = 107;
        let p4 = 5633;
        let q4 = 5461;

        let p434strat = strategy::compute_strategy(n4, p4, q4);

        // C.1.1.
        let reference = vec![
            48, 28, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2,
            1, 1, 2, 1, 1, 13, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2,
            1, 1, 1, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1,
            1, 1, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1,
        ];

        assert_eq!(reference, p434strat);
    }

    #[test]
    fn test_strategy_3tor() {
        use crate::utils::strategy;

        let n3 = 136;
        let p3 = 5322;
        let q3 = 5282;

        let p434strat = strategy::compute_strategy(n3, p3, q3);

        // C.1.2.
        let reference = vec![
            66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1,
            1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8,
            4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2,
            1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1,
            4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1,
        ];

        assert_eq!(reference, p434strat);
    }

    #[test]
    fn test_kem() {
        use crate::{
            kem::KEM,
            utils::{constants::*, conversion::*, PublicParameters},
        };

        let seclevel = 256;

        let params = PublicParameters {
            secparam: 128,
            e2: str_to_u64(SIKE_P434_E2),
            e3: str_to_u64(SIKE_P434_E3),
            xp2: str_to_p434(SIKE_P434_XP20, SIKE_P434_XP21),
            xq2: str_to_p434(SIKE_P434_XQ20, SIKE_P434_XQ21),
            xr2: str_to_p434(SIKE_P434_XR20, SIKE_P434_XR21),
            xp3: str_to_p434(SIKE_P434_XP30, SIKE_P434_XP31),
            xq3: str_to_p434(SIKE_P434_XQ30, SIKE_P434_XQ31),
            xr3: str_to_p434(SIKE_P434_XR30, SIKE_P434_XR31),
        };

        let kem = KEM::setup(params, seclevel);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3);

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c);

        assert_eq!(k, k_recovered);
    }
}

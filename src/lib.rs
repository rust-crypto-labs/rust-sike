mod ff;
mod kem;
mod pke;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn test_kem() {
        use crate::{
            kem::KEM,
            utils::{constants::*, conversion::*, PublicParameters},
        };

        let seclevel = 256;

        let params = PublicParameters {
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

        // TODO: check that k == k_recovered
    }
}

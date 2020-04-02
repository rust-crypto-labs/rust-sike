//! Key encapsulation mechanism
//!
//! # Examples
//! ```rust
//! use rust_sike::{self, KEM};
//! let params = rust_sike::sike_p434_params(None, None);
//!
//! let kem = KEM::setup(params);
//!
//! // Alice runs keygen, publishes pk3. Values s and sk3 are secret
//! let (s, sk3, pk3) = kem.keygen();
//!
//! // Bob uses pk3 to derive a key k and encapsulation c
//! let (c, k) = kem.encaps(&pk3);
//!
//! // Bob sends c to Alice
//! // Alice uses s, c, sk3 and pk3 to recover k
//! let k_recovered = kem.decaps(&s, &sk3, &pk3, c);
//!
//! assert_eq!(k, k_recovered);
//! ```

use crate::{
    ff::FiniteField,
    isogeny::{PublicKey, PublicParameters, SecretKey},
    pke::{Ciphertext, Message, PKE},
    utils::{conversion, shake},
};

use rand::prelude::*;

use std::fmt::Debug;

/// Key-encapsulation mechanism (ref Algorithm 2, Section 1.3.10)
pub struct KEM<K> {
    params: PublicParameters<K>,
    pke: PKE<K>,
    n: usize,
}

impl<K: FiniteField + Clone + Debug> KEM<K> {
    /// Initialise the KEM
    #[inline]
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            pke: PKE::setup(params.clone()),
            n: params.secparam,
            params,
        }
    }

    /// Generate a secret and a keypair
    #[inline]
    pub fn keygen(&self) -> Result<(Vec<u8>, SecretKey, PublicKey<K>), String> {
        let sk3 = SecretKey::get_random_secret_key(self.params.keyspace3 as usize)?;
        let pk3 = self.pke.isogenies.isogen3(&sk3)?;
        let s = Self::random_string(self.n);

        Ok((s, sk3, pk3))
    }

    /// Encapsulate the shared secret using the PKE encryption
    #[inline]
    pub fn encaps(&self, pk: &PublicKey<K>) -> Result<(Ciphertext, Vec<u8>), String> {
        let message = Message::from_bytes(Self::random_string(self.n / 8));
        let r = self.hash_function_g(&message.clone(), &pk);
        let det_sk = SecretKey::from_bytes(&r);

        let c0: PublicKey<K> = self.pke.isogenies.isogen2(&det_sk)?;

        let j_inv = self.pke.isogenies.isoex2(&det_sk, &pk);
        let h = self.pke.hash_function_f(j_inv);

        assert_eq!(h.len(), message.bytes.len());
        let c1_bytes = PKE::<K>::xor(&message.bytes, &h);

        let (part1, part2, part3) = c0.into_bytes();
        let cipher = Ciphertext {
            bytes00: part1,
            bytes01: part2,
            bytes02: part3,
            bytes1: c1_bytes,
        };

        let k = self.hash_function_h(&message, &cipher);
        Ok((cipher, k))
    }

    /// Decapsulate the shared secret using the PKE decryption
    #[inline]
    pub fn decaps(
        &self,
        s: &[u8],
        sk: &SecretKey,
        pk: &PublicKey<K>,
        c: Ciphertext,
    ) -> Result<Vec<u8>, String> {
        let m = self.pke.dec(&sk, c.clone())?;
        let s = Message::from_bytes(s.to_vec());
        let r = self.hash_function_g(&m.clone(), &pk);

        let c0 = PublicKey::from_bytes(&c.bytes00, &c.bytes01, &c.bytes02)?;
        let rsk = SecretKey::from_bytes(&r);

        let c0p = self.pke.isogenies.isogen2(&rsk)?;

        if c0p == c0 {
            Ok(self.hash_function_h(&m, &c))
        } else {
            Ok(self.hash_function_h(&s, &c))
        }
    }

    fn random_string(size: usize) -> Vec<u8> {
        let mut result = vec![0; size];
        rand::rngs::OsRng.fill_bytes(&mut result);
        result
    }

    fn hash_function_g(&self, m: &Message, pk: &PublicKey<K>) -> Vec<u8> {
        let (part1, part2, part3) = pk.clone().into_bytes();
        let msg_bytes = m.clone().into_bytes();
        let input = conversion::concatenate(&[&msg_bytes, &part1, &part2, &part3]);

        let n: usize = self.params.secparam;

        shake::shake256(&input, n / 8)
    }

    fn hash_function_h(&self, m: &Message, c: &Ciphertext) -> Vec<u8> {
        let input = conversion::concatenate(&[
            &m.clone().into_bytes(),
            &c.bytes00,
            &c.bytes01,
            &c.bytes02,
            &c.bytes1,
        ]);

        let n = self.params.secparam;

        shake::shake256(&input, n / 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        isogeny::{sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params},
        utils::strategy::*,
    };

    #[test]
    fn test_kem_p434() {
        let params = sike_p434_params(None, None).unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p503() {
        let params = sike_p503_params(None, None).unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p610() {
        let params = sike_p610_params(None, None).unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p751() {
        let params = sike_p751_params(None, None).unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_optim_p434() {
        let params = sike_p434_params(
            Some(P434_TWO_TORSION_STRATEGY.to_vec()),
            Some(P434_THREE_TORSION_STRATEGY.to_vec()),
        )
        .unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_optim_p503() {
        let params = sike_p503_params(
            Some(P503_TWO_TORSION_STRATEGY.to_vec()),
            Some(P503_THREE_TORSION_STRATEGY.to_vec()),
        )
        .unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_optim_p610() {
        let params = sike_p610_params(
            Some(P610_TWO_TORSION_STRATEGY.to_vec()),
            Some(P610_THREE_TORSION_STRATEGY.to_vec()),
        )
        .unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_optim_p751() {
        let params = sike_p751_params(
            Some(P751_TWO_TORSION_STRATEGY.to_vec()),
            Some(P751_THREE_TORSION_STRATEGY.to_vec()),
        )
        .unwrap();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }
}

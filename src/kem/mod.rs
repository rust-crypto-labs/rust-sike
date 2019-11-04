use crate::{
    ff::FiniteField,
    pke::{Ciphertext, Message, PKE},
    utils::{
        constants::SIKE_P434_NKS3, conversion::str_to_u64, shake, PublicKey, PublicParameters,
        SecretKey,
    },
};

use std::convert::TryInto;

pub struct KEM<K> {
    params: PublicParameters<K>,
    pke: PKE<K>,
    n: usize,
}

impl<K: FiniteField + Copy> KEM<K> {
    pub fn setup(params: PublicParameters<K>, n: usize) -> Self {
        Self {
            pke: PKE::setup(params.clone()),
            n,
            params,
        }
    }

    pub fn keygen(&self) -> (Vec<u8>, SecretKey, PublicKey<K>) {
        let nsk3 = str_to_u64(SIKE_P434_NKS3);
        let sk3 = SecretKey::get_random_secret_key(nsk3);
        let pk3 = self.pke.isogenies.isogen3(&sk3);
        let s = Self::random_string(self.n);

        (s, sk3, pk3)
    }

    pub fn encaps(&self, pk: &PublicKey<K>) -> (Ciphertext, Vec<u8>) {
        let m = Message::from_bytes(Self::random_string(self.n));
        let r = self.hash_function_g(&m.clone(), &pk);

        // Algorithm 2, Encaps, Line 7: is it m, r, or some combination!?
        let c = self.pke.enc(&pk, Message::from_bytes(r));

        let k = self.hash_function_h(&m.clone(), &c);
        (c, k)
    }

    pub fn decaps(&self, s: &[u8], sk: &SecretKey, pk: &PublicKey<K>, c: Ciphertext) -> Vec<u8> {
        let m = self.pke.dec(&sk, c.clone());
        let s = Message::from_bytes(s.to_vec());
        let r = self.hash_function_g(&m.clone(), &pk);

        let c0 = PublicKey::from_bytes(&c.bytes0);
        let rsk = SecretKey::from_bytes(&r);

        let c0p = self.pke.isogenies.isogen2(&rsk);

        let k = if c0p == c0 {
            self.hash_function_h(&m, &c)
        } else {
            self.hash_function_h(&s, &c)
        };

        k
    }

    fn random_string(size: usize) -> Vec<u8> {
        unimplemented!()
    }

    fn hash_function_g(&self, m: &Message, r: &PublicKey<K>) -> Vec<u8> {
        let input = shake::concatenate(&[&m.clone().to_bytes(), &r.clone().to_bytes()]);
        let n = self.params.e2.try_into().unwrap();

        shake::shake256(&input, n)
    }

    fn hash_function_h(&self, m: &Message, c: &Ciphertext) -> Vec<u8> {
        let input = shake::concatenate(&[&m.clone().to_bytes(), &c.bytes0, &c.bytes1]);

        let n = self.params.secparam;

        shake::shake256(&input, n)
    }
}

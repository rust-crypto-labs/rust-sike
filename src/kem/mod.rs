//! Key encapsulation mechanism

use crate::{
    ff::FiniteField,
    isogeny::{PublicKey, PublicParameters, SecretKey},
    pke::{Ciphertext, Message, PKE},
    utils::{conversion, shake},
};

use rand::prelude::*;

use std::{convert::TryInto, fmt::Debug};

/// Key-encapsulation mechanism (ref Algorithm 2, Section 1.3.10)
pub struct KEM<K> {
    params: PublicParameters<K>,
    pke: PKE<K>,
    n: usize,
}

impl<K: FiniteField + Clone + Debug> KEM<K> {
    /// Initialise the KEM
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            pke: PKE::setup(params.clone()),
            n: params.secparam,
            params,
        }
    }

    /// Generate a secret and a keypair
    pub fn keygen(&self) -> (Vec<u8>, SecretKey, PublicKey<K>) {
        let sk3 = SecretKey::get_random_secret_key(self.params.keyspace3 as usize);
        let pk3 = self.pke.isogenies.isogen3(&sk3, &self.params.e3_strategy);
        let s = Self::random_string(self.n);

        (s, sk3, pk3)
    }

    /// Encapsulate the shared secret using the PKE encryption
    pub fn encaps(&self, pk: &PublicKey<K>) -> (Ciphertext, Vec<u8>) {
        let m = Message::from_bytes(Self::random_string(self.n));
        let r = self.hash_function_g(&m.clone(), &pk);

        // Algorithm 2, Encaps, Line 7: is it m, r, or some combination!?
        let c = self.pke.enc(&pk, Message::from_bytes(r));

        let k = self.hash_function_h(&m.clone(), &c);
        (c, k)
    }

    /// Decapsulate the shared secret using the PKE decryption
    pub fn decaps(&self, s: &[u8], sk: &SecretKey, pk: &PublicKey<K>, c: Ciphertext) -> Vec<u8> {
        let m = self.pke.dec(&sk, c.clone());
        let s = Message::from_bytes(s.to_vec());
        let r = self.hash_function_g(&m.clone(), &pk);

        let c0 = PublicKey::from_bytes(&c.bytes00, &c.bytes01, &c.bytes02);
        let rsk = SecretKey::from_bytes(&r);

        let c0p = self.pke.isogenies.isogen2(&rsk, &self.params.e2_strategy);

        let k = if c0p == c0 {
            self.hash_function_h(&m, &c)
        } else {
            self.hash_function_h(&s, &c)
        };

        k
    }

    fn random_string(size: usize) -> Vec<u8> {
        let mut result = vec![0; size];
        rand::rngs::OsRng.fill_bytes(&mut result);
        result
    }

    fn hash_function_g(&self, m: &Message, r: &PublicKey<K>) -> Vec<u8> {
        let (part1, part2, part3) = r.clone().to_bytes();
        let msg_bytes = m.clone().to_bytes();
        let input = conversion::concatenate(&[&msg_bytes, &part1, &part2, &part3]);

        let n: usize = self.params.e2.try_into().unwrap();

        shake::shake256(&input, n / 8)
    }

    fn hash_function_h(&self, m: &Message, c: &Ciphertext) -> Vec<u8> {
        let input = conversion::concatenate(&[
            &m.clone().to_bytes(),
            &c.bytes00,
            &c.bytes01,
            &c.bytes02,
            &c.bytes1,
        ]);

        let n = self.params.secparam;

        shake::shake256(&input, n / 8)
    }
}

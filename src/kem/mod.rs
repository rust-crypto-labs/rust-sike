use crate::{
    ff::FiniteField,
    pke::{Ciphertext, Message, PKE},
    utils::{PublicKey, PublicParameters, SecretKey},
};

const NSK2: usize = 10; // TODO: see 1.3.8
const NSK3: usize = 10; // TODO: see 1.3.8

pub struct KEM<K> {
    pke: PKE<K>,
    n: usize,
}

impl<K: FiniteField + Copy> KEM<K> {
    pub fn setup(params: PublicParameters<K>, n: usize) -> Self {
        Self {
            pke: PKE::setup(params),
            n,
        }
    }

    pub fn keygen(&self) -> (Vec<bool>, SecretKey, PublicKey<K>) {
        let sk3 = SecretKey::get_random_secret_key(NSK3);
        let pk3 = self.pke.isogenies.isogen3(&sk3);
        let s = Self::random_string(self.n);

        (s, sk3, pk3)
    }

    pub fn encaps(&self, pk: &PublicKey<K>) -> (Ciphertext, Vec<bool>) {
        let m = Message::from_bits(Self::random_string(self.n));
        let r = Self::hash_function_g(&m.clone(), &pk);

        // Algorithm 2, Encaps, Line 7: is it m, r, or some combination!?
        let c = self.pke.enc(&pk, Message::from_bits(r));

        let k = Self::hash_function_h(&m.clone(), &c);
        (c, k)
    }

    pub fn decaps(
        &self,
        s: &[bool],
        sk: &SecretKey,
        pk: &PublicKey<K>,
        c: Ciphertext,
    ) -> Vec<bool> {
        let m = self.pke.dec(&sk, c.clone());
        let s = Message::from_bits(s.to_vec());
        let r = Self::hash_function_g(&m.clone(), &pk);

        let c0 = PublicKey::from_bits(&c.bits0);
        let rsk = SecretKey::from_bits(&r);

        let c0p = self.pke.isogenies.isogen2(&rsk);

        let k = if c0p == c0 {
            Self::hash_function_h(&m, &c)
        } else {
            Self::hash_function_h(&s, &c)
        };

        k
    }

    fn random_string(size: usize) -> Vec<bool> {
        unimplemented!()
    }

    fn hash_function_g(m: &Message, r: &PublicKey<K>) -> Vec<bool> {
        // Refer to 1.4.
        unimplemented!()
    }

    fn hash_function_h(m: &Message, c: &Ciphertext) -> Vec<bool> {
        // Refer to 1.4.
        unimplemented!()
    }
}

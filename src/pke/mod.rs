use crate::{
    ff::FiniteField,
    utils::{CurveIsogenies, PublicKey, SecretKey},
};

const NSK2: usize = 10; // TODO: see 1.3.8
const NSK3: usize = 10; // TODO: see 1.3.8

pub struct Message {
    bits: Vec<bool>,
}

pub struct Ciphertext {
    bits0: Vec<bool>,
    bits1: Vec<bool>,
}

pub struct PKE<K> {
    isogenies: CurveIsogenies<K>,
}

/// Algorithm 1, Section 1.3.9
impl<K: FiniteField + Copy> PKE<K> {
    pub fn setup() -> Self {
        unimplemented!()
    }

    pub fn gen(&self) -> (SecretKey, PublicKey<K>) {
        let sk3 = SecretKey::get_random_secret_key(NSK3);
        let pk3 = self.isogenies.isogen3(&sk3);
        (sk3, pk3)
    }

    pub fn enc(&self, pk: &PublicKey<K>, m: Message) -> Ciphertext {
        let sk2 = SecretKey::get_random_secret_key(NSK2);
        let c0: PublicKey<K> = self.isogenies.isogen2(&sk2);
        let j = self.isogenies.isoex2(&sk2, &pk);

        let c0_bits = c0.to_bits();
        let h = Self::hash_j_invariant(j, c0_bits.len());
        let c1_bits = Self::xor(&m.bits, &h);

        Ciphertext {
            bits0: c0_bits,
            bits1: c1_bits,
        }
    }

    pub fn dec(&self, sk: &SecretKey, c: Ciphertext) -> Message {
        let j: K = self.isogenies.isoex3(sk, &PublicKey::from_bits(&c.bits0));
        let h = Self::hash_j_invariant(j, c.bits1.len());
        let m = Self::xor(&h, &c.bits1);

        Message { bits: m }
    }

    fn hash_j_invariant(_j: K, _size: usize) -> Vec<bool> {
        unimplemented!()
    }

    fn xor(_input1: &[bool], _input2: &[bool]) -> Vec<bool> {
        unimplemented!()
    }
}

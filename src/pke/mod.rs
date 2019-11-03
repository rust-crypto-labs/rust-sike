use crate::{
    ff::FiniteField,
    utils::{Curve, PublicKey, SecretKey},
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

pub struct PKE {}

/// Algorithm 1, Section 1.3.9
impl PKE {
    pub fn gen<K: FiniteField + Clone>() -> (SecretKey, PublicKey<K>) {
        let sk3 = SecretKey::get_random_secret_key(NSK3);
        let pk3 = Curve::isogen3(&sk3);
        (sk3, pk3)
    }

    pub fn enc<K: FiniteField + Clone>(pk: &PublicKey<K>, m: Message) -> Ciphertext {
        let sk2 = SecretKey::get_random_secret_key(NSK2);
        let c0: PublicKey<K> = Curve::isogen2(&sk2);
        let j = Curve::isoex2(&sk2, &pk);

        let c0_bits = c0.to_bits();
        let h = Self::hash_j_invariant(j, c0_bits.len());
        let c1_bits = Self::xor(&c0_bits, &h);

        Ciphertext {
            bits0: c0_bits,
            bits1: c1_bits,
        }
    }

    pub fn dec<K: FiniteField + Clone>(sk: &SecretKey, c: Ciphertext) -> Message {
        let j: K = Curve::isoex3(sk, &PublicKey::from_bits(&c.bits0));
        let h = Self::hash_j_invariant(j, c.bits1.len());
        let m = Self::xor(&h, &c.bits1);

        Message { bits: m }
    }

    fn hash_j_invariant<K: FiniteField>(j: K, size: usize) -> Vec<bool> {
        unimplemented!()
    }

    fn xor(input1: &[bool], input2: &[bool]) -> Vec<bool> {
        unimplemented!()
    }
}

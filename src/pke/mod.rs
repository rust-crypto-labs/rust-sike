use crate::{
    ff::FiniteField,
    utils::{CurveIsogenies, PublicKey, PublicParameters, SecretKey},
};

const NSK2: usize = 10; // TODO: see 1.3.8
const NSK3: usize = 10; // TODO: see 1.3.8

#[derive(Clone)]
pub struct Message {
    bits: Vec<bool>,
}

impl Message {
    pub fn from_bits(bits: Vec<bool>) -> Self {
        Self { bits }
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    pub bits0: Vec<bool>,
    bits1: Vec<bool>,
}

pub struct PKE<K> {
    pub isogenies: CurveIsogenies<K>,
}

/// Algorithm 1, Section 1.3.9
impl<K: FiniteField + Copy> PKE<K> {
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            isogenies: CurveIsogenies::init(params),
        }
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
        let h = Self::hash_function_f(j, c0_bits.len());
        let c1_bits = Self::xor(&m.bits, &h);

        Ciphertext {
            bits0: c0_bits,
            bits1: c1_bits,
        }
    }

    pub fn dec(&self, sk: &SecretKey, c: Ciphertext) -> Message {
        let j: K = self.isogenies.isoex3(sk, &PublicKey::from_bits(&c.bits0));
        let h = Self::hash_function_f(j, c.bits1.len());
        let m = Self::xor(&h, &c.bits1);

        Message { bits: m }
    }

    fn hash_function_f(_j: K, _size: usize) -> Vec<bool> {
        // Refer to 1.4.
        unimplemented!()
    }

    fn xor(_input1: &[bool], _input2: &[bool]) -> Vec<bool> {
        unimplemented!()
    }
}

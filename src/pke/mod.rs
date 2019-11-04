use crate::{
    ff::FiniteField,
    utils::{shake, CurveIsogenies, PublicKey, PublicParameters, SecretKey},
};

const NSK2: usize = 10; // TODO: see 1.3.8
const NSK3: usize = 10; // TODO: see 1.3.8

#[derive(Clone)]
pub struct Message {
    bytes: Vec<u8>,
}

impl Message {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    pub bytes0: Vec<u8>,
    pub bytes1: Vec<u8>,
}

pub struct PKE<K> {
    pub isogenies: CurveIsogenies<K>,
    params: PublicParameters<K>,
}

/// Algorithm 1, Section 1.3.9
impl<K: FiniteField + Copy> PKE<K> {
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            isogenies: CurveIsogenies::init(params.clone()),
            params,
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

        let c0_bytes = c0.to_bytes();
        let h = self.hash_function_f(j);
        let c1_bytes = Self::xor(&m.bytes, &h);

        Ciphertext {
            bytes0: c0_bytes,
            bytes1: c1_bytes,
        }
    }

    pub fn dec(&self, sk: &SecretKey, c: Ciphertext) -> Message {
        let j: K = self.isogenies.isoex3(sk, &PublicKey::from_bytes(&c.bytes0));
        let h = self.hash_function_f(j);
        let m = Self::xor(&h, &c.bytes1);

        Message { bytes: m }
    }

    fn hash_function_f(&self, j: K) -> Vec<u8> {
        shake::shake256(&j.to_bytes(), self.params.secparam)
    }

    fn xor(input1: &[u8],input2: &[u8]) -> Vec<u8> {
        let mut result = vec![];
        let couples = input1.iter().zip(input2.iter());

        for (pos, (x, y)) in couples.enumerate() {
            result[pos] = x ^ y;
        }

        result
    }
}

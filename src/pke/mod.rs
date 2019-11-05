use crate::{
    ff::FiniteField,
    isogeny::{CurveIsogenies, PublicKey, PublicParameters, SecretKey},
    utils::{
        constants::{SIKE_P434_NKS2, SIKE_P434_NKS3},
        conversion::str_to_u64,
        shake,
    },
};

use std::fmt::Debug;

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
    pub bytes00: Vec<u8>,
    pub bytes01: Vec<u8>,
    pub bytes02: Vec<u8>,
    pub bytes1: Vec<u8>,
}

pub struct PKE<K> {
    pub isogenies: CurveIsogenies<K>,
    params: PublicParameters<K>,
}

/// Algorithm 1, Section 1.3.9
impl<K: FiniteField + Clone + Debug> PKE<K> {
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            isogenies: CurveIsogenies::init(params.clone()),
            params,
        }
    }

    pub fn gen(&self) -> (SecretKey, PublicKey<K>) {
        // 1.
        let nks3 = str_to_u64(SIKE_P434_NKS3);
        let sk3 = SecretKey::get_random_secret_key(nks3 as usize);

        // 2.
        let pk3 = self.isogenies.isogen3(&sk3);

        // 3.
        (sk3, pk3)
    }

    pub fn enc(&self, pk: &PublicKey<K>, m: Message) -> Ciphertext {
        // 4.
        let nks2 = str_to_u64(SIKE_P434_NKS2);
        let sk2 = SecretKey::get_random_secret_key(nks2 as usize);

        // 5.        
        let c0: PublicKey<K> = self.isogenies.isogen2(&sk2);

        // 6.
        let j = self.isogenies.isoex2(&sk2, &pk);

        // 7.
        let h = self.hash_function_f(j);

        // 8.
        assert_eq!(h.len(), m.bytes.len());
        let c1_bytes = Self::xor(&m.bytes, &h);

        // 9.
        let (part1, part2, part3) = c0.to_bytes();
        Ciphertext {
            bytes00: part1,
            bytes01: part2,
            bytes02: part3,
            bytes1: c1_bytes,
        }
    }

    pub fn dec(&self, sk: &SecretKey, c: Ciphertext) -> Message {
        // 10.
        let c0 = &PublicKey::from_bytes(&c.bytes00, &c.bytes01, &c.bytes02);
        let j: K = self.isogenies.isoex3(
            sk,
            c0
        );

        // 11.        
        let h = self.hash_function_f(j);

        // 12.
        assert_eq!(h.len(), c.bytes1.len());
        let m = Self::xor(&h, &c.bytes1);

        // 13.
        Message { bytes: m }
    }

    fn hash_function_f(&self, j: K) -> Vec<u8> {
        shake::shake256(&j.to_bytes(), self.params.secparam / 8)
    }

    fn xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
        let mut result = vec![0; input1.len()];
        let couples = input1.iter().zip(input2.iter());

        for (pos, (x, y)) in couples.enumerate() {
            result[pos] = x ^ y;
        }

        result
    }
}

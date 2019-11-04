use crate::{
    ff::FiniteField,
    isogeny::{CurveIsogenies, PublicKey, PublicParameters, SecretKey},
    utils::{
        constants::{SIKE_P434_NKS2, SIKE_P434_NKS3},
        conversion::str_to_u64,
        shake,
    },
};

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
impl<K: FiniteField + Clone> PKE<K> {
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            isogenies: CurveIsogenies::init(params.clone()),
            params,
        }
    }

    pub fn gen(&self) -> (SecretKey, PublicKey<K>) {
        let nks3 = str_to_u64(SIKE_P434_NKS3);
        let sk3 = SecretKey::get_random_secret_key(nks3 as usize);
        let pk3 = self.isogenies.isogen3(&sk3);
        (sk3, pk3)
    }

    pub fn enc(&self, pk: &PublicKey<K>, m: Message) -> Ciphertext {
        let nks2 = str_to_u64(SIKE_P434_NKS2);
        let sk2 = SecretKey::get_random_secret_key(nks2 as usize);
        let c0: PublicKey<K> = self.isogenies.isogen2(&sk2);
        let j = self.isogenies.isoex2(&sk2, &pk);

        let c0_bytes = c0.to_bytes();
        let h = self.hash_function_f(j);

        if h.len() != m.bytes.len() {
            panic!("Message should be the same length as the output of F.")
        }

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
        shake::shake256(&j.to_bytes(), self.params.secparam / 8)
    }

    fn xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
        let mut result = vec![];
        let couples = input1.iter().zip(input2.iter());

        for (pos, (x, y)) in couples.enumerate() {
            result[pos] = x ^ y;
        }

        result
    }
}

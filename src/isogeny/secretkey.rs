use crate::utils::conversion;
use bitvec::prelude::*;
use rand::prelude::*;

#[derive(Clone, PartialEq)]
/// Secret key
pub struct SecretKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.bytes)
    }
}

impl SecretKey {
    pub fn get_random_secret_key(size: usize) -> Self {
        let mut bytes = vec![0; size];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes)
    }

    pub fn to_bits(&self) -> Vec<bool> {
        let mut result = vec![];
        // We reverse the order of the bytes
        // such that bits are properly ordered
        //      Ex : [1, 0] -> [00000000, 00000001]
        for byte in self.bytes.iter().rev() {
            let bits = byte.as_bitslice::<BigEndian>().as_slice();
            result.push(bits);
        }

        let bitvec: BitVec = conversion::concatenate(&result).into();

        let mut result = vec![];
        for bit in bitvec.iter() {
            result.push(bit);
        }
        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

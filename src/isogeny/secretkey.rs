//! Secret key
use bitvec::prelude::*;

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
    /// Get a random secret key of given `size` in bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rust_sike::pke::SecretKey;
    /// let key = SecretKey::get_random_secret_key(64);
    /// println!("{:?}", key);
    /// ```
    pub fn get_random_secret_key(size: usize) -> Result<Self, String> {
        let mut bytes = vec![0; size];
        if let Err(_e) = getrandom::getrandom(&mut bytes) {
            return Err(String::from("RNG Error"));
        };
        Ok(Self::from_bytes(&bytes))
    }

    /// Converts the secret key into a sequence of bits
    ///
    /// Note: The format is big endian
    pub fn to_bits(&self) -> BitVec<Msb0, u8> {
        // We reverse the order of the bytes
        // such that bits are properly ordered
        //      Ex : [1, 0] -> [00000000, 00000001]
        let bytes = self.bytes.iter().rev().copied().collect();
        BitVec::<Msb0, u8>::from_vec(bytes)
    }

    /// Converts the secret key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Build a secret key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

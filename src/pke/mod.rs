//! Public-key cryptosystem: a `Message` is encrypted using the public key, and decrypted using the corresponding private key.

use crate::{
    ff::FiniteField,
    isogeny::{CurveIsogenies, PublicKey, PublicParameters, SecretKey},
    utils::shake,
};

use std::fmt::Debug;

/// `Message`
#[derive(Clone)]
pub struct Message {
    /// Contents of the message
    pub bytes: Vec<u8>,
}

impl Message {
    /// Build a `Message` from a sequence of bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Obtain bytes from a `Message`
    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// `Ciphertext`
///
/// We decompose the ciphertext in subarrays for convenience
#[derive(Clone)]
pub struct Ciphertext {
    /// Ciphertext, part 0, subpart 0
    pub bytes00: Vec<u8>,

    /// Ciphertext, part 0, subpart 1
    pub bytes01: Vec<u8>,

    /// Ciphertext, part 0, subpart 2
    pub bytes02: Vec<u8>,

    /// Ciphertext, part 1
    pub bytes1: Vec<u8>,
}

/// Public-key cryptosystem (ref Algorithm 1, Section 1.3.9)
pub struct PKE<K> {
    /// Instance of the SIKE problem for this PKE
    pub isogenies: CurveIsogenies<K>,
    params: PublicParameters<K>,
}

impl<K: FiniteField + Clone + Debug> PKE<K> {
    /// Initialise cryptosystem with parameters `params`
    #[inline]
    pub fn setup(params: PublicParameters<K>) -> Self {
        Self {
            isogenies: CurveIsogenies::init(params.clone()),
            params,
        }
    }

    /// Generate a keypair
    #[inline]
    pub fn gen(&self) -> (SecretKey, PublicKey<K>) {
        // 1.
        let sk3 = SecretKey::get_random_secret_key(self.params.keyspace3 as usize);

        // 2.
        let pk3 = self.isogenies.isogen3(&sk3);

        // 3.
        (sk3, pk3)
    }

    /// Encrypt a message
    ///
    /// # Panics
    ///
    /// The function will panic if the message length is incorrect, of if the public key is incorrect
    #[inline]
    pub fn enc(&self, pk: &PublicKey<K>, m: Message) -> Ciphertext {
        // 4.
        let sk2 = SecretKey::get_random_secret_key(self.params.keyspace2 as usize);

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

    /// Decrypts a message
    ///
    /// # Panics
    ///
    /// The function will panic if the public key is incorrect
    #[inline]
    pub fn dec(&self, sk: &SecretKey, c: Ciphertext) -> Message {
        // 10.
        let c0 = &PublicKey::from_bytes(&c.bytes00, &c.bytes01, &c.bytes02);

        let j: K = self.isogenies.isoex3(sk, c0);

        // 11.
        let h = self.hash_function_f(j);

        // 12.
        assert_eq!(h.len(), c.bytes1.len());
        let m = Self::xor(&h, &c.bytes1);

        // 13.
        Message { bytes: m }
    }

    /// Computes the F function
    pub fn hash_function_f(&self, j: K) -> Vec<u8> {
        shake::shake256(&j.to_bytes(), self.params.secparam / 8)
    }

    /// Computes the bitwise XOR between two sequences
    pub fn xor(input1: &[u8], input2: &[u8]) -> Vec<u8> {
        let mut result = vec![0; input1.len()];
        let couples = input1.iter().zip(input2.iter());

        for (pos, (x, y)) in couples.enumerate() {
            result[pos] = x ^ y;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        isogeny::{sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params},
        utils::strategy::*,
    };

    #[test]
    fn test_pke_optim_p434() {
        let params = sike_p434_params(
            Some(P434_TWO_TORSION_STRATEGY.to_vec()),
            Some(P434_THREE_TORSION_STRATEGY.to_vec()),
        );

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_optim_p503() {
        let params = sike_p503_params(
            Some(P503_TWO_TORSION_STRATEGY.to_vec()),
            Some(P503_THREE_TORSION_STRATEGY.to_vec()),
        );

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_optim_p610() {
        let params = sike_p610_params(
            Some(P610_TWO_TORSION_STRATEGY.to_vec()),
            Some(P610_THREE_TORSION_STRATEGY.to_vec()),
        );

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_optim_p751() {
        let params = sike_p751_params(
            Some(P751_TWO_TORSION_STRATEGY.to_vec()),
            Some(P751_THREE_TORSION_STRATEGY.to_vec()),
        );

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_p434() {
        let params = sike_p434_params(None, None);

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_p503() {
        let params = sike_p503_params(None, None);

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_p610() {
        let params = sike_p610_params(None, None);

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }

    #[test]
    fn test_pke_p751() {
        let params = sike_p751_params(None, None);

        let pke = PKE::setup(params.clone());

        // Alice generates a keypair, she published her pk
        println!("[Debug] Key generation");
        let (sk, pk) = pke.gen();

        // Bob writes a message
        let msg = Message::from_bytes(vec![0; params.secparam / 8]);
        // Bob encrypts the message using Alice's pk
        println!("[Debug] Encryption");
        let ciphertext = pke.enc(&pk, msg.clone());

        // Bob sends the ciphertext to Alice
        // Alice decrypts the message using her sk
        println!("[Debug] Decryption");
        let msg_recovered = pke.dec(&sk, ciphertext);

        // Alice should correctly recover Bob's plaintext message
        assert_eq!(msg_recovered.to_bytes(), msg.to_bytes());
    }
}

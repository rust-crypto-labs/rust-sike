//! This is documentation for the `rust-sike` crate.
//!
//! # Introduction
//! `rust-sike` is an implementation of the supersingular isogeny primitives for SIKE, a post-quantum
//! candidate submitted to NIST for standardization.
//!
//! This crate provides public-key encryption (`PKE`) and key encapsulation (`KEM`).

#![warn(missing_docs)]

pub mod constants;
pub mod ff;
pub mod isogeny;
pub mod kem;
pub mod pke;
pub mod utils;

#[cfg(test)]
mod tests {

    use crate::{
        constants::cs_p434::*,
        ff::{ff_p434::PrimeFieldP434, FiniteField, QuadraticExtension},
        isogeny::{
            point::Point,
            publicparams::{
                sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params,
            },
            CurveIsogenies, PublicKey, SecretKey,
        },
        kem::KEM,
        pke::{Message, PKE},
        utils::{conversion, shake, strategy},
    };

    fn compare_arrays<T>(array1: &[T], array2: &[T]) -> bool
    where
        T: PartialEq + std::fmt::Debug,
    {
        let couples = array1.iter().zip(array2.iter());

        for (x, y) in couples {
            if x != y {
                println!("[!] Arrays differ");
                println!("{:?}", array1);
                println!("{:?}", array2);

                return false;
            }
        }

        true
    }

    #[test]
    fn test_strategy_2tor() {
        let n4 = 107;
        let p4 = 5633;
        let q4 = 5461;

        let p434strat = strategy::compute_strategy(n4, p4, q4);
        assert!(compare_arrays(
            &p434strat,
            &strategy::P434_TWO_TORSION_STRATEGY
        ));
    }

    #[test]
    fn test_strategy_3tor() {
        let n3 = 136;
        let p3 = 5322;
        let q3 = 5282;

        let p434strat = strategy::compute_strategy(n3, p3, q3);

        assert!(compare_arrays(
            &p434strat,
            &strategy::P434_THREE_TORSION_STRATEGY
        ));
    }

    #[test]
    fn test_shake256_0bit() {
        let msg = vec![];
        let output = shake::shake256(&msg, 512);

        // NIST test vector for SHAKE-256 on a zero-bit input
        let reference: [u8; 512] = [
            0x46, 0xB9, 0xDD, 0x2B, 0x0B, 0xA8, 0x8D, 0x13, 0x23, 0x3B, 0x3F, 0xEB, 0x74, 0x3E,
            0xEB, 0x24, 0x3F, 0xCD, 0x52, 0xEA, 0x62, 0xB8, 0x1B, 0x82, 0xB5, 0x0C, 0x27, 0x64,
            0x6E, 0xD5, 0x76, 0x2F, 0xD7, 0x5D, 0xC4, 0xDD, 0xD8, 0xC0, 0xF2, 0x00, 0xCB, 0x05,
            0x01, 0x9D, 0x67, 0xB5, 0x92, 0xF6, 0xFC, 0x82, 0x1C, 0x49, 0x47, 0x9A, 0xB4, 0x86,
            0x40, 0x29, 0x2E, 0xAC, 0xB3, 0xB7, 0xC4, 0xBE, 0x14, 0x1E, 0x96, 0x61, 0x6F, 0xB1,
            0x39, 0x57, 0x69, 0x2C, 0xC7, 0xED, 0xD0, 0xB4, 0x5A, 0xE3, 0xDC, 0x07, 0x22, 0x3C,
            0x8E, 0x92, 0x93, 0x7B, 0xEF, 0x84, 0xBC, 0x0E, 0xAB, 0x86, 0x28, 0x53, 0x34, 0x9E,
            0xC7, 0x55, 0x46, 0xF5, 0x8F, 0xB7, 0xC2, 0x77, 0x5C, 0x38, 0x46, 0x2C, 0x50, 0x10,
            0xD8, 0x46, 0xC1, 0x85, 0xC1, 0x51, 0x11, 0xE5, 0x95, 0x52, 0x2A, 0x6B, 0xCD, 0x16,
            0xCF, 0x86, 0xF3, 0xD1, 0x22, 0x10, 0x9E, 0x3B, 0x1F, 0xDD, 0x94, 0x3B, 0x6A, 0xEC,
            0x46, 0x8A, 0x2D, 0x62, 0x1A, 0x7C, 0x06, 0xC6, 0xA9, 0x57, 0xC6, 0x2B, 0x54, 0xDA,
            0xFC, 0x3B, 0xE8, 0x75, 0x67, 0xD6, 0x77, 0x23, 0x13, 0x95, 0xF6, 0x14, 0x72, 0x93,
            0xB6, 0x8C, 0xEA, 0xB7, 0xA9, 0xE0, 0xC5, 0x8D, 0x86, 0x4E, 0x8E, 0xFD, 0xE4, 0xE1,
            0xB9, 0xA4, 0x6C, 0xBE, 0x85, 0x47, 0x13, 0x67, 0x2F, 0x5C, 0xAA, 0xAE, 0x31, 0x4E,
            0xD9, 0x08, 0x3D, 0xAB, 0x4B, 0x09, 0x9F, 0x8E, 0x30, 0x0F, 0x01, 0xB8, 0x65, 0x0F,
            0x1F, 0x4B, 0x1D, 0x8F, 0xCF, 0x3F, 0x3C, 0xB5, 0x3F, 0xB8, 0xE9, 0xEB, 0x2E, 0xA2,
            0x03, 0xBD, 0xC9, 0x70, 0xF5, 0x0A, 0xE5, 0x54, 0x28, 0xA9, 0x1F, 0x7F, 0x53, 0xAC,
            0x26, 0x6B, 0x28, 0x41, 0x9C, 0x37, 0x78, 0xA1, 0x5F, 0xD2, 0x48, 0xD3, 0x39, 0xED,
            0xE7, 0x85, 0xFB, 0x7F, 0x5A, 0x1A, 0xAA, 0x96, 0xD3, 0x13, 0xEA, 0xCC, 0x89, 0x09,
            0x36, 0xC1, 0x73, 0xCD, 0xCD, 0x0F, 0xAB, 0x88, 0x2C, 0x45, 0x75, 0x5F, 0xEB, 0x3A,
            0xED, 0x96, 0xD4, 0x77, 0xFF, 0x96, 0x39, 0x0B, 0xF9, 0xA6, 0x6D, 0x13, 0x68, 0xB2,
            0x08, 0xE2, 0x1F, 0x7C, 0x10, 0xD0, 0x4A, 0x3D, 0xBD, 0x4E, 0x36, 0x06, 0x33, 0xE5,
            0xDB, 0x4B, 0x60, 0x26, 0x01, 0xC1, 0x4C, 0xEA, 0x73, 0x7D, 0xB3, 0xDC, 0xF7, 0x22,
            0x63, 0x2C, 0xC7, 0x78, 0x51, 0xCB, 0xDD, 0xE2, 0xAA, 0xF0, 0xA3, 0x3A, 0x07, 0xB3,
            0x73, 0x44, 0x5D, 0xF4, 0x90, 0xCC, 0x8F, 0xC1, 0xE4, 0x16, 0x0F, 0xF1, 0x18, 0x37,
            0x8F, 0x11, 0xF0, 0x47, 0x7D, 0xE0, 0x55, 0xA8, 0x1A, 0x9E, 0xDA, 0x57, 0xA4, 0xA2,
            0xCF, 0xB0, 0xC8, 0x39, 0x29, 0xD3, 0x10, 0x91, 0x2F, 0x72, 0x9E, 0xC6, 0xCF, 0xA3,
            0x6C, 0x6A, 0xC6, 0xA7, 0x58, 0x37, 0x14, 0x30, 0x45, 0xD7, 0x91, 0xCC, 0x85, 0xEF,
            0xF5, 0xB2, 0x19, 0x32, 0xF2, 0x38, 0x61, 0xBC, 0xF2, 0x3A, 0x52, 0xB5, 0xDA, 0x67,
            0xEA, 0xF7, 0xBA, 0xAE, 0x0F, 0x5F, 0xB1, 0x36, 0x9D, 0xB7, 0x8F, 0x3A, 0xC4, 0x5F,
            0x8C, 0x4A, 0xC5, 0x67, 0x1D, 0x85, 0x73, 0x5C, 0xDD, 0xDB, 0x09, 0xD2, 0xB1, 0xE3,
            0x4A, 0x1F, 0xC0, 0x66, 0xFF, 0x4A, 0x16, 0x2C, 0xB2, 0x63, 0xD6, 0x54, 0x12, 0x74,
            0xAE, 0x2F, 0xCC, 0x86, 0x5F, 0x61, 0x8A, 0xBE, 0x27, 0xC1, 0x24, 0xCD, 0x8B, 0x07,
            0x4C, 0xCD, 0x51, 0x63, 0x01, 0xB9, 0x18, 0x75, 0x82, 0x4D, 0x09, 0x95, 0x8F, 0x34,
            0x1E, 0xF2, 0x74, 0xBD, 0xAB, 0x0B, 0xAE, 0x31, 0x63, 0x39, 0x89, 0x43, 0x04, 0xE3,
            0x58, 0x77, 0xB0, 0xC2, 0x8A, 0x9B, 0x1F, 0xD1, 0x66, 0xC7, 0x96, 0xB9, 0xCC, 0x25,
            0x8A, 0x06, 0x4A, 0x8F, 0x57, 0xE2, 0x7F, 0x2A,
        ];

        assert!(compare_arrays(&reference, &output))
    }

    #[test]
    fn test_iso_eval() {
        let one: QuadraticExtension<PrimeFieldP434> = QuadraticExtension::one();
        let two = one.add(&one);
        let k1 = two.add(&one).mul(&two);
        let k2 = two.add(&two).mul(&two);
        let k3 = two.add(&two);

        let x = one.add(&one).add(&two).add(&two);

        let pt = Point::from_x(x);

        println!("Before {:?}", pt.x.div(&pt.z));

        let pt2 = CurveIsogenies::four_isogeny_eval(&k1, &k2, &k3, &pt);

        let pt3 = CurveIsogenies::three_isogeny_eval(&pt, &k1, &k2);

        println!("After 4isoeval {:?}", pt2.x.div(&pt2.z));
        println!("After 3isoeval {:?}", pt3.x.div(&pt3.z));

        assert_ne!(pt, pt3)
    }

    #[test]
    fn test_isoex_isogen() {
        let nks3 = conversion::str_to_u64(SIKE_P434_NKS3);
        let nks2 = conversion::str_to_u64(SIKE_P434_NKS2);

        let params = sike_p434_params(None, None);

        let iso = CurveIsogenies::init(params.clone());

        let sk3 = SecretKey::get_random_secret_key(nks3 as usize);
        let sk2 = SecretKey::get_random_secret_key(nks2 as usize);

        let pk3 = iso.isogen3(&sk3, &params.e3_strategy);
        let pk2 = iso.isogen2(&sk2, &params.e2_strategy);

        let j_a = iso.isoex2(&sk2, &pk3, &params.e2_strategy);
        let j_b = iso.isoex3(&sk3, &pk2, &params.e3_strategy);

        println!("j_A = {:?}", j_a);
        println!("j_B = {:?}", j_b);

        assert!(j_a.equals(&j_b));
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
        let params = sike_p503_params();

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
        let params = sike_p610_params();

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
        let params = sike_p751_params();

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
    fn test_kem_p434() {
        let params = sike_p434_params(None, None);

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3);

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c);

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p503() {
        let params = sike_p503_params();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3);

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c);

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p610() {
        let params = sike_p610_params();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3);

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c);

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_kem_p751() {
        let params = sike_p751_params();

        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3);

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c);

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_concatenate() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![6, 7, 8];
        let c = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let d = crate::utils::conversion::concatenate(&[&a, &b]);

        assert_eq!(c, d)
    }

    #[test]
    fn test_conversion_ff434_bytes() {
        let num = PrimeFieldP434::from_string(SIKE_P434_XP20);

        let b = num.clone().to_bytes();
        let num_recovered = PrimeFieldP434::from_bytes(&b);

        println!("{:?}", num);
        println!("{:?}", num_recovered);

        assert!(num.equals(&num_recovered));
    }

    #[test]
    fn test_conversion_quadratic_bytes() {
        let num1 = PrimeFieldP434::from_string(SIKE_P434_XP20);
        let num2 = PrimeFieldP434::from_string(SIKE_P434_XP21);

        let q = QuadraticExtension::from(num1, num2);
        let b = q.clone().to_bytes();
        let q_recovered = QuadraticExtension::from_bytes(&b);

        println!("{:?}", q);
        println!("{:?}", q_recovered);

        assert!(q.equals(&q_recovered));
    }

    #[test]
    fn test_conversion_secretkey_bytes() {
        let k = SecretKey::get_random_secret_key(256);
        let b = k.clone().to_bytes();
        let k_recovered = SecretKey::from_bytes(&b);

        assert_eq!(k, k_recovered);
    }

    #[test]
    fn test_j_invariant() {
        use crate::{
            ff::{ff_p434::PrimeFieldP434, QuadraticExtension},
            isogeny::Curve,
        };
        let curve = Curve::starting_curve();

        let j: QuadraticExtension<PrimeFieldP434> = curve.j_invariant();
        let j_ref: QuadraticExtension<PrimeFieldP434> = curve.j_invariant_ref();

        // 287496 + 0i
        assert_eq!(j, j_ref)
    }

    #[test]
    fn test_conversion_publickey_bytes() {
        let nks3 = conversion::str_to_u64(SIKE_P434_NKS3);
        let sk = SecretKey::get_random_secret_key(nks3 as usize);
        let strat = Some(strategy::P434_THREE_TORSION_STRATEGY);

        let params = sike_p434_params(None, strat.clone());
        let iso = CurveIsogenies::init(params);
        let pk = iso.isogen3(&sk, &strat);
        let (b0, b1, b2) = pk.clone().to_bytes();

        let pk_recovered = PublicKey::from_bytes(&b0, &b1, &b2);

        assert_eq!(pk, pk_recovered)
    }

    #[test]
    fn test_isogen2() {
        let nks2 = conversion::str_to_u64(SIKE_P434_NKS2);
        let sk = SecretKey::get_random_secret_key(nks2 as usize);
        let strat = Some(strategy::P434_TWO_TORSION_STRATEGY);

        let params = sike_p434_params(strat.clone(), None);

        let iso = CurveIsogenies::init(params);
        let pk = iso.isogen2(&sk, &strat);
        let pk_2 = iso.isogen2(&sk, &None);

        assert_eq!(pk, pk_2);
    }

    #[test]
    fn test_isogen3() {
        let nks3 = conversion::str_to_u64(SIKE_P434_NKS3);
        let sk = SecretKey::get_random_secret_key(nks3 as usize);
        let strat = Some(strategy::P434_THREE_TORSION_STRATEGY);

        let params = sike_p434_params(None, strat.clone());

        let iso = CurveIsogenies::init(params);
        let pk = iso.isogen3(&sk, &strat);
        let pk_2 = iso.isogen3(&sk, &None);

        assert_eq!(pk, pk_2);
    }

    #[test]
    fn test_ff() {
        let one = PrimeFieldP434::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four1 = two.add(&two);
        let four2 = two.mul(&two);
        let zero = one.sub(&one);

        println!("zero = {:?}", zero);
        println!("one = {:?}", one);
        println!("two = {:?}", two);
        println!("three = {:?}", three);
        println!("four1 = {:?}", four1);
        println!("four2 = {:?}", four2);
    }

    #[test]
    fn test_qff() {
        let one = PrimeFieldP434::one();
        let two = one.add(&one);
        let x = QuadraticExtension::from(two.clone(), two.clone());

        let eight_i = x.mul(&x);

        println!("eight_i = {:?}", eight_i);

        let two_plus_two_i = eight_i.div(&x);

        println!("two_plus_two_i = {:?}", two_plus_two_i);

        assert_eq!(two_plus_two_i, x)
    }
}

use criterion::{criterion_group, criterion_main, Criterion};

use rust_sike::{
    kem::KEM,
    pke::{Message, PKE},
    sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params,
    strategy::*,
};

pub fn bench_p434_pke_std(c: &mut Criterion) {
    let params = sike_p434_params(None, None).unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp434 PKE (no opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone());

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p434_pke_optim(c: &mut Criterion) {
    let params = sike_p434_params(
        Some(P434_TWO_TORSION_STRATEGY.to_vec()),
        Some(P434_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp434 PKE (opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone());

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p434_kem_std(c: &mut Criterion) {
    let params = sike_p434_params(None, None).unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp434 KEM (no opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p434_kem_optim(c: &mut Criterion) {
    let params = sike_p434_params(
        Some(P434_TWO_TORSION_STRATEGY.to_vec()),
        Some(P434_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp434 KEM (opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p503_pke_std(c: &mut Criterion) {
    let params = sike_p503_params(None, None).unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp503 PKE (no opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p503_pke_optim(c: &mut Criterion) {
    let params = sike_p503_params(
        Some(P503_TWO_TORSION_STRATEGY.to_vec()),
        Some(P503_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp503 PKE (opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p503_kem_std(c: &mut Criterion) {
    let params = sike_p503_params(None, None).unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp503 KEM (no opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p503_kem_optim(c: &mut Criterion) {
    let params = sike_p503_params(
        Some(P503_TWO_TORSION_STRATEGY.to_vec()),
        Some(P503_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp503 KEM (opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p610_pke_std(c: &mut Criterion) {
    let params = sike_p610_params(None, None).unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp610 PKE (no opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p610_pke_optim(c: &mut Criterion) {
    let params = sike_p610_params(
        Some(P610_TWO_TORSION_STRATEGY.to_vec()),
        Some(P610_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp610 PKE (opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p610_kem_std(c: &mut Criterion) {
    let params = sike_p610_params(None, None).unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp610 KEM (no opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p610_kem_optim(c: &mut Criterion) {
    let params = sike_p610_params(
        Some(P610_TWO_TORSION_STRATEGY.to_vec()),
        Some(P610_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp610 KEM (opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone());

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p751_pke_std(c: &mut Criterion) {
    let params = sike_p751_params(None, None).unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp751 PKE (no opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p751_pke_optim(c: &mut Criterion) {
    let params = sike_p751_params(
        Some(P751_TWO_TORSION_STRATEGY.to_vec()),
        Some(P751_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let mut group = c.benchmark_group("SIKEp751 PKE (opti)");
    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let _msg_recovered = pke.dec(&sk, ciphertext.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| pke.gen()));
    group.bench_function("Encryption", |b| b.iter(|| pke.enc(&pk, msg.clone())));
    group.bench_function("Decryption", |b| {
        b.iter(|| pke.dec(&sk, ciphertext.clone()))
    });

    group.finish();
}

pub fn bench_p751_kem_std(c: &mut Criterion) {
    let params = sike_p751_params(None, None).unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp751 KEM (no opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn bench_p751_kem_optim(c: &mut Criterion) {
    let params = sike_p751_params(
        Some(P751_TWO_TORSION_STRATEGY.to_vec()),
        Some(P751_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let kem = KEM::setup(params);

    let mut group = c.benchmark_group("SIKEp751 KEM (opti)");
    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let _k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    group.bench_function("Keygen", |b| b.iter(|| kem.keygen()));
    group.bench_function("Encapsulation", |b| b.iter(|| kem.encaps(&pk3)));
    group.bench_function("Decapsulation", |b| {
        b.iter(|| kem.decaps(&s, &sk3, &pk3, c.clone()))
    });

    group.finish();
}

pub fn config() -> Criterion {
    Criterion::default().sample_size(10)
}

criterion_group! {
    name = p434;
    config = config();
    targets = bench_p434_pke_std, bench_p434_pke_optim, bench_p434_kem_std, bench_p434_kem_optim
}

criterion_group! {
    name = p503;
    config = config();
    targets = bench_p503_pke_std, bench_p503_pke_optim, bench_p503_kem_std, bench_p503_kem_optim
}
criterion_group! {
    name = p610;
    config = config();
    targets = bench_p610_pke_std, bench_p610_pke_optim, bench_p610_kem_std, bench_p610_kem_optim
}
criterion_group! {
    name = p751;
    config = config();
    targets = bench_p751_pke_std, bench_p751_pke_optim, bench_p751_kem_std, bench_p751_kem_optim
}

criterion_group! {
    name = pke;
    config = config();
    targets = bench_p434_pke_optim, bench_p503_pke_optim, bench_p610_pke_optim, bench_p751_pke_optim
}

criterion_group! {
    name = kem;
    config = config();
    targets = bench_p434_kem_optim, bench_p503_kem_optim, bench_p610_kem_optim, bench_p751_kem_optim
}

criterion_main!(kem);

use rust_sike::{
    kem::KEM,
    sike_p751_params,
    strategy::{P751_THREE_TORSION_STRATEGY, P751_TWO_TORSION_STRATEGY},
};

fn main() {
    let params = sike_p751_params(
        Some(P751_TWO_TORSION_STRATEGY.to_vec()),
        Some(P751_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let kem = KEM::setup(params);

    let (s, sk3, pk3) = kem.keygen().unwrap();
    let (c, _k) = kem.encaps(&pk3).unwrap();
    let k_recovered = kem.decaps(&s, &sk3, &pk3, c.clone()).unwrap();

    println!("{:?}", k_recovered)
}

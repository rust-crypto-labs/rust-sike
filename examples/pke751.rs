use rust_sike::{
    pke::{Message, PKE},
    sike_p751_params,
    strategy::{P751_THREE_TORSION_STRATEGY, P751_TWO_TORSION_STRATEGY},
};

fn main() {
    let params = sike_p751_params(
        Some(P751_TWO_TORSION_STRATEGY.to_vec()),
        Some(P751_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let msg_recovered = pke.dec(&sk, ciphertext.clone());

    msg_recovered.unwrap();
}

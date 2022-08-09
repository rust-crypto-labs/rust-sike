use rust_sike::{
    pke::{Message, PKE},
    sike_p503_params,
    strategy::{P503_THREE_TORSION_STRATEGY, P503_TWO_TORSION_STRATEGY},
};

fn main() {
    let params = sike_p503_params(
        Some(P503_TWO_TORSION_STRATEGY.to_vec()),
        Some(P503_THREE_TORSION_STRATEGY.to_vec()),
    )
    .unwrap();
    let msg = Message::from_bytes(vec![0; params.clone().secparam / 8]);
    let pke = PKE::setup(params);

    let (sk, pk) = pke.gen().unwrap();
    let ciphertext = pke.enc(&pk, msg.clone()).unwrap();
    let msg_recovered = pke.dec(&sk, ciphertext.clone());

    msg_recovered.unwrap();
}

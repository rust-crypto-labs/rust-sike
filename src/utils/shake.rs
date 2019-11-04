use tiny_keccak::Keccak;

pub fn shake256(input: &[u8], len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    Keccak::shake256(input, &mut buffer);
    buffer.to_vec()
}

pub fn concatenate(arrays: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![];
    for &array in arrays {
        result.extend(array);
    }
    result
}

extern crate num_bigint;

mod ff;
mod kem;
mod pke;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

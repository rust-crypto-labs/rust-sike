//! This is documentation for the `rust-sike` crate.
//!
//! # Introduction
//! `rust-sike` is an implementation of the supersingular isogeny primitives for SIKE, a post-quantum
//! candidate submitted to NIST for standardization.
//!
//! This crate provides public-key encryption (`PKE`) and key encapsulation (`KEM`).

#![warn(missing_docs)]

mod constants;
mod ff;
mod isogeny;
mod utils;

pub mod kem;
pub mod pke;
pub use {kem::KEM, pke::PKE};

pub use utils::strategy::{
    compute_strategy, P434_THREE_TORSION_STRATEGY, P434_TWO_TORSION_STRATEGY,
    P503_THREE_TORSION_STRATEGY, P503_TWO_TORSION_STRATEGY, P610_THREE_TORSION_STRATEGY,
    P610_TWO_TORSION_STRATEGY, P751_THREE_TORSION_STRATEGY, P751_TWO_TORSION_STRATEGY,
};

pub use crate::{
    isogeny::{sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params},
    utils::strategy,
};

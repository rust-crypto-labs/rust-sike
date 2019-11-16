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
pub mod kem;
pub mod pke;
mod utils;

pub use crate::{
    isogeny::{sike_p434_params, sike_p503_params, sike_p610_params, sike_p751_params},
    utils::strategy,
};

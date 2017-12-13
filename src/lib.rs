//! Type-safe, verified cryptography for Rust.

#![warn(missing_docs)]

#[macro_use]
extern crate failure;
extern crate hacl_sys;
extern crate rand;

pub mod error;
pub mod nacl;

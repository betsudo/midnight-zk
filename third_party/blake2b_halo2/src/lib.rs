//! Halo2 Blake2b implementation.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(rust_2018_idioms)]

use midnight_proofs::{circuit::Layouter, plonk::ConstraintSystem};

use ff::PrimeField;
use midnight_proofs::circuit::{Region, Value};
use midnight_proofs::plonk::{Advice, Column, Error, Expression, Selector, TableColumn};
use midnight_proofs::poly::Rotation;

pub(crate) mod base_operations;

#[cfg(test)]
mod tests;
pub mod blake2b;
pub mod types;
pub mod usage_utils;

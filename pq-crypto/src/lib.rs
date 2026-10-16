//! Post-quantum primitives used by the Agave validator, runtime and native QUIC.
//! Consensus and proof profiles remain experimental and require independent review.

// AIR constraints and WOTS arithmetic deliberately operate in finite fields.
#![allow(clippy::arithmetic_side_effects)]

pub type Address = [u8; 32];
pub type Commitment = [u8; 48];
pub mod auth;
pub mod ax;
pub mod ax_state;
pub mod checkpoint;
pub mod consensus;
pub mod crypto;
pub mod migration;
pub mod network;
pub mod quantumglow;
pub mod seed_proof;
mod transaction;

#[cfg(test)]
mod quantumglow_tests;

#![allow(unexpected_cfgs)]

pub mod auth;
pub mod compact;
pub mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod utils;

/// Base fee in lamports (0.000005 SOL).
pub const BASE_FEE_LAMPORTS: u64 = 5_000;

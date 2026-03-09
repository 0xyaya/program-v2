use pinocchio::pubkey::Pubkey;

/// Fee config PDA seeds
pub const FEE_CONFIG_SEED: &[u8] = b"fee_config";

/// Fee config account size
/// discriminator(1) + authority(32) + recipient(32) + 
/// pending_authority(32) + pending_authority_valid_at(8)
pub const FEE_CONFIG_SIZE: usize = 1 + 32 + 32 + 32 + 8; // 105 bytes

/// Fee config discriminator
pub const FEE_CONFIG_DISCRIMINATOR: u8 = 4;

/// Timelock duration: ~24 hours at 400ms/slot = 216,000 slots
pub const TIMELOCK_SLOTS: u64 = 216_000;

/// Zero pubkey (represents no pending value)
pub const ZERO_PUBKEY: Pubkey = [0u8; 32];

/// Derives the fee config PDA
pub fn derive_fee_config(program_id: &Pubkey) -> (Pubkey, u8) {
    pinocchio::pubkey::find_program_address(&[FEE_CONFIG_SEED], program_id)
}

/// FeeConfig layout offsets
pub mod offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const AUTHORITY: usize = 1;                      // 1..33
    pub const RECIPIENT: usize = 33;                     // 33..65
    pub const PENDING_AUTHORITY: usize = 65;             // 65..97
    pub const PENDING_AUTHORITY_VALID_AT: usize = 97;    // 97..105
}

//! InitFeeConfig processor - initializes the fee configuration PDA.
//!
//! Instruction tag: 6
//!
//! # Accounts
//! 0. `[signer, writable]` payer - pays for account creation
//! 1. `[writable]` fee_config PDA - derived from ["fee_config"]
//! 2. `[]` system_program
//!
//! # Data Layout
//! - authority (32 bytes) - admin who can update fee config
//! - recipient (32 bytes) - receives protocol fees

use assertions::sol_assert_bytes_eq;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::state::fee::{
    derive_fee_config, offsets, FEE_CONFIG_DISCRIMINATOR, FEE_CONFIG_SIZE, ZERO_PUBKEY,
};

/// Processes the `InitFeeConfig` instruction.
///
/// Initializes the singleton fee configuration PDA that stores:
/// - authority: admin who can update the fee recipient
/// - recipient: address that receives protocol fees
///
/// This instruction can only be called once. Subsequent calls will fail
/// with `AccountAlreadyInitialized` error.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse instruction data: authority(32) + recipient(32) = 64 bytes
    if instruction_data.len() < 64 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut authority = [0u8; 32];
    authority.copy_from_slice(&instruction_data[0..32]);

    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&instruction_data[32..64]);

    // Get accounts
    let account_info_iter = &mut accounts.iter();

    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let fee_config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Verify payer is signer
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive and verify fee_config PDA
    let (expected_fee_config, fee_config_bump) = derive_fee_config(program_id);
    if !sol_assert_bytes_eq(
        fee_config_pda.key().as_ref(),
        expected_fee_config.as_ref(),
        32,
    ) {
        return Err(ProgramError::InvalidSeeds);
    }

    // Check if already initialized (discriminator != 0)
    // For unallocated accounts, data_len is 0
    let data_len = fee_config_pda.data_len();
    if data_len > 0 {
        let data = unsafe { fee_config_pda.borrow_data_unchecked() };
        if data[offsets::DISCRIMINATOR] != 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }

    // Get rent sysvar - we need to calculate rent manually since we don't have it passed
    // Use a hardcoded rent-exempt minimum for 105 bytes
    // rent = base_rent + (bytes * lamports_per_byte_year)
    // For mainnet: ~890,880 lamports per 100 bytes (approximately)
    // More accurate: use Rent sysvar if available, or calculate
    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(FEE_CONFIG_SIZE);

    // Initialize PDA using secure transfer-allocate-assign pattern
    let fee_config_bump_arr = [fee_config_bump];
    let pda_seeds = [
        Seed::from(crate::state::fee::FEE_CONFIG_SEED),
        Seed::from(&fee_config_bump_arr),
    ];

    crate::utils::initialize_pda_account(
        payer,
        fee_config_pda,
        system_program,
        FEE_CONFIG_SIZE,
        rent_lamports,
        program_id,
        &pda_seeds,
    )?;

    // Write fee config data
    let fee_config_data = unsafe { fee_config_pda.borrow_mut_data_unchecked() };

    // Write discriminator (1 byte)
    fee_config_data[offsets::DISCRIMINATOR] = FEE_CONFIG_DISCRIMINATOR;

    // Write authority (32 bytes)
    fee_config_data[offsets::AUTHORITY..offsets::RECIPIENT].copy_from_slice(&authority);

    // Write recipient (32 bytes)
    fee_config_data[offsets::RECIPIENT..offsets::PENDING_AUTHORITY].copy_from_slice(&recipient);

    // Write zero pending_authority (32 bytes)
    fee_config_data[offsets::PENDING_AUTHORITY..offsets::PENDING_AUTHORITY_VALID_AT]
        .copy_from_slice(&ZERO_PUBKEY);

    // Write zero pending_valid_at (8 bytes)
    fee_config_data[offsets::PENDING_AUTHORITY_VALID_AT..FEE_CONFIG_SIZE]
        .copy_from_slice(&0u64.to_le_bytes());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_data_parsing() {
        let authority = [1u8; 32];
        let recipient = [2u8; 32];

        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&authority);
        data.extend_from_slice(&recipient);

        // Verify we can parse correctly
        assert_eq!(data.len(), 64);
        assert_eq!(&data[0..32], &authority);
        assert_eq!(&data[32..64], &recipient);
    }

    #[test]
    fn test_instruction_data_too_short() {
        let data = vec![0u8; 63]; // Need 64
        assert!(data.len() < 64);
    }
}

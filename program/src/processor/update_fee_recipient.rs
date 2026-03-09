//! Processor for UpdateFeeRecipient instruction.
//!
//! Updates the fee recipient with a 24-hour timelock for security.
//! First call stages the change, second call (after timelock) applies it.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::state::fee::{
    offsets, derive_fee_config, FEE_CONFIG_DISCRIMINATOR, FEE_CONFIG_SIZE, 
    TIMELOCK_SLOTS, ZERO_PUBKEY,
};

/// Processes the UpdateFeeRecipient instruction.
///
/// # Flow:
/// 1. If no pending change (pending_valid_at == 0):
///    - Stage new_recipient and set pending_valid_at = current_slot + TIMELOCK_SLOTS
/// 2. If timelock elapsed (current_slot >= pending_valid_at && pending_valid_at > 0):
///    - Apply pending_recipient → recipient
///    - Clear pending fields
///
/// # Accounts:
/// 0. `[signer]` authority - Must match stored authority
/// 1. `[writable]` fee_config PDA
///
/// # Data:
/// `[7, new_recipient(32)]`
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse instruction data: [new_recipient(32)]
    if instruction_data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_recipient: &[u8; 32] = instruction_data[..32]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Parse accounts
    let account_iter = &mut accounts.iter();
    
    let authority = account_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let fee_config = account_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Validate authority is signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate fee_config is writable
    if !fee_config.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate fee_config is owned by this program
    if fee_config.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Validate fee_config PDA derivation
    let (expected_pda, _bump) = derive_fee_config(program_id);
    if fee_config.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Get mutable data
    let data = unsafe { fee_config.borrow_mut_data_unchecked() };

    // Validate account size
    if data.len() < FEE_CONFIG_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }

    // Validate discriminator
    if data[offsets::DISCRIMINATOR] != FEE_CONFIG_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify signer matches stored authority
    let stored_authority = &data[offsets::AUTHORITY..offsets::AUTHORITY + 32];
    if stored_authority != authority.key().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Get current slot
    let clock = Clock::get()?;
    let current_slot = clock.slot;

    // Read pending_valid_at (little-endian u64 at offset 97)
    let pending_valid_at = u64::from_le_bytes(
        data[offsets::PENDING_AUTHORITY_VALID_AT..offsets::PENDING_AUTHORITY_VALID_AT + 8]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?
    );

    if pending_valid_at == 0 {
        // No pending change - stage the new recipient
        // Set pending_recipient
        data[offsets::PENDING_AUTHORITY..offsets::PENDING_AUTHORITY + 32]
            .copy_from_slice(new_recipient);
        
        // Set pending_valid_at = current_slot + TIMELOCK_SLOTS
        let valid_at = current_slot
            .checked_add(TIMELOCK_SLOTS)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        data[offsets::PENDING_AUTHORITY_VALID_AT..offsets::PENDING_AUTHORITY_VALID_AT + 8]
            .copy_from_slice(&valid_at.to_le_bytes());
    } else if current_slot >= pending_valid_at {
        // Timelock has elapsed - apply the pending change
        // Copy pending_recipient → recipient
        let pending_recipient: [u8; 32] = data[offsets::PENDING_AUTHORITY..offsets::PENDING_AUTHORITY + 32]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        data[offsets::RECIPIENT..offsets::RECIPIENT + 32]
            .copy_from_slice(&pending_recipient);

        // Clear pending fields
        data[offsets::PENDING_AUTHORITY..offsets::PENDING_AUTHORITY + 32]
            .copy_from_slice(&ZERO_PUBKEY);
        data[offsets::PENDING_AUTHORITY_VALID_AT..offsets::PENDING_AUTHORITY_VALID_AT + 8]
            .copy_from_slice(&0u64.to_le_bytes());
    } else {
        // Timelock not yet elapsed - reject
        return Err(ProgramError::Custom(1)); // TimelockNotElapsed
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_slots_is_24h() {
        // 400ms per slot, 216_000 slots = 86_400 seconds = 24 hours
        let seconds = TIMELOCK_SLOTS * 400 / 1000;
        assert_eq!(seconds, 86_400);
    }
}

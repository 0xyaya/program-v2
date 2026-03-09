use assertions::{check_zero_data, sol_assert_bytes_eq};
use no_padding::NoPadding;
use pinocchio::{
    account_info::AccountInfo,
    instruction::Seed,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{
    auth::{
        ed25519::Ed25519Authenticator, secp256r1::Secp256r1Authenticator, traits::Authenticator,
    },
    error::AuthError,
    state::{authority::AuthorityAccountHeader, session::SessionAccount, AccountDiscriminator},
};

/// Arguments for the `CreateSession` instruction (V3).
///
/// Layout (80 bytes):
/// - `session_key`: The public key of the ephemeral session signer (32).
/// - `expires_at`: The absolute slot height when this session expires (8).
/// - `mint`: Allowed token mint (all zeros = native SOL) (32).
/// - `max_amount`: Maximum spendable amount (8).
#[repr(C, align(8))]
#[derive(NoPadding)]
pub struct CreateSessionArgs {
    pub session_key: [u8; 32],
    pub expires_at: u64,
    pub mint: [u8; 32],
    pub max_amount: u64,
}

impl CreateSessionArgs {
    /// Size of V3 CreateSessionArgs in bytes.
    pub const SIZE: usize = 80;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        // args are: [session_key(32)][expires_at(8)][mint(32)][max_amount(8)]
        let mut offset = 0;

        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let expires_at = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let max_amount = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());

        Ok(Self {
            session_key,
            expires_at,
            mint,
            max_amount,
        })
    }
}

/// Processes the `CreateSession` instruction.
///
/// Creates a temporary `Session` account that facilitates limited-scope execution (Spender role).
///
/// # Logic:
/// 1. Verifies the authorizing authority (must be Owner or Admin).
/// 2. Derives a fresh Session PDA from `["session", wallet, session_key]`.
/// 3. Allocates and initializes the Session account with expiry.
///
/// # Accounts:
/// 1. `[signer, writable]` Payer: Pays for rent.
/// 2. `[]` Wallet PDA.
/// 3. `[signer, writable]` Authorizer: Authority approving this session creation.
/// 4. `[writable]` Session PDA: The new session account.
/// 5. `[]` System Program.
/// 6. `[]` Rent Sysvar.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let args = CreateSessionArgs::from_bytes(instruction_data)?;

    let account_info_iter = &mut accounts.iter();
    let payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let wallet_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let authorizer_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let session_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let rent_sysvar = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Get rent from sysvar (fixes audit issue #5 - hardcoded rent calculations)
    let rent = Rent::from_account_info(rent_sysvar)?;

    // Validate system_program is the correct System Program (audit N2)
    if !assertions::sol_assert_bytes_eq(
        system_program.key().as_ref(),
        &crate::utils::SYSTEM_PROGRAM_ID,
        32,
    ) {
        return Err(ProgramError::IncorrectProgramId);
    }

    if wallet_pda.owner() != program_id || authorizer_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Validate Wallet Discriminator (Issue #7)
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    if wallet_data.is_empty() || wallet_data[0] != AccountDiscriminator::Wallet as u8 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify Authorizer
    // Check removed: conditional writable check inside match

    let auth_data = unsafe { authorizer_pda.borrow_mut_data_unchecked() };

    // Safe Copy of Header using read_unaligned
    if auth_data.len() < std::mem::size_of::<AuthorityAccountHeader>() {
        return Err(ProgramError::InvalidAccountData);
    }
    let auth_header =
        unsafe { std::ptr::read_unaligned(auth_data.as_ptr() as *const AuthorityAccountHeader) };

    if auth_header.discriminator != AccountDiscriminator::Authority as u8 {
        return Err(ProgramError::InvalidAccountData);
    }
    if auth_header.wallet != *wallet_pda.key() {
        return Err(ProgramError::InvalidAccountData);
    }
    // Only Admin (1) or Owner (0) can create sessions.
    // Spender (2) cannot create sessions.
    if auth_header.role != 0 && auth_header.role != 1 {
        return Err(AuthError::PermissionDenied.into());
    }

    // Authenticate Authorizer

    // We assume CreateSession instruction data AFTER the args is payload for Secp256r1 if any
    let payload_offset = std::mem::size_of::<CreateSessionArgs>();
    let authority_payload = if instruction_data.len() > payload_offset {
        &instruction_data[payload_offset..]
    } else {
        &[]
    };

    // But wait, `CreateSessionArgs` consumes 40 bytes.
    // `instruction_data` passed here is whatever follows the discriminator.
    // `Execute` passes compact instructions.
    // Here we pass args.

    // For Secp256r1, we need to distinguish args from auth payload.
    // The instruction format is [discriminator][args][payload].
    // `instruction_data` here is [args][payload].
    let data_payload = &instruction_data[..payload_offset];

    // Include payer in signed payload to prevent payer swap
    // V3: Challenge includes session_key || expires_at || mint || max_amount
    let mut ed25519_payload = Vec::with_capacity(112);
    ed25519_payload.extend_from_slice(payer.key().as_ref());
    ed25519_payload.extend_from_slice(&args.session_key);
    ed25519_payload.extend_from_slice(&args.expires_at.to_le_bytes());
    ed25519_payload.extend_from_slice(&args.mint);
    ed25519_payload.extend_from_slice(&args.max_amount.to_le_bytes());

    match auth_header.authority_type {
        0 => {
            // Ed25519: Include payer + session_key in signed payload
            Ed25519Authenticator.authenticate(accounts, auth_data, &[], &ed25519_payload, &[5])?;
        },
        1 => {
            // Secp256r1: Include payer in data_payload
            let mut extended_data_payload = Vec::with_capacity(data_payload.len() + 32);
            extended_data_payload.extend_from_slice(data_payload);
            extended_data_payload.extend_from_slice(payer.key().as_ref());

            Secp256r1Authenticator.authenticate(
                accounts,
                auth_data,
                authority_payload,
                &extended_data_payload,
                &[5],
            )?;
        },
        _ => return Err(AuthError::InvalidAuthenticationKind.into()),
    }

    // Derive Session PDA
    let (session_key, bump) = find_program_address(
        &[b"session", wallet_pda.key().as_ref(), &args.session_key],
        program_id,
    );
    if !sol_assert_bytes_eq(session_pda.key().as_ref(), session_key.as_ref(), 32) {
        return Err(ProgramError::InvalidSeeds);
    }
    check_zero_data(session_pda, ProgramError::AccountAlreadyInitialized)?;

    // Create Session Account
    let space = std::mem::size_of::<SessionAccount>();
    let session_rent = rent.minimum_balance(space);

    let bump_arr = [bump];
    let seeds = [
        Seed::from(b"session"),
        Seed::from(wallet_pda.key().as_ref()),
        Seed::from(&args.session_key),
        Seed::from(&bump_arr),
    ];

    crate::utils::initialize_pda_account(
        payer,
        session_pda,
        system_program,
        space,
        session_rent,
        program_id,
        &seeds,
    )?;

    // Initialize Session State (V3 with spending limits)
    let data = unsafe { session_pda.borrow_mut_data_unchecked() };
    let session = SessionAccount {
        discriminator: AccountDiscriminator::Session as u8,
        bump,
        version: crate::state::session::CURRENT_SESSION_VERSION,
        flags: 0,
        _reserved: [0; 4],
        wallet: *wallet_pda.key(),
        session_key: Pubkey::from(args.session_key),
        expires_at: args.expires_at,
        mint: Pubkey::from(args.mint),
        max_amount: args.max_amount,
        spent_amount: 0,
    };

    // Safe write
    let session_bytes = unsafe {
        std::slice::from_raw_parts(
            &session as *const SessionAccount as *const u8,
            std::mem::size_of::<SessionAccount>(),
        )
    };
    data[0..std::mem::size_of::<SessionAccount>()].copy_from_slice(session_bytes);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_args_from_bytes() {
        let mut data = Vec::new();
        // V3: session_key(32) + expires_at(8) + mint(32) + max_amount(8)
        let session_key = [7u8; 32];
        let expires_at = 12345678u64;
        let mint = [0u8; 32]; // Native SOL
        let max_amount = 1_000_000_000u64; // 1 SOL

        data.extend_from_slice(&session_key);
        data.extend_from_slice(&expires_at.to_le_bytes());
        data.extend_from_slice(&mint);
        data.extend_from_slice(&max_amount.to_le_bytes());

        let args = CreateSessionArgs::from_bytes(&data).unwrap();
        assert_eq!(args.session_key, session_key);
        assert_eq!(args.expires_at, expires_at);
        assert_eq!(args.mint, mint);
        assert_eq!(args.max_amount, max_amount);
    }

    #[test]
    fn test_create_session_args_size() {
        assert_eq!(CreateSessionArgs::SIZE, 80);
    }

    #[test]
    fn test_create_session_args_too_short() {
        let data = vec![0u8; 79]; // Need 80
        assert!(CreateSessionArgs::from_bytes(&data).is_err());
    }
}

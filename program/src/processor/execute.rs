use crate::{
    auth::{
        ed25519::Ed25519Authenticator, secp256r1::Secp256r1Authenticator, traits::Authenticator,
    },
    compact::parse_compact_instructions,
    error::AuthError,
    state::{
        authority::AuthorityAccountHeader,
        fee::{FEE_CONFIG_DISCRIMINATOR, offsets},
        session::SessionAccount,
        AccountDiscriminator,
    },
    BASE_FEE_LAMPORTS,
};
use pinocchio::{
    account_info::AccountInfo,
    instruction::{Account, AccountMeta, Instruction, Seed, Signer},
    program::invoke_signed_unchecked,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

/// Process the Execute instruction  
/// Processes the `Execute` instruction.
///
/// Executes a batch of condensed "Compact Instructions" on behalf of the wallet.
///
/// # Logic:
/// 1. **Authentication**: Verifies that the signer is a valid `Authority` or `Session` for this wallet.
/// 2. **Session Checks**: If authenticated via Session, enforces slot expiry.
/// 3. **Decompression**: Expands `CompactInstructions` (index-based references) into full Solana instructions.
/// 4. **Execution**: Invokes the Instructions via CPI, signing with the Vault PDA.
///
/// # Accounts:
/// 0. `[signer]` Payer.
/// 1. `[]` Wallet PDA.
/// 2. `[signer, writable]` Authority or Session PDA.
/// 3. `[writable]` Vault PDA (Signer for CPI).
/// 4. `[]` FeeConfig PDA (read fee recipient from on-chain state).
/// 5. `[writable]` Fee recipient (must match recipient stored in FeeConfig).
/// 6. `[]` System Program (for fee transfer CPI).
/// 7. `...` Inner accounts referenced by instructions.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse accounts
    let account_info_iter = &mut accounts.iter();
    let _payer = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let wallet_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let authority_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let vault_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let fee_config_pda = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let fee_recipient = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let system_program = account_info_iter
        .next()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    // Remaining accounts are for inner instructions (after system_program)
    let inner_accounts_start = 7;
    let _inner_accounts = &accounts[inner_accounts_start..];

    // Verify FeeConfig PDA ownership and read recipient
    if fee_config_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    let fee_config_data = unsafe { fee_config_pda.borrow_data_unchecked() };
    if fee_config_data.len() < offsets::RECIPIENT + 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    if fee_config_data[offsets::DISCRIMINATOR] != FEE_CONFIG_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    // Read the fee recipient pubkey from FeeConfig (offset 33, 32 bytes)
    let stored_recipient: Pubkey = fee_config_data[offsets::RECIPIENT..offsets::RECIPIENT + 32]
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    
    // Verify the provided fee_recipient account matches the stored recipient
    if fee_recipient.key() != &stored_recipient {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify System Program
    if system_program.key() != &Pubkey::from(crate::utils::SYSTEM_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Verify ownership
    if wallet_pda.owner() != program_id || authority_pda.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    // Validate Wallet Discriminator (Issue #7)
    let wallet_data = unsafe { wallet_pda.borrow_data_unchecked() };
    if wallet_data.is_empty() || wallet_data[0] != AccountDiscriminator::Wallet as u8 {
        return Err(ProgramError::InvalidAccountData);
    }

    if !authority_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read authority header
    // Safe copy header
    // Read authority data
    let authority_data = unsafe { authority_pda.borrow_mut_data_unchecked() };

    // Authenticate based on discriminator
    let discriminator = if !authority_data.is_empty() {
        authority_data[0]
    } else {
        return Err(ProgramError::InvalidAccountData);
    };

    // Track if this is session authentication for spending limit enforcement
    let mut is_session_auth = false;
    let mut session_mint: Option<Pubkey> = None;

    // Parse compact instructions
    let compact_instructions = parse_compact_instructions(instruction_data)?;

    // Serialize compact instructions to get their byte length
    let compact_bytes = crate::compact::serialize_compact_instructions(&compact_instructions);
    let compact_len = compact_bytes.len();

    match discriminator {
        2 => {
            // Authority
            if authority_data.len() < std::mem::size_of::<AuthorityAccountHeader>() {
                return Err(ProgramError::InvalidAccountData);
            }
            // Use read_unaligned to safely copy potentially unaligned data into a local struct
            let authority_header = unsafe {
                std::ptr::read_unaligned(authority_data.as_ptr() as *const AuthorityAccountHeader)
            };

            if authority_header.discriminator != AccountDiscriminator::Authority as u8 {
                return Err(ProgramError::InvalidAccountData);
            }

            if authority_header.wallet != *wallet_pda.key() {
                return Err(ProgramError::InvalidAccountData);
            }
            match authority_header.authority_type {
                0 => {
                    // Ed25519: Verify signer (authority_payload ignored)
                    Ed25519Authenticator.authenticate(accounts, authority_data, &[], &[], &[4])?;
                },
                1 => {
                    // Secp256r1 (WebAuthn)
                    // Issue #11: Include accounts hash to prevent account reordering attacks
                    // signed_payload is compact_instructions bytes + accounts hash for Execute
                    let data_payload = &instruction_data[..compact_len];
                    let authority_payload = &instruction_data[compact_len..];

                    // Compute hash of all account pubkeys referenced by compact instructions
                    // This binds the signature to the exact accounts, preventing reordering
                    let accounts_hash = compute_accounts_hash(accounts, &compact_instructions)?;

                    // Extended payload: compact_instructions + accounts_hash
                    let mut extended_payload = Vec::with_capacity(compact_len + 32);
                    extended_payload.extend_from_slice(data_payload);
                    extended_payload.extend_from_slice(&accounts_hash);

                    Secp256r1Authenticator.authenticate(
                        accounts,
                        authority_data,
                        authority_payload,
                        &extended_payload,
                        &[4],
                    )?;
                },
                _ => return Err(AuthError::InvalidAuthenticationKind.into()),
            }
        },
        3 => {
            // Session (V3 with spending limits)
            is_session_auth = true;
        },
        _ => return Err(ProgramError::InvalidAccountData),
    }

    // Get vault bump for signing
    let (vault_key, vault_bump) =
        find_program_address(&[b"vault", wallet_pda.key().as_ref()], program_id);

    // Verify vault PDA.
    // CRITICAL: Ensure we are signing with the correct Vault derived from this Wallet.
    if vault_pda.key() != &vault_key {
        return Err(ProgramError::InvalidSeeds);
    }

    // Session validation (deferred to allow shared authority_data handling)
    if is_session_auth {
        let session_data = unsafe { authority_pda.borrow_mut_data_unchecked() };
        
        // V3 sessions are 128 bytes, legacy are 80 bytes
        let is_v3 = session_data.len() >= SessionAccount::SIZE;
        
        if session_data.len() < SessionAccount::LEGACY_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Use read_unaligned to safely load SessionAccount
        let session = unsafe {
            std::ptr::read_unaligned(session_data.as_ptr() as *const SessionAccount)
        };

        let clock = Clock::get()?;
        let current_slot = clock.slot;

        // Verify Wallet
        if session.wallet != *wallet_pda.key() {
            return Err(ProgramError::InvalidAccountData);
        }

        // Verify Expiry
        if current_slot > session.expires_at {
            return Err(AuthError::SessionExpired.into());
        }

        // V3: Check if session is revoked
        if is_v3 && session.is_revoked() {
            return Err(AuthError::SessionExpired.into());
        }

        // Verify Signer matches Session Key
        let mut signer_matched = false;
        for acc in accounts {
            if acc.is_signer() && *acc.key() == session.session_key {
                signer_matched = true;
                break;
            }
        }
        if !signer_matched {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Store mint for spending limit tracking (V3 only)
        if is_v3 {
            session_mint = Some(session.mint);
        }
    }

    // Record balance before CPIs for spending limit enforcement (V3 sessions)
    let balance_before = if session_mint.is_some() {
        vault_pda.lamports()
    } else {
        0
    };

    // Fee deduction: Transfer BASE_FEE_LAMPORTS from vault to fee_recipient
    // Fee recipient is read from FeeConfig PDA and verified above
    // Fee is MANDATORY - reject if fee_recipient not writable
    if !fee_recipient.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    deduct_fee(vault_pda, fee_recipient, system_program, vault_bump, wallet_pda.key())?;

    // Execute each compact instruction
    for compact_ix in &compact_instructions {
        let decompressed = compact_ix.decompress(accounts)?;

        // Build AccountMeta array for instruction
        let account_metas: Vec<AccountMeta> = decompressed
            .accounts
            .iter()
            .map(|acc| AccountMeta {
                pubkey: acc.key(),
                is_signer: acc.is_signer() || acc.key() == vault_pda.key(),
                is_writable: acc.is_writable(),
            })
            .collect();

        // Prevent self-reentrancy (Issue #10)
        // Reject CPI calls back into this program to avoid unexpected state mutations
        if decompressed.program_id.as_ref() == program_id.as_ref() {
            return Err(AuthError::SelfReentrancyNotAllowed.into());
        }

        // Create instruction
        let ix = Instruction {
            program_id: decompressed.program_id,
            accounts: &account_metas,
            data: &decompressed.data,
        };

        // Create seeds for vault signing (pinocchio style)
        let vault_bump_arr = [vault_bump];
        let seeds = [
            Seed::from(b"vault"),
            Seed::from(wallet_pda.key().as_ref()),
            Seed::from(&vault_bump_arr),
        ];
        let signer: Signer = (&seeds).into();

        // Convert AccountInfo to Account for invoke_signed_unchecked
        let cpi_accounts: Vec<Account> = decompressed
            .accounts
            .iter()
            .map(|acc| Account::from(*acc))
            .collect();

        // Invoke with vault as signer
        // Use unchecked invocation to support dynamic account list (slice)
        unsafe {
            invoke_signed_unchecked(&ix, &cpi_accounts, &[signer]);
        }
    }

    // Spending limit enforcement for V3 sessions
    if session_mint.is_some() {
        let balance_after = vault_pda.lamports();
        
        // Calculate spent amount (only positive spending, ignore deposits)
        let spent = balance_before.saturating_sub(balance_after);
        
        if spent > 0 {
            // Update session spent_amount
            let session_data = unsafe { authority_pda.borrow_mut_data_unchecked() };
            let session_ptr = session_data.as_mut_ptr() as *mut SessionAccount;
            
            // Read current session state
            let session = unsafe { std::ptr::read_unaligned(session_ptr) };
            
            // Check if spending would exceed limit
            if session.would_exceed_limit(spent) {
                return Err(AuthError::SpendingLimitExceeded.into());
            }
            
            // Update spent_amount
            let new_spent = session.spent_amount.saturating_add(spent);
            unsafe {
                // Write only the spent_amount field (offset: 1+1+1+1+4+32+32+8+32+8 = 120)
                let spent_offset = 120;
                std::ptr::write_unaligned(
                    session_data[spent_offset..].as_mut_ptr() as *mut u64,
                    new_spent,
                );
            }
        }
    }

    Ok(())
}

/// Compute SHA256 hash of all account pubkeys referenced by compact instructions (Issue #11)
///
/// This binds the signature to the exact accounts in their exact order,
/// preventing account reordering attacks where an attacker could swap
/// recipient addresses while keeping the signature valid.
///
/// # Arguments
/// * `accounts` - Slice of all account infos in the transaction
/// * `compact_instructions` - Parsed compact instructions containing account indices
///
/// # Returns
/// * 32-byte SHA256 hash of all referenced pubkeys
fn compute_accounts_hash(
    accounts: &[AccountInfo],
    compact_instructions: &[crate::compact::CompactInstruction],
) -> Result<[u8; 32], ProgramError> {
    // Collect all account pubkeys in order of reference
    let mut pubkeys_data = Vec::new();

    for ix in compact_instructions {
        // Include program_id
        let program_idx = ix.program_id_index as usize;
        if program_idx >= accounts.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        pubkeys_data.extend_from_slice(accounts[program_idx].key().as_ref());

        // Include all account pubkeys
        for &acc_idx in &ix.accounts {
            let idx = acc_idx as usize;
            if idx >= accounts.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            pubkeys_data.extend_from_slice(accounts[idx].key().as_ref());
        }
    }

    // Compute SHA256 hash
    #[allow(unused_assignments)]
    let mut hash = [0u8; 32];
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_sha256(
            [pubkeys_data.as_slice()].as_ptr() as *const u8,
            1,
            hash.as_mut_ptr(),
        );
    }
    #[cfg(not(target_os = "solana"))]
    {
        // For tests, use a dummy hash
        hash = [0xAA; 32];
        let _ = pubkeys_data; // suppress warning
    }

    Ok(hash)
}

/// Deduct fee from vault and transfer to fee recipient via CPI.
///
/// # Arguments
/// * `vault` - Vault PDA to deduct from (owned by System Program)
/// * `fee_recipient` - Account to receive the fee
/// * `system_program` - System Program for CPI transfer
/// * `vault_bump` - Bump seed for vault PDA signing
/// * `wallet_key` - Wallet pubkey for vault seed derivation
fn deduct_fee(
    vault: &AccountInfo,
    fee_recipient: &AccountInfo,
    system_program: &AccountInfo,
    vault_bump: u8,
    wallet_key: &Pubkey,
) -> ProgramResult {
    // Check vault has enough balance for fee
    let vault_balance = vault.lamports();
    if vault_balance < BASE_FEE_LAMPORTS {
        // Not enough for fee, skip (or return error if strict)
        return Ok(());
    }

    // Build System Program transfer instruction
    // Instruction data: [2, 0, 0, 0] (transfer = 2) + amount as u64 LE
    let mut transfer_data = [0u8; 12];
    transfer_data[0] = 2; // Transfer instruction index
    transfer_data[4..12].copy_from_slice(&BASE_FEE_LAMPORTS.to_le_bytes());

    let transfer_accounts = [
        AccountMeta {
            pubkey: vault.key(),
            is_signer: true,
            is_writable: true,
        },
        AccountMeta {
            pubkey: fee_recipient.key(),
            is_signer: false,
            is_writable: true,
        },
    ];

    let transfer_ix = Instruction {
        program_id: &Pubkey::from(crate::utils::SYSTEM_PROGRAM_ID),
        accounts: &transfer_accounts,
        data: &transfer_data,
    };

    // Create vault PDA signer seeds
    let vault_bump_arr = [vault_bump];
    let seeds = [
        Seed::from(b"vault"),
        Seed::from(wallet_key.as_ref()),
        Seed::from(&vault_bump_arr),
    ];
    let signer: Signer = (&seeds).into();

    // CPI to System Program with vault as signer
    let cpi_accounts = [
        Account::from(vault),
        Account::from(fee_recipient),
        Account::from(system_program),
    ];
    unsafe {
        invoke_signed_unchecked(&transfer_ix, &cpi_accounts, &[signer]);
    }

    Ok(())
}

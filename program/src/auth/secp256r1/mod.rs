use crate::{error::AuthError, state::authority::AuthorityAccountHeader};
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::instructions::{Instructions, INSTRUCTIONS_ID},
};
use pinocchio_pubkey::pubkey;

pub mod introspection;
pub mod nonce;
pub mod slothashes;
pub mod webauthn;

use self::introspection::verify_secp256r1_instruction_data;
use self::nonce::validate_nonce;
use self::webauthn::{
    verify_client_data_json_challenge, verify_client_data_json_type_get, AuthDataParser,
};

use crate::auth::traits::Authenticator;

/// Authenticator implementation for Secp256r1 (WebAuthn).
/// 
/// # V2 Changes (Chrome Compatibility Fix)
/// 
/// The V1 implementation used "reconstruction" - rebuilding clientDataJSON from flags
/// and comparing. This failed because browsers produce different JSON structures:
/// - Chrome adds "other_keys_can_be_added_here" field
/// - Safari may omit "crossOrigin"
/// - Field ordering varies
/// 
/// V2 accepts the actual clientDataJSON bytes from the client, parses out the
/// challenge field, and verifies it matches the expected value. This works across
/// all browsers since we only check the challenge, not the full JSON structure.
/// 
/// # Auth Payload Format (V2 with Chrome fix)
/// 
/// ```text
/// [0..8]   slot: u64 (LE) - for nonce/replay protection
/// [8]      sysvar_ix_index: u8 - index of instructions sysvar in accounts
/// [9]      sysvar_slothashes_index: u8 - index of slothashes sysvar in accounts
/// [10]     rp_id_len: u8 - length of RP ID
/// [11..11+rp_id_len] rp_id: bytes - RP ID for domain verification
/// [11+rp_id_len..13+rp_id_len] client_data_json_len: u16 (LE)
/// [13+rp_id_len..] client_data_json: bytes - actual clientDataJSON from WebAuthn
/// [after json..] authenticator_data: bytes - authenticator data from WebAuthn
/// ```
pub struct Secp256r1Authenticator;

impl Authenticator for Secp256r1Authenticator {
    /// Authenticates a Secp256r1 signature (WebAuthn/Passkeys).
    ///
    /// # Arguments
    /// * `accounts`: Slice of accounts, expecting Sysvar Lookups if needed.
    /// * `auth_data`: Mutable reference to the Authority account data (to update counter).
    /// * `auth_payload`: V2 format payload (see struct docs above).
    /// * `signed_payload`: The actual message/data that was signed (e.g. instruction args).
    /// * `discriminator`: Instruction discriminator for domain separation.
    fn authenticate(
        &self,
        accounts: &[AccountInfo],
        auth_data: &mut [u8],
        auth_payload: &[u8],
        signed_payload: &[u8],
        discriminator: &[u8],
    ) -> Result<(), ProgramError> {
        // Minimum: 8 (slot) + 1 + 1 + 1 (rp_id_len) = 11 bytes header
        if auth_payload.len() < 11 {
            return Err(AuthError::InvalidAuthorityPayload.into());
        }

        let slot = u64::from_le_bytes(auth_payload[0..8].try_into().unwrap());
        let sysvar_ix_index = auth_payload[8] as usize;
        let sysvar_slothashes_index = auth_payload[9] as usize;
        
        // Extract rp_id first (for domain verification)
        let rp_id_len = auth_payload[10] as usize;
        if auth_payload.len() < 11 + rp_id_len + 2 {
            return Err(AuthError::InvalidAuthorityPayload.into());
        }
        let rp_id = &auth_payload[11..11 + rp_id_len];
        
        // V2: Read clientDataJSON length and extract JSON bytes
        let json_len_offset = 11 + rp_id_len;
        let client_data_json_len = u16::from_le_bytes(auth_payload[json_len_offset..json_len_offset + 2].try_into().unwrap()) as usize;
        
        let json_offset = json_len_offset + 2;
        if auth_payload.len() < json_offset + client_data_json_len {
            return Err(AuthError::InvalidAuthorityPayload.into());
        }
        let client_data_json = &auth_payload[json_offset..json_offset + client_data_json_len];
        
        let authenticator_data_raw = &auth_payload[json_offset + client_data_json_len..];

        // Validate authenticator data minimum length (37 bytes: rpIdHash + flags + counter)
        if authenticator_data_raw.len() < 37 {
            return Err(AuthError::InvalidAuthorityPayload.into());
        }

        // Validate Nonce (SlotHashes)
        let slothashes_account = accounts
            .get(sysvar_slothashes_index)
            .ok_or(AuthError::InvalidAuthorityPayload)?;
        let _slot_hash = validate_nonce(slothashes_account, slot)?;

        let header_size = std::mem::size_of::<AuthorityAccountHeader>();
        if auth_data.len() < header_size {
            return Err(AuthError::InvalidAuthorityPayload.into());
        }

        // Safe read using unaligned access
        let mut header = unsafe {
            std::ptr::read_unaligned(auth_data.as_ptr() as *const AuthorityAccountHeader)
        };

        // Secp256r1 on-chain data layout:
        //   [Header] [credential_id_hash(32)] [Pubkey(33)]
        // Note: credential_id_hash is stored for off-chain wallet discovery
        //       via getProgramAccounts + memcmp filter. It is not used in authentication.
        let pubkey_offset = header_size + 32; // skip credential_id_hash

        // Compute rp_id_hash from provided rp_id
        #[allow(unused_assignments)]
        let mut computed_rp_id_hash = [0u8; 32];
        #[cfg(target_os = "solana")]
        unsafe {
            let _res = pinocchio::syscalls::sol_sha256(
                [rp_id].as_ptr() as *const u8,
                1,
                computed_rp_id_hash.as_mut_ptr(),
            );
        }
        #[cfg(not(target_os = "solana"))]
        {
            computed_rp_id_hash = [0u8; 32];
        }

        // Verify payer is signer (for challenge computation)
        let payer = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !payer.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Extract auth_prefix (everything before json_len) for challenge computation
        // This avoids circular dependency: JSON contains challenge, so we can't include JSON in challenge hash
        // auth_prefix = [slot:8][ix_idx:1][slothash_idx:1][rp_id_len:1][rp_id:N]
        let auth_prefix = &auth_payload[0..json_len_offset];

        // Compute expected challenge: sha256(discriminator || auth_prefix || signed_payload || slot || payer)
        #[allow(unused_assignments)]
        let mut expected_challenge = [0u8; 32];
        #[cfg(target_os = "solana")]
        unsafe {
            let _res = pinocchio::syscalls::sol_sha256(
                [
                    discriminator,
                    auth_prefix,
                    signed_payload,
                    &slot.to_le_bytes(),
                    payer.key().as_ref(),
                ]
                .as_ptr() as *const u8,
                5,
                expected_challenge.as_mut_ptr(),
            );
        }
        #[cfg(not(target_os = "solana"))]
        {
            let _ = (discriminator, signed_payload);
            expected_challenge = [0u8; 32];
        }

        // V2 Chrome fix: Verify clientDataJSON contains the expected challenge
        // This extracts the "challenge" field from JSON and compares (base64url decoded)
        verify_client_data_json_challenge(client_data_json, &expected_challenge)?;
        
        // V2: Verify type is "webauthn.get" (assertion, not registration)
        verify_client_data_json_type_get(client_data_json)?;

        // Hash the actual clientDataJSON for signature verification
        #[allow(unused_assignments)]
        let mut client_data_hash = [0u8; 32];
        #[cfg(target_os = "solana")]
        unsafe {
            let _res = pinocchio::syscalls::sol_sha256(
                [client_data_json].as_ptr() as *const u8,
                1,
                client_data_hash.as_mut_ptr(),
            );
        }
        #[cfg(not(target_os = "solana"))]
        {
            client_data_hash = [0u8; 32];
        }

        let auth_data_parser = AuthDataParser::new(authenticator_data_raw);
        if !auth_data_parser.is_user_present() {
            return Err(AuthError::PermissionDenied.into());
        }

        let authenticator_counter = auth_data_parser.counter() as u64;

        if authenticator_counter > 0 && authenticator_counter <= header.counter {
            return Err(AuthError::SignatureReused.into());
        }
        header.counter = authenticator_counter;
        unsafe {
            std::ptr::write_unaligned(
                auth_data.as_mut_ptr() as *mut AuthorityAccountHeader,
                header,
            );
        }

        // Security Validation: Verify domain
        // Ensure the rp_id provided in the payload actually matches
        // the rpIdHash that the authenticator signed over inside authenticatorData.
        if auth_data_parser.rp_id_hash() != computed_rp_id_hash {
            return Err(AuthError::InvalidPubkey.into());
        }

        // Extract the 33-byte COMPRESSED key from authority account
        let instruction_pubkey_bytes = &auth_data[pubkey_offset..pubkey_offset + 33];
        let expected_pubkey: &[u8; 33] = instruction_pubkey_bytes.try_into().unwrap();

        // Build signed message: authenticatorData || sha256(clientDataJSON)
        let mut signed_message = Vec::with_capacity(authenticator_data_raw.len() + 32);
        signed_message.extend_from_slice(authenticator_data_raw);
        signed_message.extend_from_slice(&client_data_hash);

        let sysvar_instructions = accounts
            .get(sysvar_ix_index)
            .ok_or(AuthError::InvalidAuthorityPayload)?;
        if sysvar_instructions.key().as_ref() != INSTRUCTIONS_ID.as_ref() {
            return Err(AuthError::InvalidInstruction.into());
        }

        let sysvar_data = unsafe { sysvar_instructions.borrow_data_unchecked() };
        let ixs = unsafe { Instructions::new_unchecked(sysvar_data) };
        let current_index = ixs.load_current_index() as usize;
        if current_index == 0 {
            return Err(AuthError::InvalidInstruction.into());
        }

        let secp_ix = unsafe { ixs.deserialize_instruction_unchecked(current_index - 1) };
        if secp_ix.get_program_id() != &pubkey!("Secp256r1SigVerify1111111111111111111111111") {
            return Err(AuthError::InvalidInstruction.into());
        }

        verify_secp256r1_instruction_data(
            secp_ix.get_instruction_data(),
            expected_pubkey,
            &signed_message,
        )?;

        Ok(())
    }
}

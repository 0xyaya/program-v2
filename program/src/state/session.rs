use no_padding::NoPadding;
use pinocchio::pubkey::Pubkey;

/// Current session account version (V3 with spending limits)
pub const CURRENT_SESSION_VERSION: u8 = 3;

/// Native SOL represented as all zeros
pub const NATIVE_SOL_MINT: [u8; 32] = [0u8; 32];

#[repr(C, align(8))]
#[derive(NoPadding)]
/// Ephemeral Session Account V3.
///
/// Represents a temporary delegated authority with an expiration time
/// and spending limits.
pub struct SessionAccount {
    /// Account discriminator (must be `3` for Session).
    pub discriminator: u8, // 1
    /// Bump seed for this PDA.
    pub bump: u8, // 1
    /// Account Version (3 for V3).
    pub version: u8, // 1
    /// Flags (bit 0: revoked).
    pub flags: u8, // 1
    /// Reserved for future use.
    pub _reserved: [u8; 4], // 4
    /// The wallet this session belongs to.
    pub wallet: Pubkey, // 32
    /// The ephemeral public key authorized to sign.
    pub session_key: Pubkey, // 32
    /// Absolute slot height when this session expires.
    pub expires_at: u64, // 8
    /// Allowed token mint (all zeros = native SOL).
    pub mint: Pubkey, // 32
    /// Maximum spendable amount.
    pub max_amount: u64, // 8
    /// Cumulative spent amount.
    pub spent_amount: u64, // 8
}
// Total: 128 bytes

impl SessionAccount {
    /// Size of V3 session account in bytes.
    pub const SIZE: usize = 128;

    /// Size of legacy session account (V1/V2).
    pub const LEGACY_SIZE: usize = 80;

    /// Check if this session has been revoked.
    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if this session tracks native SOL.
    #[inline]
    pub fn is_native_sol(&self) -> bool {
        self.mint.eq(&NATIVE_SOL_MINT)
    }

    /// Calculate remaining spendable amount.
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.max_amount.saturating_sub(self.spent_amount)
    }

    /// Check if spending `amount` would exceed the limit.
    #[inline]
    pub fn would_exceed_limit(&self, amount: u64) -> bool {
        self.spent_amount.saturating_add(amount) > self.max_amount
    }

    /// Record spending and return true if successful, false if limit exceeded.
    #[inline]
    pub fn record_spending(&mut self, amount: u64) -> bool {
        if self.would_exceed_limit(amount) {
            false
        } else {
            self.spent_amount = self.spent_amount.saturating_add(amount);
            true
        }
    }
}

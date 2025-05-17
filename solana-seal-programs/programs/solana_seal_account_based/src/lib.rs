use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;

declare_id!("8G4ruxnreCskTDTHN43PtKsU7oBzW3ReZEpLcsfeHDmp");

#[program]
pub mod solana_seal_account_based {
    use super::*;

    /// Initialize an account-based encryption account
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let account = &mut ctx.accounts.account;
        account.owner = ctx.accounts.owner.key();
        account.bump = ctx.bumps.account;
        Ok(())
    }

    /// Seal approve - verify access control
    pub fn seal_approve(ctx: Context<SealApprove>) -> Result<()> {
        let account = &ctx.accounts.account;
        require!(
            account.owner == ctx.accounts.owner.key(),
            AccountBasedError::NoAccess
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + AccountBased::LEN,
        seeds = [b"account_based", owner.key().as_ref()],
        bump
    )]
    pub account: Account<'info, AccountBased>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SealApprove<'info> {
    #[account(
        seeds = [b"account_based", account.owner.as_ref()],
        bump = account.bump
    )]
    pub account: Account<'info, AccountBased>,
    pub owner: Signer<'info>,
}

#[account]
pub struct AccountBased {
    pub owner: Pubkey,
    pub bump: u8,
}

impl AccountBased {
    pub const LEN: usize = 32 + 1; // owner + bump
}

#[error_code]
pub enum AccountBasedError {
    #[msg("No access to this account")]
    NoAccess,
} 
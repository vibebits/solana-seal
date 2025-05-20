use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;

declare_id!("5E7FfNPZjzbxLJCTz64oTsk1ZpKZKDsqAiG5H3igxe9x");

// Helper function to check if an ID has the correct prefix
fn check_id_prefix(id: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > id.len() {
        return false;
    }
    id.iter().zip(prefix.iter()).all(|(a, b)| a == b)
}

#[program]
pub mod solana_seal_whitelist {
    use super::*;

    // seal_approve will accept id as uint8array
    // it will get user from the context
    // user has proxy signed with sessionKey for the program
    // it will return ok if user is in the whitelist
    // else it will return not_ok (won't throw error)
    // so that multiple instructions can be simulated in a single transaction
    pub fn seal_approve(ctx: Context<SealApprove>, id: Vec<u8>) -> Result<String> {
        let whitelist = &ctx.accounts.whitelist;
        let address_list = &ctx.accounts.address_list;
        let user = &ctx.accounts.user;

        msg!("whitelist seal_approve id: {:?}, user: {}", id, user.key());
        msg!("whitelist: {:?}", whitelist.id);
        msg!("address_list: {:?}", address_list.key());

        // Check if the ID has the right prefix
        if !check_id_prefix(&id, address_list.key().as_ref()) {
            return Ok("not_ok".to_string());
        }

        if address_list.addresses.contains(&user.key()) {
            Ok("ok".to_string())
        } else {
            Ok("not_ok".to_string())
        }
    }

    pub fn create_whitelist(ctx: Context<CreateWhitelist>) -> Result<()> {
        let whitelist = &mut ctx.accounts.whitelist;
        whitelist.authority = ctx.accounts.authority.key();
        whitelist.bump = ctx.bumps.whitelist;
        whitelist.id = ctx.accounts.authority.key(); // Set initial ID to authority's pubkey
        Ok(())
    }

    pub fn add_to_whitelist(ctx: Context<AddToWhitelist>, address: Pubkey) -> Result<()> {
        let whitelist = &mut ctx.accounts.whitelist;
        require!(
            whitelist.authority == ctx.accounts.authority.key(),
            WhitelistError::InvalidAuthority
        );

        // Add address to whitelist
        let address_list = &mut ctx.accounts.address_list;
        address_list.addresses.push(address);
        Ok(())
    }

    pub fn remove_from_whitelist(ctx: Context<RemoveFromWhitelist>, address: Pubkey) -> Result<()> {
        let whitelist = &mut ctx.accounts.whitelist;
        require!(
            whitelist.authority == ctx.accounts.authority.key(),
            WhitelistError::InvalidAuthority
        );

        // Remove address from whitelist
        let address_list = &mut ctx.accounts.address_list;
        if let Some(pos) = address_list.addresses.iter().position(|x| *x == address) {
            address_list.addresses.remove(pos);
        }
        Ok(())
    }

    pub fn verify_whitelist(ctx: Context<VerifyWhitelist>) -> Result<()> {
        let address_list = &ctx.accounts.address_list;
        require!(
            address_list.addresses.contains(&ctx.accounts.user.key()),
            WhitelistError::NotInWhitelist
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateWhitelist<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Whitelist::LEN,
        seeds = [b"whitelist", authority.key().as_ref()],
        bump
    )]
    pub whitelist: Account<'info, Whitelist>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AddToWhitelist<'info> {
    #[account(
        mut,
        seeds = [b"whitelist", whitelist.authority.as_ref()],
        bump = whitelist.bump
    )]
    pub whitelist: Account<'info, Whitelist>,
    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + AddressList::LEN,
        seeds = [b"address_list", whitelist.key().as_ref()],
        bump
    )]
    pub address_list: Account<'info, AddressList>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveFromWhitelist<'info> {
    #[account(
        mut,
        seeds = [b"whitelist", whitelist.authority.as_ref()],
        bump = whitelist.bump
    )]
    pub whitelist: Account<'info, Whitelist>,
    #[account(
        mut,
        seeds = [b"address_list", whitelist.key().as_ref()],
        bump
    )]
    pub address_list: Account<'info, AddressList>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct VerifyWhitelist<'info> {
    #[account(
        seeds = [b"whitelist", whitelist.authority.as_ref()],
        bump = whitelist.bump
    )]
    pub whitelist: Account<'info, Whitelist>,
    #[account(
        seeds = [b"address_list", whitelist.key().as_ref()],
        bump
    )]
    pub address_list: Account<'info, AddressList>,
    /// CHECK: This is the user we're verifying
    pub user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SealApprove<'info> {
    /// CHECK: This is the user account whose public key will be checked against the whitelist.
    /// It is not mutated and not required to be a signer for this instruction.
    /// this is also checked by key server against certificate, in case if user account is using in program logic
    pub user: AccountInfo<'info>,
    #[account(
        seeds = [b"whitelist", whitelist.authority.as_ref()],
        bump = whitelist.bump
    )]
    pub whitelist: Account<'info, Whitelist>,
    #[account(
        seeds = [b"address_list", whitelist.key().as_ref()],
        bump
    )]
    pub address_list: Account<'info, AddressList>,
}

#[account]
pub struct Whitelist {
    pub authority: Pubkey,
    pub bump: u8,
    pub id: Pubkey, // Added to store the prefix ID
}

impl Whitelist {
    pub const LEN: usize = 32 + 1 + 32; // authority + bump + id
}

#[account]
pub struct AddressList {
    pub addresses: Vec<Pubkey>,
}

impl AddressList {
    pub const LEN: usize = 4 + (32 * 100); // vec length + max 100 addresses
}

#[error_code]
pub enum WhitelistError {
    #[msg("Invalid authority")]
    InvalidAuthority,
    #[msg("Address not in whitelist")]
    NotInWhitelist,
    #[msg("No access to this account")]
    NoAccess,
}

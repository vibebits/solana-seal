use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;

declare_id!("HMyQGJVyXw5MvpHbKQ8noKXcbtX9TyPkwM8TcyHSFdTJ");

#[program]
pub mod solana_seal_starter {
    use super::*;

    // seal_approve will accept address id as uint8array
    // if its first 3 items are [49, 50, 51] it will return ok
    // else it will return not_ok (won't throw error)
    // so that multiple instructions can be simulated in a single transaction
    pub fn seal_approve(ctx: Context<SealApprove>, id: Vec<u8>) -> Result<String> {
        let user = &ctx.accounts.user;

        msg!("starter seal_approve id: {:?}, user: {}", id, user.key());

        // check if first 3 items are [49, 50, 51]
        if id.len() < 3 {
            return Ok("not_ok".to_string());
        }
        if id[0] != 49 || id[1] != 50 || id[2] != 51 {
            return Ok("not_ok".to_string());
        }

        Ok("ok".to_string())
    }
}

#[derive(Accounts)]
pub struct SealApprove<'info> {
    /// CHECK: This is the user account whose public key will be checked against the whitelist.
    /// It is not mutated and not required to be a signer for this instruction.
    /// this is also checked by key server against certificate, in case if user account is using in program logic
    pub user: AccountInfo<'info>,
}

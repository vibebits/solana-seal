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
    pub fn seal_approve(_ctx: Context<SealApprove>, id: Vec<u8>) -> Result<String> {
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
pub struct SealApprove {
    // empty as no accounts are needed
}

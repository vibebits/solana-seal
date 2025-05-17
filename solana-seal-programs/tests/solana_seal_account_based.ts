import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaSealAccountBased } from "../target/types/solana_seal_account_based";
import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";

describe("solana_seal_account_based", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaSealAccountBased as Program<SolanaSealAccountBased>;
  const wallet = provider.wallet as anchor.Wallet;

  it("Initializes an account-based encryption account", async () => {
    const [accountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("account_based"), wallet.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .initialize()
      .accounts({
        account: accountPda,
        owner: wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const account = await program.account.accountBased.fetch(accountPda);
    expect(account.owner.toString()).to.equal(wallet.publicKey.toString());
  });

  it("Approves access for the owner", async () => {
    const [accountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("account_based"), wallet.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .sealApprove()
      .accounts({
        account: accountPda,
        owner: wallet.publicKey,
      })
      .rpc();
  });

  it("Fails when non-owner tries to access", async () => {
    const [accountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("account_based"), wallet.publicKey.toBuffer()],
      program.programId
    );

    // Create a new keypair to simulate a different user
    const otherUser = anchor.web3.Keypair.generate();

    try {
      await program.methods
        .sealApprove()
        .accounts({
          account: accountPda,
          owner: otherUser.publicKey,
        })
        .signers([otherUser])
        .rpc();
      expect.fail("Expected transaction to fail");
    } catch (err) {
      expect(err.toString()).to.include("No access to this account");
    }
  });
}); 
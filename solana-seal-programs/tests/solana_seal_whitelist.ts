import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaSealWhitelist } from "../target/types/solana_seal_whitelist";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { expect } from "chai";

describe("solana_seal_whitelist", () => {
  // Configure the client to use the local cluster
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaSealWhitelist as Program<SolanaSealWhitelist>;
  
  // Test accounts
  const authority = Keypair.generate();
  const user1 = Keypair.generate();
  const user2 = Keypair.generate();
  
  // PDAs for verification
  let whitelistPda: PublicKey;
  let addressListPda: PublicKey;
  let whitelistBump: number;

  before(async () => {
    // Airdrop SOL to authority for testing
    const signature = await provider.connection.requestAirdrop(
      authority.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(signature);

    // Calculate PDAs for verification
    [whitelistPda, whitelistBump] = await PublicKey.findProgramAddress(
      [Buffer.from("whitelist"), authority.publicKey.toBuffer()],
      program.programId
    );

    [addressListPda] = await PublicKey.findProgramAddress(
      [Buffer.from("address_list"), whitelistPda.toBuffer()],
      program.programId
    );
  });

  it("Creates a whitelist", async () => {
    await program.methods
      .createWhitelist()
      .accounts({
        whitelist: whitelistPda,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Verify whitelist was created
    const whitelistAccount = await program.account.whitelist.fetch(whitelistPda);
    expect(whitelistAccount.authority.toString()).to.equal(authority.publicKey.toString());
    expect(whitelistAccount.bump).to.equal(whitelistBump);
  });

  it("Adds addresses to whitelist", async () => {
    // Add user1 to whitelist
    await program.methods
      .addToWhitelist(user1.publicKey)
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Add user2 to whitelist
    await program.methods
      .addToWhitelist(user2.publicKey)
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Verify addresses were added
    const addressListAccount = await program.account.addressList.fetch(addressListPda);
    expect(addressListAccount.addresses.length).to.equal(2);
    expect(addressListAccount.addresses[0].toString()).to.equal(user1.publicKey.toString());
    expect(addressListAccount.addresses[1].toString()).to.equal(user2.publicKey.toString());
  });

  it("Verifies whitelisted addresses", async () => {
    // Verify user1 is whitelisted
    await program.methods
      .verifyWhitelist()
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        user: user1.publicKey,
      })
      .rpc();

    // Verify user2 is whitelisted
    await program.methods
      .verifyWhitelist()
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        user: user2.publicKey,
      })
      .rpc();
  });

  it("Removes address from whitelist", async () => {
    // Remove user1 from whitelist
    await program.methods
      .removeFromWhitelist(user1.publicKey)
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        authority: authority.publicKey,
      })
      .signers([authority])
      .rpc();

    // Verify user1 was removed
    const addressListAccount = await program.account.addressList.fetch(addressListPda);
    expect(addressListAccount.addresses.length).to.equal(1);
    expect(addressListAccount.addresses[0].toString()).to.equal(user2.publicKey.toString());
  });

  it("Fails to verify non-whitelisted address", async () => {
    // Try to verify user1 (who was removed)
    try {
      await program.methods
        .verifyWhitelist()
        .accounts({
          whitelist: whitelistPda,
          addressList: addressListPda,
          user: user1.publicKey,
        })
        .rpc();
      expect.fail("Expected error but got success");
    } catch (err) {
      expect(err.toString()).to.include("Address not in whitelist");
    }
  });

  it("Fails when non-authority tries to modify whitelist", async () => {
    // Try to add user1 back using user2 as authority
    try {
      await program.methods
        .addToWhitelist(user1.publicKey)
        .accounts({
          whitelist: whitelistPda,
          addressList: addressListPda,
          authority: user2.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([user2])
        .rpc();
      expect.fail("Expected error but got success");
    } catch (err) {
      expect(err.toString()).to.include("Invalid authority");
    }
  });

  // New tests for seal_approve functionality
  it("Successfully approves access with correct prefix and whitelisted user", async () => {
    // Create a test ID that matches the prefix (using authority's pubkey as prefix)
    const testId = Buffer.concat([
      authority.publicKey.toBuffer(),
      Buffer.from("some_suffix")
    ]);

    await program.methods
      .sealApprove(testId)
      .accounts({
        whitelist: whitelistPda,
        addressList: addressListPda,
        user: user2.publicKey, // user2 is still in whitelist
      })
      .rpc();
  });

  it("Fails to approve access with incorrect prefix", async () => {
    // Create a test ID that doesn't match the prefix
    const wrongPrefix = Keypair.generate();
    const testId = Buffer.concat([
      wrongPrefix.publicKey.toBuffer(),
      Buffer.from("some_suffix")
    ]);

    try {
      await program.methods
        .sealApprove(testId)
        .accounts({
          whitelist: whitelistPda,
          addressList: addressListPda,
          user: user2.publicKey,
        })
        .rpc();
      expect.fail("Expected error but got success");
    } catch (err) {
      expect(err.toString()).to.include("No access to this account");
    }
  });

  it("Fails to approve access for non-whitelisted user", async () => {
    // Create a test ID that matches the prefix
    const testId = Buffer.concat([
      authority.publicKey.toBuffer(),
      Buffer.from("some_suffix")
    ]);

    try {
      await program.methods
        .sealApprove(testId)
        .accounts({
          whitelist: whitelistPda,
          addressList: addressListPda,
          user: user1.publicKey, // user1 was removed from whitelist
        })
        .rpc();
      expect.fail("Expected error but got success");
    } catch (err) {
      expect(err.toString()).to.include("No access to this account");
    }
  });
});
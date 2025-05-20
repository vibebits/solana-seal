import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  Keypair,
  SystemProgram,
} from "@solana/web3.js";
import { Buffer } from "buffer";
import { WHITELIST_PROGRAM_ID, AUTHORITY_PUBLIC_KEY } from "@/utils/constants";

export async function getFullEncryptionId(encryptionId: string) {
  // this is the simplest one
  // return Buffer.from(encryptionId).toString('hex');

  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), AUTHORITY_PUBLIC_KEY.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(`(AddToWhitelist) Whitelist PDA: ${whitelistPda.toBase58()}`);

  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );

  // it is obtained from addressListPda
  const whitelistIdBase58String: string = addressListPda.toBase58();
  
  // 1. Convert whitelistIdString (Base58 Pubkey) to Buffer
  const whitelistIdPubkey = new PublicKey(whitelistIdBase58String);
  const whitelistIdBytes: Buffer = whitelistIdPubkey.toBuffer(); // This is your 32-byte prefix

  // 2. Convert encryptionId to Buffer (UTF-8 encoded)
  const encryptionIdBytes: Buffer = Buffer.from(encryptionId, "utf8");

  // 3. Concatenate the two Buffers
  const combinedIdBytes: Buffer = Buffer.concat([
    whitelistIdBytes,
    encryptionIdBytes,
  ]);

  // for whitelist we need to add whitelist id as prefix
  return combinedIdBytes.toString("hex");
}

export async function createWhitelist(
  connection: Connection,
  authorityKeypair: Keypair
): Promise<string> {
  const authorityPublicKey = authorityKeypair.publicKey;

  // === 1. Create Whitelist Instruction ===
  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), authorityPublicKey.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(
    "(createWhitelist) Using authority:",
    authorityPublicKey.toBase58()
  );
  console.log(
    "(createWhitelist) Whitelist PDA to be created:",
    whitelistPda.toBase58()
  );

  // Discriminator for global:create_whitelist
  const createDiscriminator = Buffer.from([89, 182, 231, 206, 68, 173, 60, 6]);
  const createInstruction = new TransactionInstruction({
    programId: WHITELIST_PROGRAM_ID,
    keys: [
      { pubkey: whitelistPda, isSigner: false, isWritable: true },
      { pubkey: authorityPublicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: createDiscriminator,
  });

  // === 2. Add to Whitelist Instruction (to initialize AddressList) ===
  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(
    "(createWhitelist) AddressList PDA to be initialized/used:",
    addressListPda.toBase58()
  );

  // Discriminator for global:add_to_whitelist
  const addDiscriminator = Buffer.from([157, 211, 52, 54, 144, 81, 5, 55]);
  const addressToAddBuffer = authorityPublicKey.toBuffer(); // Adding the authority itself

  const addInstructionData = Buffer.concat([
    addDiscriminator,
    addressToAddBuffer, // Argument for add_to_whitelist is the Pubkey to add
  ]);

  const addInstruction = new TransactionInstruction({
    programId: WHITELIST_PROGRAM_ID,
    keys: [
      { pubkey: whitelistPda, isSigner: false, isWritable: true },
      { pubkey: addressListPda, isSigner: false, isWritable: true },
      { pubkey: authorityPublicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: addInstructionData,
  });

  // === Transaction Assembly & Sending ===
  const transaction = new Transaction()
    .add(createInstruction)
    .add(addInstruction);
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = authorityKeypair.publicKey; // FEEPAYER pays transaction fees

  console.log(
    `(createWhitelist) Preparing transaction to create whitelist AND add initial address for authority ${authorityPublicKey.toBase58()}.`
  );

  try {
    // AUTHORITY must sign because it's marked as signer in instruction keys
    // FEEPAYER must sign because it's the feePayer for the transaction
    const signers = [authorityKeypair];
    const txHash = await connection.sendTransaction(transaction, signers, {
      skipPreflight: false,
    });
    console.log(
      "(createWhitelist) Combined CreateWhitelist & AddToWhitelist TX sent. Hash:",
      txHash
    );
    await connection.confirmTransaction(txHash, "confirmed");
    console.log("(createWhitelist) Transaction confirmed.");

    return txHash;
  } catch (e: unknown) {
    console.error("(createWhitelist) Error sending combined transaction:", e);
    if (
      e instanceof Error &&
      e.message &&
      e.message.includes("Transaction simulation failed")
    ) {
      // Check if the error object might have Solana-specific logs
      const errorWithLogs = e as { logs?: string[] }; // Type assertion
      if (errorWithLogs.logs && Array.isArray(errorWithLogs.logs)) {
        console.error("(createWhitelist) Error logs:", errorWithLogs.logs);
      } else {
        try {
          const simError = await connection.simulateTransaction(transaction, [
            authorityKeypair,
          ]);
          console.error(
            "(createWhitelist) Simulation logs on error:",
            simError.value.logs
          );
        } catch (simCatchError) {
          console.error(
            "(createWhitelist) Error during simulation in catch block:",
            simCatchError
          );
        }
      }
    }
    throw e;
  }
}

export async function addToWhitelist(
  connection: Connection,
  authorityKeypair: Keypair, // The authority of the whitelist, signs and pays
  addressToAdd: PublicKey // The address to add to the whitelist
): Promise<string> {
  const authorityPublicKey = authorityKeypair.publicKey;

  console.log(`(AddToWhitelist) Authority: ${authorityPublicKey.toBase58()}`);
  console.log(`(AddToWhitelist) Address to add: ${addressToAdd.toBase58()}`);

  // 1. Derive Whitelist PDA (controlled by the authority)
  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), authorityPublicKey.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(`(AddToWhitelist) Whitelist PDA: ${whitelistPda.toBase58()}`);

  // 2. Derive AddressList PDA (associated with the Whitelist PDA)
  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(`(AddToWhitelist) AddressList PDA: ${addressListPda.toBase58()}`);

  // 3. Discriminator for global:add_to_whitelist
  const discriminator = Buffer.from([157, 211, 52, 54, 144, 81, 5, 55]);

  // 4. Instruction data: discriminator + address_to_add (as buffer)
  const instructionData = Buffer.concat([
    discriminator,
    addressToAdd.toBuffer(),
  ]);

  // 5. Create the instruction
  const instruction = new TransactionInstruction({
    programId: WHITELIST_PROGRAM_ID,
    keys: [
      { pubkey: whitelistPda, isSigner: false, isWritable: true }, // Whitelist account (mutable because its data might be read for checks, though AddToWhitelist primarily modifies AddressList)
      { pubkey: addressListPda, isSigner: false, isWritable: true }, // AddressList account (mutable, new address added here)
      { pubkey: authorityPublicKey, isSigner: true, isWritable: true }, // Authority must sign
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // System program (for potential account creation by init_if_needed)
    ],
    data: instructionData,
  });

  // 6. Create and return the transaction
  const transaction = new Transaction().add(instruction);
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = authorityPublicKey; // Authority pays the transaction fee

  console.log("(AddToWhitelist) Transaction prepared.");

  // send the transaction
  const txHash = await connection.sendTransaction(transaction, [
    authorityKeypair,
  ]);
  console.log("(AddToWhitelist) Transaction sent. Hash:", txHash);

  return txHash;
}

export async function removeFromWhitelist(
  connection: Connection,
  authorityKeypair: Keypair, // The authority of the whitelist, signs and pays
  addressToRemove: PublicKey // The address to remove from the whitelist
): Promise<string> {
  const authorityPublicKey = authorityKeypair.publicKey;

  console.log(
    `(RemoveFromWhitelist) Authority: ${authorityPublicKey.toBase58()}`
  );
  console.log(
    `(RemoveFromWhitelist) Address to remove: ${addressToRemove.toBase58()}`
  );

  // 1. Derive Whitelist PDA (controlled by the authority)
  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), authorityPublicKey.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(
    `(RemoveFromWhitelist) Whitelist PDA: ${whitelistPda.toBase58()}`
  );

  // 2. Derive AddressList PDA (associated with the Whitelist PDA)
  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(
    `(RemoveFromWhitelist) AddressList PDA: ${addressListPda.toBase58()}`
  );

  // 3. Discriminator for global:remove_from_whitelist
  const discriminator = Buffer.from([7, 144, 216, 239, 243, 236, 193, 235]); // Updated discriminator from IDL

  // 4. Instruction data: discriminator + address_to_remove (as buffer)
  const instructionData = Buffer.concat([
    discriminator,
    addressToRemove.toBuffer(),
  ]);

  // 5. Create the instruction
  const instruction = new TransactionInstruction({
    programId: WHITELIST_PROGRAM_ID,
    keys: [
      { pubkey: whitelistPda, isSigner: false, isWritable: true },
      { pubkey: addressListPda, isSigner: false, isWritable: true },
      { pubkey: authorityPublicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: instructionData,
  });

  // 6. Create and return the transaction
  const transaction = new Transaction().add(instruction);
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = authorityPublicKey;

  console.log("(RemoveFromWhitelist) Transaction prepared.");

  // send the transaction
  const txHash = await connection.sendTransaction(transaction, [
    authorityKeypair,
  ]);
  console.log("(RemoveFromWhitelist) Transaction sent. Hash:", txHash);

  // Wait for confirmation
  console.log("(RemoveFromWhitelist) Waiting for confirmation...");
  const confirmation = await connection.confirmTransaction(txHash, "confirmed");
  if (confirmation.value.err) {
    console.error(
      "(RemoveFromWhitelist) Transaction failed to confirm:",
      confirmation.value.err
    );
    throw new Error("Transaction failed to confirm");
  }
  console.log("(RemoveFromWhitelist) Transaction confirmed successfully");

  return txHash;
}

export async function verifyWhitelist(
  connection: Connection,
  authorityPublicKey: PublicKey, // The authority of the whitelist
  addressToVerify: PublicKey // The address to verify
): Promise<boolean> {
  console.log(`(VerifyWhitelist) Authority: ${authorityPublicKey.toBase58()}`);
  console.log(
    `(VerifyWhitelist) Address to verify: ${addressToVerify.toBase58()}`
  );

  // 1. Derive Whitelist PDA (controlled by the authority)
  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), authorityPublicKey.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(`(VerifyWhitelist) Whitelist PDA: ${whitelistPda.toBase58()}`);

  // 2. Derive AddressList PDA (associated with the Whitelist PDA)
  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  console.log(
    `(VerifyWhitelist) AddressList PDA: ${addressListPda.toBase58()}`
  );

  try {
    // 3. Get the AddressList account data
    const addressListAccount = await connection.getAccountInfo(addressListPda);
    if (!addressListAccount) {
      console.log("(VerifyWhitelist) AddressList account not found");
      return false;
    }

    // 4. Parse the account data to check if the address is in the list
    // The account data structure should be:
    // - First 8 bytes: discriminator
    // - Next 4 bytes: number of addresses (u32)
    // - Remaining bytes: array of addresses (each 32 bytes)
    const data = addressListAccount.data;
    const numAddresses = data.readUInt32LE(8); // Read u32 after discriminator
    const addresses = [];

    for (let i = 0; i < numAddresses; i++) {
      const start = 12 + i * 32; // Skip discriminator (8) + count (4) + previous addresses
      const addressBytes = data.slice(start, start + 32);
      const address = new PublicKey(addressBytes);
      addresses.push(address);
    }

    // 5. Check if the address is in the list
    const isWhitelisted = addresses.some((addr) =>
      addr.equals(addressToVerify)
    );
    console.log(
      `(VerifyWhitelist) Address ${addressToVerify.toBase58()} is ${
        isWhitelisted ? "whitelisted" : "not whitelisted"
      }`
    );

    return isWhitelisted;
  } catch (error) {
    console.error("(VerifyWhitelist) Error verifying whitelist:", error);
    return false;
  }
}

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { Buffer } from "buffer";
import { WHITELIST_PROGRAM_ID, DUMMY_FEEPAYER, AUTHORITY_PUBLIC_KEY, SEAL_APPROVE_DISCRIMINATOR } from "@/utils/constants";

export async function createWhitelistSealIx(
  connection: Connection,
  sessionKeyPubkey: PublicKey,
  encryptionId: string // Hex string for the id: Vec<u8> argument
): Promise<TransactionInstruction> {
  const authorityForPDA = AUTHORITY_PUBLIC_KEY;
  
  // PDAs derived using authorityForPDA (AUTHORITY_PUBLIC_KEY)
  const [whitelistPda] = await PublicKey.findProgramAddress(
    [Buffer.from("whitelist"), authorityForPDA.toBuffer()],
    WHITELIST_PROGRAM_ID
  );
  const [addressListPda] = await PublicKey.findProgramAddress(
    [Buffer.from("address_list"), whitelistPda.toBuffer()],
    WHITELIST_PROGRAM_ID
  );

  console.log(`whitelistPda: ${whitelistPda.toBase58()}`);
  console.log(`addressListPda: ${addressListPda.toBase58()}`);

  // Prepare the id argument from encryptionId (hex string)
  // This will be passed as `id: Vec<u8>` to the Rust function.
  // Anchor expects Vec<u8> to be serialized as: 4-byte LE length + bytes.
  const idBytes = Buffer.from(encryptionId, "hex");
  const idLengthBuffer = Buffer.alloc(4);
  idLengthBuffer.writeUInt32LE(idBytes.length, 0);
  const idArgPayload = Buffer.concat([idLengthBuffer, idBytes]);

  console.log(
    `encryptionId: ${encryptionId}`,
    `idArgPayload: ${idArgPayload.toString("hex")}`
  );

  // Instruction: seal_approve
  // The 'id' argument is encryptionId
  const instructionData = Buffer.concat([
    SEAL_APPROVE_DISCRIMINATOR,
    idArgPayload, // Pass the prepared id (encryptionId) argument
  ]);

  const ix = new TransactionInstruction({
    programId: WHITELIST_PROGRAM_ID,
    keys: [
      // Accounts for SealApprove instruction context
      { pubkey: sessionKeyPubkey, isSigner: false, isWritable: false }, // user account
      { pubkey: whitelistPda, isSigner: false, isWritable: false }, // whitelist PDA
      { pubkey: addressListPda, isSigner: false, isWritable: false }, // address list PDA
    ],
    data: instructionData,
  });

  return ix;
}

export async function createWhitelistSealTx(
  connection: Connection,
  sessionKeyPubkey: PublicKey,
  encryptionId: string // Hex string for the id: Vec<u8> argument
): Promise<Transaction> {

  const feePayer = DUMMY_FEEPAYER;
 
  const ix = await createWhitelistSealIx(
    connection,
    sessionKeyPubkey,
    encryptionId
  );

  const transaction = new Transaction();
  transaction.add(ix);

  // ... (rest of transaction setup: blockhash, feePayer, simulation) ...
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = feePayer.publicKey;

  // partial sign by feePayer
  transaction.partialSign(feePayer);

  console.log("Simulating transaction with seal_approve instructions...");
  const simulation = await connection.simulateTransaction(transaction, [
    feePayer, // FEEPAYER Keypair is needed for simulation if it's the feePayer
  ]);
  console.log(
    "Simulation result (seal_approve for PK1 & PK2):",
    simulation.value.logs,
    simulation.value.returnData
  );

  return transaction;
}

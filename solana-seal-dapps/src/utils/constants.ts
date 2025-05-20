import { PublicKey, Keypair } from "@solana/web3.js";
import { Buffer } from "buffer";
import bs58 from 'bs58';

export const SEAL_APPROVE_DISCRIMINATOR = Buffer.from([
  114, 84, 92, 48, 48, 9, 84, 182,
]); // global:seal_approve

export const SEAL_KEY_SERVER_OBJECT_ID_1 = process.env.NEXT_PUBLIC_SEAL_KEY_SERVER_OBJECT_ID_1 || "0xc99e3323d679ab4d26de2c984cda693698c453c9ae12baaf218c7ea3518428b0";
export const SEAL_KEY_SERVER_OBJECT_ID_2 = process.env.NEXT_PUBLIC_SEAL_KEY_SERVER_OBJECT_ID_2 || "0xa6a2f5713b84cfc0572b29d9b3edf4fa9d88915e821f6ac10c77fcf84d57181f";

export const SOLANA_RPC_URL = process.env.NEXT_PUBLIC_SOLANA_RPC_URL || "https://api.devnet.solana.com";

export const STARTER_PROGRAM_ID = new PublicKey(
  process.env.NEXT_PUBLIC_STARTER_PROGRAM_ID || "HMyQGJVyXw5MvpHbKQ8noKXcbtX9TyPkwM8TcyHSFdTJ"
);

export const WHITELIST_PROGRAM_ID = new PublicKey(
  process.env.NEXT_PUBLIC_WHITELIST_PROGRAM_ID || "5E7FfNPZjzbxLJCTz64oTsk1ZpKZKDsqAiG5H3igxe9x"
);

export const AUTHORITY_PUBLIC_KEY = new PublicKey(
  process.env.NEXT_PUBLIC_AUTHORITY_PUBLIC_KEY || "9LELvHvGz5XoTw5uAEMS2vSupX1BMQPJQacyTgN9SADj"
);

export const DUMMY_FEEPAYER = Keypair.fromSecretKey(
  bs58.decode(process.env.NEXT_PUBLIC_DUMMY_PRIVATE_KEY!)
);

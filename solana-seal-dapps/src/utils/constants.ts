import { PublicKey, Keypair } from "@solana/web3.js";
import { Buffer } from "buffer";

export const SEAL_APPROVE_DISCRIMINATOR = Buffer.from([
  114, 84, 92, 48, 48, 9, 84, 182,
]); // global:seal_approve

export const SOLANA_RPC_URL = "http://127.0.0.1:8899";

export const STARTER_PROGRAM_ID = new PublicKey(
  "HMyQGJVyXw5MvpHbKQ8noKXcbtX9TyPkwM8TcyHSFdTJ"
);

export const WHITELIST_PROGRAM_ID = new PublicKey(
  "5E7FfNPZjzbxLJCTz64oTsk1ZpKZKDsqAiG5H3igxe9x"
);

// A dummy feePayer (can be any keypair)
// just to sign for simulation, no need to keep it secret
// DUMMygJyQ7ebNvfvuvtQ235WLU7tcYkuRNd4vULTNHHR
export const FEEPAYER = Keypair.fromSecretKey(
  new Uint8Array([
    45, 77, 173, 63, 230, 87, 52, 139, 27, 221, 243, 109, 54, 11, 39, 73, 96,
    244, 182, 136, 65, 198, 126, 140, 188, 199, 32, 181, 15, 46, 94, 185, 185,
    77, 242, 174, 236, 30, 28, 3, 106, 132, 76, 236, 33, 125, 169, 149, 152,
    240, 192, 153, 35, 234, 244, 191, 165, 140, 87, 243, 155, 105, 222, 0,
  ])
);

// seALwNh86PfsT7mR8JTFzCJ3x8ct8oFeYjVthugoVsy
export const SEAL = Keypair.fromSecretKey(
  new Uint8Array([
    79, 0, 42, 43, 249, 153, 34, 130, 1, 72, 133, 161, 184, 56, 141, 225, 170,
    27, 16, 58, 236, 9, 49, 199, 155, 177, 8, 107, 192, 132, 165, 32, 12, 249,
    15, 3, 49, 217, 161, 176, 0, 189, 46, 200, 140, 103, 24, 165, 148, 244, 7,
    13, 130, 2, 21, 251, 59, 167, 55, 81, 158, 20, 198, 28,
  ])
);

// AuTHcg73n2Fk485zR5n7YPdXqjLFaTJSQm1o3e8nat2j
export const AUTHORITY = Keypair.fromSecretKey(
  new Uint8Array([
    89, 153, 142, 2, 64, 191, 210, 37, 149, 92, 165, 107, 160, 218, 192, 49, 46,
    87, 166, 102, 14, 169, 230, 113, 149, 118, 234, 229, 172, 181, 144, 94, 147,
    41, 27, 74, 233, 73, 131, 156, 85, 29, 111, 218, 120, 65, 104, 164, 242, 41,
    61, 214, 4, 161, 28, 91, 253, 93, 45, 56, 116, 209, 131, 40,
  ])
);

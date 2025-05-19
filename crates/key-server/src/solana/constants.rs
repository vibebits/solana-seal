/// Expected discriminator for `seal_approve` instruction
pub const SEAL_APPROVE_DISCRIMINATOR: &[u8; 8] = &[114, 84, 92, 48, 48, 9, 84, 182];

/// Solana RPC endpoint
pub const SOLANA_RPC_ENDPOINT: &str = "http://localhost:8899";

/// Maximum TTL for session keys in minutes
pub const SESSION_KEY_TTL_MAX: u16 = 30; 
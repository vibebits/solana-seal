import { NextResponse } from 'next/server';
import { Connection, Keypair } from '@solana/web3.js';
import { createWhitelist } from '@/utils/whitelist';
import bs58 from 'bs58';
import { SOLANA_RPC_URL } from '@/utils/constants';

// Decode the private key from bs58 and create keypair
const AUTHORITY = Keypair.fromSecretKey(bs58.decode(process.env.AUTHORITY_PRIVATE_KEY!));

// only done once, create the whitelist with AUTHORITY account
export async function GET() {
  try {
    const connection = new Connection(SOLANA_RPC_URL);
    const txHash = await createWhitelist(connection, AUTHORITY);
    
    return NextResponse.json({ 
      success: true,
      txHash 
    });
  } catch (error) {
    console.error('Error in create whitelist endpoint:', error);
    return NextResponse.json(
      { error: 'Failed to create whitelist' },
      { status: 500 }
    );
  }
} 
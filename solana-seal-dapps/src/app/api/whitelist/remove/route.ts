import { NextResponse } from 'next/server';
import { Connection, PublicKey, Keypair } from '@solana/web3.js';
import { removeFromWhitelist } from '@/utils/whitelist';
import bs58 from 'bs58';
import { SOLANA_RPC_URL } from '@/utils/constants';

// Decode the private key from bs58 and create keypair
const AUTHORITY = Keypair.fromSecretKey(bs58.decode(process.env.AUTHORITY_PRIVATE_KEY!));

export async function POST(request: Request) {
  try {
    const { address } = await request.json();
    
    if (!address) {
      return NextResponse.json(
        { error: 'Missing address parameter' },
        { status: 400 }
      );
    }

    const connection = new Connection(SOLANA_RPC_URL);
    const txHash = await removeFromWhitelist(
      connection,
      AUTHORITY,
      new PublicKey(address)
    );
    
    return NextResponse.json({ 
      success: true,
      txHash 
    });
  } catch (error) {
    console.error('Error in remove from whitelist endpoint:', error);
    return NextResponse.json(
      { error: 'Failed to remove from whitelist' },
      { status: 500 }
    );
  }
} 
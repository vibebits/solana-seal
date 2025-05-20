import { NextResponse } from 'next/server';
import { Connection, PublicKey } from '@solana/web3.js';
import { verifyWhitelist } from '@/utils/whitelist';
import { SOLANA_RPC_URL } from '@/utils/constants';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const authority = searchParams.get('authority');
    const address = searchParams.get('address');

    console.log('Params:', { authority, address });

    if (!authority || !address) {
      return NextResponse.json(
        { error: 'Missing required parameters' },
        { status: 400 }
      );
    }

    const connection = new Connection(SOLANA_RPC_URL);
    const isWhitelisted = await verifyWhitelist(
      connection,
      new PublicKey(authority),
      new PublicKey(address)
    );

    console.log(`/api/whitelist/verify - isWhitelisted: ${isWhitelisted}`);

    const response = NextResponse.json({ isWhitelisted });
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    response.headers.set('Pragma', 'no-cache');
    response.headers.set('Expires', '0');
    return response;
  } catch (error) {
    console.error('Error in verify endpoint:', error);
    return NextResponse.json(
      { error: 'Failed to verify whitelist' },
      { status: 500 }
    );
  }
} 
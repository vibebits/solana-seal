import { useMemo } from 'react';
import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { SealClient } from '@/solana-seal-sdk/client';
import { SEAL_KEY_SERVER_OBJECT_ID_1, SEAL_KEY_SERVER_OBJECT_ID_2 } from '@/utils/constants';

export const useSolanaSealClient = () => {
  const rpcUrl = process.env.NEXT_PUBLIC_SUI_RPC_URL || getFullnodeUrl('testnet');

  const solanaSealClient = useMemo(() => {
    const suiClient = new SuiClient({ url: rpcUrl });

    return new SealClient({
      suiClient,
      serverObjectIds: [  
        // solana-seal-key-server - devnet
        // "0xc99e3323d679ab4d26de2c984cda693698c453c9ae12baaf218c7ea3518428b0",
        // "0xa6a2f5713b84cfc0572b29d9b3edf4fa9d88915e821f6ac10c77fcf84d57181f"

        // solana-seal-key-server - localnet
        // "0x37ab2dd74ec066492efcab7d324abd902b258cca4f86ca3a17d51861e4eb2afc",
        // "0x37ab2dd74ec066492efcab7d324abd902b258cca4f86ca3a17d51861e4eb2afc",
        
        SEAL_KEY_SERVER_OBJECT_ID_1,
        SEAL_KEY_SERVER_OBJECT_ID_2,
      ],
      verifyKeyServers: false,
    });
  }, [rpcUrl]);

  return solanaSealClient;
}; 
'use client';

import { useState, useCallback, useEffect } from 'react';
import { useWallet } from '@solana/wallet-adapter-react';
import { SessionKey } from '@/solana-seal-sdk/session-key-solana';

// Custom Signer implementation for Solana wallet
class SolanaSigner {
  private publicKey: string;
  private signMessage: (message: Uint8Array) => Promise<Uint8Array>;

  constructor(publicKey: string, signMessage: (message: Uint8Array) => Promise<Uint8Array>) {
    this.publicKey = publicKey;
    this.signMessage = signMessage;
  }

  getPublicKey() {
    return {
      toSuiAddress: () => this.publicKey
    };
  }

  async signPersonalMessage(message: Uint8Array): Promise<{ signature: string }> {
    const signatureBytes = await this.signMessage(message);
    return {
      signature: Buffer.from(signatureBytes).toString('base64')
    };
  }
}

export const useSessionKey = (programId: string) => {
  const { publicKey, signMessage } = useWallet();
  const [sessionKey, setSessionKey] = useState<SessionKey | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Clear session key when wallet changes
  useEffect(() => {
    setSessionKey(null);
    setError(null);
  }, [publicKey]);

  useEffect(() => {
    console.log('sessionKey', sessionKey);
  }, [sessionKey]);

  // Generate a new session key
  const generateSessionKey = useCallback(async () => {
    if (!publicKey || !signMessage) {
      setError('Wallet not connected');
      return null;
    }

    setIsGenerating(true);
    setError(null);

    try {
      // Create a custom signer for our SessionKey implementation
      const signer = new SolanaSigner(
        publicKey.toString(),
        signMessage
      );

      // Create a new session key with the connected wallet
      // Use the Solana program ID as the package ID for encryption/decryption
      const newSessionKey = new SessionKey({
        address: publicKey.toString(),
        packageId: programId,
        ttlMin: 15, // 15 minutes TTL
        signer
      });

      // Get certificate to trigger message signing
      await newSessionKey.getCertificate();
      
      setSessionKey(newSessionKey);
      return newSessionKey;
    } catch (err) {
      console.error('Error generating session key:', err);
      setError(err instanceof Error ? err.message : 'Failed to generate session key');
      return null;
    } finally {
      setIsGenerating(false);
    }
  }, [publicKey, signMessage]);

  return {
    sessionKey,
    isGenerating,
    error,
    generateSessionKey
  };
};

export default useSessionKey; 
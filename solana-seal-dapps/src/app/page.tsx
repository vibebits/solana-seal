"use client";

import dynamic from "next/dynamic";
import { useState } from "react";

import { useWallet } from "@solana/wallet-adapter-react";

import useSessionKey from "@/hooks/useSessionKey";
import { useNetwork, NetworkOption } from "@/contexts/NetworkContext";
import { WHITELIST_PROGRAM_ID } from "@/utils/constants";
import { TextEncryptDecrypt } from "@/components/TextEncryptDecrypt";
import { ImageEncryptDecrypt } from "@/components/ImageEncryptDecrypt";
import { useSolanaSealClient } from "@/hooks/useSolanaSealClient";

// Import the WalletMultiButton component with SSR disabled to prevent hydration errors
const WalletMultiButton = dynamic(
  async () =>
    (await import("@solana/wallet-adapter-react-ui")).WalletMultiButton,
  { ssr: false }
);

export default function Home() {
  const { connected } = useWallet();
  const { network, setNetwork } = useNetwork();
  const [encryptionMode, setEncryptionMode] = useState<'text' | 'image'>('text');
  const {
    sessionKey,
    isGenerating,
    error: sessionKeyError,
    generateSessionKey,
  } = useSessionKey(WHITELIST_PROGRAM_ID.toString());

  const solanaSealClient = useSolanaSealClient();

  const handleNetworkChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setNetwork(e.target.value as NetworkOption);
  };

  return (
    <main className="flex min-h-screen flex-col items-center p-8">
      <div className="flex flex-col items-center justify-center w-full max-w-3xl gap-8">
        <h1 className="text-4xl font-bold text-center mt-8">
          Solana Seal Demo
        </h1>

        <div className="w-full">
          <div className="bg-white p-6 rounded-lg shadow-lg w-full">
            <div className="flex justify-between items-center mb-6">
              <WalletMultiButton />

              <div className="flex items-center space-x-2">
                <label
                  htmlFor="network"
                  className="text-sm font-medium text-gray-700"
                >
                  Network:
                </label>
                <select
                  id="network"
                  value={network}
                  onChange={handleNetworkChange}
                  className="rounded border text-black border-gray-300 px-3 py-1 text-sm"
                >
                  <option value="devnet">Devnet</option>
                  {/* <option value="testnet">Testnet</option>
                  <option value="mainnet-beta">Mainnet</option> */}
                </select>
              </div>
            </div>

            {connected ? (
              <div className="space-y-6">
                {/* Session Key Section */}
                <div className="border p-4 rounded-md">
                  <h2 className="text-lg font-medium text-gray-900 mb-2">
                    Session Key
                  </h2>

                  {sessionKey ? (
                    <div className="space-y-2">
                      <div className="bg-green-50 p-3 rounded-md text-green-800">
                        Session key generated successfully!
                      </div>

                      <div className="text-xs text-gray-800 font-mono">
                        <p>
                          <span className="font-medium">User:</span>{" "}
                          {sessionKey.getAddress()}
                        </p>
                        <p>
                          <span className="font-medium">Program ID:</span>{" "}
                          {sessionKey.getProgramId()}
                        </p>
                        <p>
                          <span className="font-medium">Expired?:</span>{" "}
                          {sessionKey.isExpired() ? "Expired" : "Still valid :)"}
                        </p>

                        <p className="mt-2 text-gray-600">
                          This session key allows you to request decryption keys
                          from the Seal key server without needing to sign each
                          request individually. It&apos;s valid for a limited
                          time and is tied to your wallet.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm text-gray-600 mb-3">
                        Generate a session key to request decryption keys. This
                        will require you to sign a message with your wallet.
                      </p>

                      <button
                        type="button"
                        onClick={generateSessionKey}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded w-full"
                        disabled={isGenerating}
                      >
                        {isGenerating
                          ? "Generating..."
                          : "Generate Session Key"}
                      </button>

                      {sessionKeyError && (
                        <div className="mt-2 p-2 bg-red-50 text-red-700 rounded text-sm">
                          {sessionKeyError}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Encryption Mode Toggle */}
                <div className="border p-4 rounded-md">
                  <h2 className="text-lg font-medium text-gray-900 mb-4">Encryption Mode</h2>
                  <div className="flex gap-4">
                    <button
                      onClick={() => setEncryptionMode('text')}
                      className={`flex-1 py-2 px-4 rounded-md ${
                        encryptionMode === 'text'
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      Text Encryption
                    </button>
                    <button
                      onClick={() => setEncryptionMode('image')}
                      className={`flex-1 py-2 px-4 rounded-md ${
                        encryptionMode === 'image'
                          ? 'bg-purple-600 text-white'
                          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                      }`}
                    >
                      Image Encryption
                    </button>
                  </div>
                </div>

                {/* Encryption Component */}
                {encryptionMode === 'text' ? (
                  <TextEncryptDecrypt sessionKey={sessionKey} solanaSealClient={solanaSealClient} />
                ) : (
                  <ImageEncryptDecrypt sessionKey={sessionKey} solanaSealClient={solanaSealClient} />
                )}
              </div>
            ) : (
              <div className="text-center text-gray-600">
                Connect your wallet to request keys from the Seal key server.
              </div>
            )}
          </div>
        </div>

        <div className="mt-8 text-center text-sm text-gray-500">
          <p>
            This demo app interacts with the Solana Seal key server.
            <br />
            It creates a transaction with a Seal program instruction and
            requests keys.
          </p>
          <p className="mt-2 font-semibold">
            Current network:{" "}
            <span
              className={
                network === "mainnet-beta" ? "text-red-500" : "text-green-500"
              }
            >
              {network === "mainnet-beta" ? "MAINNET" : network.toUpperCase()}
            </span>
          </p>
        </div>
    </div>
    </main>
  );
}

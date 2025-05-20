"use client";

import dynamic from "next/dynamic";
import { useState, useEffect } from "react";

import { useWallet } from "@solana/wallet-adapter-react";

import useSessionKey from "@/hooks/useSessionKey";
import { useNetwork, NetworkOption } from "@/contexts/NetworkContext";
import { SOLANA_RPC_URL, WHITELIST_PROGRAM_ID } from "@/utils/constants";
import { useSolanaSealClient } from "@/hooks/useSolanaSealClient";
import WhitelistManager from "@/components/WhitelistManager";

import { photoBlobs } from "@/utils/photoBlobs";
import { PublicKey } from "@solana/web3.js";
import { Connection } from "@solana/web3.js";
import { createWhitelistTx } from "@/utils/whitelist.seal";
import { SessionKey as SuiSessionKey } from "@/solana-seal-sdk";

// Import the WalletMultiButton component with SSR disabled to prevent hydration errors
const WalletMultiButton = dynamic(
  async () =>
    (await import("@solana/wallet-adapter-react-ui")).WalletMultiButton,
  { ssr: false }
);

export default function Home() {
  const { connected } = useWallet();
  const { network, setNetwork } = useNetwork();
  const [whitelistStatus, setWhitelistStatus] = useState<boolean | null>(null);
  const {
    sessionKey,
    isGenerating,
    error: sessionKeyError,
    generateSessionKey,
  } = useSessionKey(WHITELIST_PROGRAM_ID.toString());

  const solanaSealClient = useSolanaSealClient()

  const handleNetworkChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setNetwork(e.target.value as NetworkOption);
  };

  const [isDecrypting, setIsDecrypting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [decryptedImages, setDecryptedImages] = useState<string[]>([]);

  useEffect(() => {
    setDecryptedImages(Array(photoBlobs.length).fill(null));
  }, [whitelistStatus]);

  const getFullEncryptionId = (encryptionId: string) => {
    // this is the simplest one
    // return Buffer.from(encryptionId).toString('hex');

    // it is obtained from addressListPda
    const whitelistIdBase58String: string =
      "5w5SpuJhM7drtZNNBg9o7MoAJg8y85SMLPUTxTqMseMP"; // Example Base58 Pubkey string

    // 1. Convert whitelistIdString (Base58 Pubkey) to Buffer
    const whitelistIdPubkey = new PublicKey(whitelistIdBase58String);
    const whitelistIdBytes: Buffer = whitelistIdPubkey.toBuffer(); // This is your 32-byte prefix

    // 2. Convert encryptionId to Buffer (UTF-8 encoded)
    const encryptionIdBytes: Buffer = Buffer.from(encryptionId, "utf8");

    // 3. Concatenate the two Buffers
    const combinedIdBytes: Buffer = Buffer.concat([
      whitelistIdBytes,
      encryptionIdBytes,
    ]);

    // for whitelist we need to add whitelist id as prefix
    return combinedIdBytes.toString("hex");
  };

  const handleDecrypt = async (photoBlobsIndex: number) => {
    if (!sessionKey) {
      setLocalError("Please generate a session key first");
      return;
    }

    setIsDecrypting(true);
    setLocalError(null);

    const photoBlob = photoBlobs[photoBlobsIndex];
    if (!photoBlob) {
      setLocalError("Invalid photo blob");
      setIsDecrypting(false);
      return;
    }

    try {
      // Convert the base64 ciphertext to Uint8Array
      const ciphertextBytes = Buffer.from(photoBlob.ciphertext, "base64");

      // Create a Solana connection
      const connection = new Connection(SOLANA_RPC_URL, "confirmed");

      // Create the seal_approve transaction
      const fullEncryptionId = getFullEncryptionId(photoBlob.encryptionId);
      console.log("Encryption path - ID details:", {
        original: photoBlob.encryptionId,
        hexEncoded: fullEncryptionId,
        has0xPrefix: fullEncryptionId.startsWith("0x"),
      });

      const tx = await createWhitelistTx(
        connection,
        new PublicKey(sessionKey.getAddress()),
        fullEncryptionId
      );

      const serializedTx = tx.serialize();

      // prepend a dummy byte to the transaction
      const serializedTx1 = Buffer.concat([Buffer.from([0]), serializedTx]);

      // Call decrypt with the parameters
      const decryptResult = await solanaSealClient.decrypt({
        data: ciphertextBytes,
        sessionKey: sessionKey as unknown as SuiSessionKey,
        txBytes: serializedTx1,
      });

      if (decryptResult) {
        const text = new TextDecoder().decode(decryptResult);
        setDecryptedImages(prevImages => {
          const newImages = [...prevImages];
          newImages[photoBlobsIndex] = text;
          return newImages;
        });
      } else {
        setLocalError("Decryption failed");
      }
    } catch (err) {
      console.error("Error during decryption:", err);
      setLocalError(err instanceof Error ? err.message : "Decryption failed");
    } finally {
      setIsDecrypting(false);
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center p-8">
      <div className="flex flex-col items-center justify-center w-full max-w-3xl gap-8">
        <h1 className="text-4xl font-bold text-center mt-8">
          Solana Seal Whitelist Demo
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
                <WhitelistManager whitelistStatus={whitelistStatus} setWhitelistStatus={setWhitelistStatus} />

                {/* Decrypt Section */}
                {whitelistStatus && (
                  <div className="border p-4 rounded-md">
                    <h2 className="text-lg font-medium text-gray-900 mb-2">
                      Images for only whitelisted users
                    </h2>
                    <div className="mt-4 grid grid-cols-3 gap-4">
                      {photoBlobs.map((_, index) => (
                        <button
                          key={index}
                          onClick={() => handleDecrypt(index)}
                          disabled={isDecrypting || Boolean(decryptedImages[index])}
                          className={`px-4 py-2 rounded ${
                            isDecrypting || Boolean(decryptedImages[index])
                              ? "bg-gray-400 cursor-not-allowed"
                              : "bg-blue-600 hover:bg-blue-700 text-white"
                          }`}
                        >
                          {isDecrypting ? "Decrypting..." : `Decrypt Image ${index + 1}`}
                        </button>
                      ))}
                    </div>
                    {localError && (
                      <div className="mt-4 p-3 bg-red-50 text-red-700 rounded text-sm">
                        {localError}
                      </div>
                    )}
                    <div className="mt-4 grid grid-cols-3 gap-4">
                      {decryptedImages.map((image, index) => (
                        image && (
                          <div key={index} className="p-3 bg-green-50 rounded">
                            <img src={image} alt={`Decrypted Image ${index + 1}`} className="w-full h-auto" />
                          </div>
                        )
                      ))}
                    </div>
                  </div>
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

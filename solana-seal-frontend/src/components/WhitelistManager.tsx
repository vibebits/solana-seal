import { useState, useEffect } from "react";
import { useWallet } from "@solana/wallet-adapter-react";
import { Connection } from "@solana/web3.js";
import { AUTHORITY, SOLANA_RPC_URL } from "@/utils/constants";
import {
  addToWhitelist,
  removeFromWhitelist,
  verifyWhitelist,
} from "@/utils/whitelist";

interface WhitelistManagerProps {
  whitelistStatus: boolean | null;
  setWhitelistStatus: (status: boolean | null) => void;
}

export default function WhitelistManager({ whitelistStatus, setWhitelistStatus }: WhitelistManagerProps) {
  const { publicKey, connected } = useWallet();
  const [isAdding, setIsAdding] = useState(false);
  const [isRemoving, setIsRemoving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check whitelist status when wallet connects
  useEffect(() => {
    const checkWhitelistStatus = async () => {
      if (!publicKey || !connected) {
        setWhitelistStatus(null);
        return;
      }

      try {
        const connection = new Connection(SOLANA_RPC_URL, "confirmed");
        const isWhitelisted = await verifyWhitelist(
          connection,
          AUTHORITY.publicKey,
          publicKey
        );
        setWhitelistStatus(isWhitelisted);
      } catch (err) {
        console.error("Error checking whitelist status:", err);
        setError("Failed to check whitelist status");
      }
    };

    checkWhitelistStatus();
  }, [publicKey, connected]);

  const handleAddToWhitelist = async () => {
    if (!publicKey || !connected) {
      setError("Please connect your wallet first");
      return;
    }

    setIsAdding(true);
    setError(null);

    try {
      const connection = new Connection(SOLANA_RPC_URL, "confirmed");
      const txHash = await addToWhitelist(connection, AUTHORITY, publicKey);
      
      // Wait for transaction confirmation
      const confirmation = await connection.confirmTransaction(txHash, "confirmed");
      if (confirmation.value.err) {
        throw new Error("Transaction failed to confirm");
      }

      console.log("Added to whitelist. Transaction:", txHash);
      setWhitelistStatus(true);
    } catch (err) {
      console.error("Error adding to whitelist:", err);
      setError("Failed to add to whitelist");
    } finally {
      setIsAdding(false);
    }
  };

  const handleRemoveFromWhitelist = async () => {
    if (!publicKey || !connected) {
      setError("Please connect your wallet first");
      return;
    }

    setIsRemoving(true);
    setError(null);

    try {
      const connection = new Connection(SOLANA_RPC_URL, "confirmed");
      const txHash = await removeFromWhitelist(connection, AUTHORITY, publicKey);
      
      // Wait for transaction confirmation
      const confirmation = await connection.confirmTransaction(txHash, "confirmed");
      if (confirmation.value.err) {
        throw new Error("Transaction failed to confirm");
      }

      console.log("Removed from whitelist. Transaction:", txHash);
      setWhitelistStatus(false);
    } catch (err) {
      console.error("Error removing from whitelist:", err);
      setError("Failed to remove from whitelist");
    } finally {
      setIsRemoving(false);
    }
  };

  return (
    <div className="border p-4 rounded-md">
      <h2 className="text-lg font-medium text-gray-900 mb-4">
        Am I whitelisted?
      </h2>
      <div className="flex flex-col items-center justify-center mb-4">
        <p className="" style={{ fontSize: "3rem" }}>
          {whitelistStatus === null
            ? "Connect wallet to check status"
            : whitelistStatus
            ? "😎"
            : "😭"}
        </p>
      </div>

      <div className="flex gap-4">
        <button
          onClick={handleAddToWhitelist}
          disabled={!connected || isAdding || whitelistStatus === true}
          className={`flex-1 py-1 px-4 rounded-md ${
            !connected || isAdding || whitelistStatus === true
              ? "bg-gray-300 cursor-not-allowed"
              : "bg-purple-600 hover:bg-purple-700 text-white"
          }`}
        >
          {isAdding ? "Adding..." : "Add Me!"}
        </button>
        <button
          onClick={handleRemoveFromWhitelist}
          disabled={!connected || isRemoving || whitelistStatus === false}
          className={`flex-1 py-1 px-4 rounded-md ${
            !connected || isRemoving || whitelistStatus === false
              ? "bg-gray-300 cursor-not-allowed"
              : "bg-red-600 hover:bg-red-700 text-white"
          }`}
        >
          {isRemoving ? "Removing..." : "Remove Me!"}
        </button>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-50 text-red-700 rounded text-sm">
          {error}
        </div>
      )}
    </div>
  );
}

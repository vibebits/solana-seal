import { useState } from "react";
import { SessionKey } from "@/solana-seal-sdk/session-key-solana";
import { SessionKey as SuiSessionKey } from "@/solana-seal-sdk/session-key";
import { SealClient } from "@/solana-seal-sdk/client";
import { Connection, PublicKey } from "@solana/web3.js";
import { createWhitelistTx } from "@/utils/whitelist.seal";
import { EncryptedObject } from "@/solana-seal-sdk";
import { SOLANA_RPC_URL } from "@/utils/constants";

interface TextEncryptDecryptProps {
  sessionKey: SessionKey | null;
  solanaSealClient: SealClient;
}

export const TextEncryptDecrypt = ({
  sessionKey,
  solanaSealClient,
}: TextEncryptDecryptProps) => {
  const [encryptionId, setEncryptionId] = useState("text");
  const [plaintext, setPlaintext] = useState("hello world!");
  const [encryptedData, setEncryptedData] = useState<{
    ciphertext: string;
    key: string;
  } | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const getFullEncryptionId = () => {
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

  const handleEncrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sessionKey || !plaintext) return;

    setIsEncrypting(true);
    setLocalError(null);
    setEncryptedData(null);
    setDecryptedText(null);

    try {
      // Convert plaintext to Uint8Array
      const plaintextBytes = new TextEncoder().encode(plaintext);

      // Ensure the encryptionId is a valid hex string
      const fullEncryptionId = getFullEncryptionId();
      console.log("Encryption path - ID details:", {
        original: encryptionId,
        hexEncoded: fullEncryptionId,
        has0xPrefix: fullEncryptionId.startsWith("0x"),
        length: fullEncryptionId.length,
      });

      const encryptResult = await solanaSealClient.encrypt({
        threshold: 2,
        packageId: sessionKey.getPackageId(),
        id: fullEncryptionId,
        data: plaintextBytes,
      });

      // Store the encrypted data and key
      setEncryptedData({
        ciphertext: Buffer.from(encryptResult.encryptedObject).toString(
          "base64"
        ),
        key: Buffer.from(encryptResult.key).toString("base64"),
      });
    } catch (err) {
      console.error("Encryption error:", err);
      setLocalError(
        err instanceof Error ? err.message : "Failed to encrypt text"
      );
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleDecrypt = async () => {
    if (!sessionKey || !encryptedData) return;

    setIsDecrypting(true);
    setLocalError(null);
    setDecryptedText(null);

    try {
      // Convert the base64 ciphertext to Uint8Array
      const ciphertextBytes = Buffer.from(encryptedData.ciphertext, "base64");

      // Create a Solana connection
      const connection = new Connection(SOLANA_RPC_URL, "confirmed");

      // Create the seal_approve transaction
      const fullEncryptionId = getFullEncryptionId();
      console.log("Encryption path - ID details:", {
        original: encryptionId,
        hexEncoded: fullEncryptionId,
        has0xPrefix: fullEncryptionId.startsWith("0x"),
        length: fullEncryptionId.length,
      });
      const tx = await createWhitelistTx(
        connection,
        new PublicKey(sessionKey.getAddress()),
        fullEncryptionId
      );

      const serializedTx = tx.serialize();

      // prepend a dummy byte to the transaction
      const serializedTx1 = Buffer.concat([Buffer.from([0]), serializedTx]);

      console.log("serializedTx", serializedTx.length);
      console.log("serializedTx1", serializedTx1.length);

      console.log("Starting decryption process...");
      console.log("Ciphertext length:", ciphertextBytes.length);
      console.log("Session key:", sessionKey);
      console.log("Transaction length:", serializedTx.length);
      console.log(
        "Transaction (hex):",
        Buffer.from(serializedTx).toString("hex")
      );

      try {
        // Call decrypt with the parameters from the signature
        console.log("Calling solanaSealClient.decrypt...");
        console.log("Input data:", {
          ciphertextLength: ciphertextBytes.length,
          sessionKeyAddress: sessionKey?.getAddress(),
          txBytesLength: serializedTx.length,
          txBytesHex:
            Buffer.from(serializedTx).toString("hex").slice(0, 100) + "...",
        });

        // Parse the encrypted object to check its structure
        const encryptedObject = EncryptedObject.parse(ciphertextBytes);
        console.log("Encrypted object:", {
          id: encryptedObject.id,
          packageId: encryptedObject.packageId,
          threshold: encryptedObject.threshold,
          services: encryptedObject.services,
          encryptedShares: encryptedObject.encryptedShares,
          ciphertext: encryptedObject.ciphertext,
        });

        console.log("Session key:", {
          address: sessionKey?.getAddress(),
          packageId: sessionKey?.getPackageId(),
          isExpired: sessionKey?.isExpired(),
        });

        console.log("Transaction bytes:", {
          length: serializedTx.length,
          hex: Buffer.from(serializedTx).toString("hex").slice(0, 100) + "...",
        });

        const decryptResult = await solanaSealClient.decrypt({
          data: ciphertextBytes,
          sessionKey: sessionKey as unknown as SuiSessionKey,
          txBytes: serializedTx1, // just to be same as Sui, prepend a dummy byte
        });

        if (!decryptResult) {
          throw new Error("Decrypt result is undefined");
        }

        console.log("Decrypt call completed");
        console.log("Decrypt result length:", decryptResult.length);
        console.log(
          "Decrypt result (hex):",
          Buffer.from(decryptResult).toString("hex")
        );

        // Convert result to text
        const text = new TextDecoder().decode(decryptResult);
        console.log("Decoded text:", text);
        setDecryptedText(text);
      } catch (decryptErr) {
        console.error("Decrypt error details:", {
          error: decryptErr,
          errorType: typeof decryptErr,
          errorString: String(decryptErr),
          name: decryptErr instanceof Error ? decryptErr.name : "Unknown",
          message:
            decryptErr instanceof Error
              ? decryptErr.message
              : String(decryptErr),
          stack: decryptErr instanceof Error ? decryptErr.stack : undefined,
        });
        throw decryptErr; // Re-throw to be caught by outer catch
      }
    } catch (err: unknown) {
      console.error("Error decrypting data:", err);
      if (err instanceof Error) {
        console.error("Error details:", {
          name: err.name,
          message: err.message,
          stack: err.stack,
        });
        setLocalError(err.message);
      } else {
        setLocalError("Failed to decrypt data");
      }
    } finally {
      setIsDecrypting(false);
    }
  };

  return (
    <div className="border p-4 rounded-md">
      <h2 className="text-lg font-medium text-gray-900 mb-2">Encrypt Text</h2>

      <form onSubmit={handleEncrypt} className="space-y-4">
        <div>
          <label
            htmlFor="encryptionId"
            className="block text-sm font-medium text-gray-700"
          >
            Encryption ID
          </label>
          <input
            type="text"
            id="encryptionId"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border text-gray-800"
            placeholder="Enter a hex ID for encryption"
            value={encryptionId}
            onChange={(e) => setEncryptionId(e.target.value)}
            required
          />
          <p className="text-xs text-gray-500 mt-1">
            This should be a valid hexadecimal string (0-9, a-f)
          </p>
        </div>

        <div>
          <label
            htmlFor="plaintext"
            className="block text-sm font-medium text-gray-700"
          >
            Text to Encrypt
          </label>
          <textarea
            id="plaintext"
            rows={4}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border text-gray-800"
            placeholder="Enter text to encrypt"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            required
          />
        </div>

        <button
          type="submit"
          className="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded w-full"
          disabled={isEncrypting || !sessionKey || !plaintext}
        >
          {isEncrypting ? "Encrypting..." : "Encrypt Text"}
        </button>

        {!sessionKey && (
          <p className="text-sm text-amber-600">
            Please generate a session key first
          </p>
        )}
      </form>

      {encryptedData && (
        <div className="mt-4 p-3 bg-gray-100 rounded">
          <h3 className="text-md font-medium text-gray-800 mb-2">
            Encrypted Result
          </h3>
          <div className="space-y-2">
            <div>
              <span className="text-xs text-gray-500">Ciphertext:</span>
              <p className="text-xs text-gray-800 font-mono break-all bg-gray-50 p-2 rounded mt-1 max-h-20 overflow-auto">
                {encryptedData.ciphertext}
              </p>
            </div>
            <div>
              <span className="text-xs text-gray-500">Encryption Key:</span>
              <p className="text-xs text-gray-800 font-mono break-all bg-gray-50 p-2 rounded mt-1">
                {encryptedData.key}
              </p>
            </div>
          </div>
        </div>
      )}

      {encryptedData && (
        <div className="mt-4">
          <button
            type="button"
            onClick={handleDecrypt}
            className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full"
            disabled={isDecrypting}
          >
            {isDecrypting ? "Decrypting..." : "Decrypt Text"}
          </button>

          {decryptedText && (
            <div className="mt-4 p-3 bg-green-50 rounded">
              <h3 className="text-md font-medium mb-2 text-gray-800">
                Decrypted Result
              </h3>
              <p className="bg-white p-2 rounded border border-green-200 text-gray-800">
                {decryptedText}
              </p>
            </div>
          )}
        </div>
      )}
      {localError && (
        <div className="mt-2 p-2 bg-red-50 text-red-700 rounded text-sm">
          {localError}
        </div>
      )}
    </div>
  );
};

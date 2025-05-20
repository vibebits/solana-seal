import { useState } from "react";
import { SessionKey } from "@/solana-seal-sdk/session-key-solana";
import { SessionKey as SuiSessionKey } from "@/solana-seal-sdk/session-key";
import { SealClient } from "@/solana-seal-sdk/client";
import { Connection, PublicKey } from "@solana/web3.js";
import { createStarterSealTx } from "@/utils/starter.seal";
import { getFullEncryptionId } from "@/utils/starter";
import { EncryptedObject } from "@/solana-seal-sdk";
import { SOLANA_RPC_URL } from "@/utils/constants";

interface ImageEncryptDecryptProps {
  sessionKey: SessionKey | null;
  solanaSealClient: SealClient;
}

export const ImageEncryptDecrypt = ({
  sessionKey,
  solanaSealClient,
}: ImageEncryptDecryptProps) => {
  const [encryptionId, setEncryptionId] = useState("123-image");
  const [plaintext, setPlaintext] = useState("data:image/webp;base64,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");
  const [encryptedData, setEncryptedData] = useState<{
    ciphertext: string;
    key: string;
  } | null>(null);
  const [decryptedText, setDecryptedText] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

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
      const fullEncryptionId = await getFullEncryptionId(encryptionId);
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
      const fullEncryptionId = await getFullEncryptionId(encryptionId);
      console.log("Encryption path - ID details:", {
        original: encryptionId,
        hexEncoded: fullEncryptionId,
        has0xPrefix: fullEncryptionId.startsWith("0x"),
        length: fullEncryptionId.length,
      });
      const tx = await createStarterSealTx(
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
        setLocalError("Failed to decrypt data. To decrypt successfully, the encryption ID should start with '123'.");
      }
    } finally {
      setIsDecrypting(false);
    }
  };

  return (
    <div className="border p-4 rounded-md">
      <h2 className="text-lg font-medium text-gray-900 mb-2">Encrypt Image</h2>

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
            This is a string. If it starts with <em>123</em>, you can get decryption key from the server.
          </p>
        </div>

        <div>
          <label
            htmlFor="plaintext"
            className="block text-sm font-medium text-gray-700"
          >
            Image to Encrypt
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
          {isEncrypting ? "Encrypting..." : "Encrypt Image"}
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
            {isDecrypting ? "Decrypting..." : "Decrypt Image"}
          </button>

          {decryptedText && (
            <div className="mt-4 p-3 bg-green-50 rounded">
              <h3 className="text-md font-medium mb-2 text-gray-800">
                Decrypted Result
              </h3>
              <p className="bg-white p-2 rounded border border-green-200 text-gray-800">
                <img src={decryptedText} alt="Decrypted Image" className="w-1/2 h-auto" style={{ margin: '0 auto' }} />
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

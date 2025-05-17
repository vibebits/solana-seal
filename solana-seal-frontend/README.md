# Solana Seal Key Server Frontend

This is a Next.js frontend application that demonstrates how to interact with the Solana Seal Key Server. It allows users to connect their Solana wallet, create a transaction with a Seal program instruction, and request decryption keys from the key server.

## Features

- Solana wallet integration with Phantom, Solflare, and other wallets
- Transaction creation with Seal program instructions
- Key request and retrieval from the Seal key server
- Responsive UI for desktop and mobile

## Prerequisites

- Node.js 18+ and npm/pnpm
- A Solana wallet (like Phantom or Solflare)
- Access to a running Seal key server

## Getting Started

1. Clone the repository

2. Install dependencies
   ```bash
   pnpm install
   ```

3. Set up environment variables
   Create a `.env.local` file with the following variables:
   ```
   NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
   ```
   Adjust the URL to point to your Seal key server.

4. Run the development server
```bash
pnpm dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser to see the application

## How It Works

1. **Connect Wallet**: Click the "Connect Wallet" button to connect your Solana wallet.

2. **Enter Key ID**: Enter a key ID that will be used in the Seal program instruction.

3. **Request Key**: Click the "Request Key" button to:
   - Create a transaction with a `seal_approve` instruction
   - Sign the transaction with your wallet
   - Generate a certificate with your wallet's public key
   - Sign the certificate with your wallet
   - Send the request to the key server
   - Receive encrypted decryption keys

4. **View Results**: The response from the key server will be displayed, showing the encrypted decryption keys.

## Integration Details

The app demonstrates a complete flow for interacting with the Seal key server:

1. **Frontend Form**: Collects user input for the key ID
2. **Wallet Signing**: Uses Solana wallet adapters for transaction and message signing
3. **API Request**: Formats and sends the request to the key server
4. **Response Display**: Processes and displays the encrypted keys

## Customization

You can modify the application to suit your specific needs:

- Update the `PROGRAM_ID` in `src/hooks/useSealProgram.ts` to match your Solana program
- Modify the key ID generation logic in the form
- Implement actual ElGamal encryption/decryption (current implementation uses placeholders)

## Next Steps

For production use, you would need to:

1. Implement proper ElGamal key generation and encryption
2. Add error handling for network issues and validation failures
3. Enhance the UI to display more information about the keys
4. Implement decryption of the received keys

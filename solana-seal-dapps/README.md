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
   Copy `example.env` into `.env` enter the env variables.

4. Run the development server
```bash
pnpm dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser to see the application

## How It Works

1. **Connect Wallet**: Click the "Connect Wallet" button to connect your Solana wallet.

2. **Create a session key**: Session key authorizes Seal key server to call `seal_approve` function a Solana Program for a period of time. So you won't need to sign for each request for a decryption key.

2. **Enter Key ID**: Enter an encryption id that will be used in the Seal program instruction. (for starter example, id that starts with '123' will pass `seal_approve` check, so decryption will be successful)

3. **Request Key**: Click the "Request Key" button to:
   - Create a transaction with one or more `seal_approve` instructions
   - No need to sign as session key is used and the transaction is only simulated.
   - Send the request to the key servers
   - Servers check `seal_approve` of the Solana program
   - If the function return `true`, servers return decryption keys

4. **View Results**: If threshold of keys are received, then decryption can be made successfully.

## Integration Details

The app demonstrates a complete flow for interacting with the Seal key server:

1. **Encryption**: Encrypt client-side with encryption id
2. **Wallet Signing**: Uses Solana wallet adapters for transaction and message signing
3. **API Request**: Formats and sends the request to the key server
4. **Decryption**: Fetch keys and decrypt

## Customization

You can modify the application to suit your specific needs:

- Update the `.env` for `STARTER_PROGRAM_ID` or `WHITELIST_PROGRAM_ID` with your own Solana Program ID to try out with your own `seal_approve` logic
- Read more about **identity based encryption** (https://github.com/MystenLabs/seal/blob/main/Design.md) to develop your own access policy patterns


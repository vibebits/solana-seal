# solana-seal
Unleash the power of Walrus.xyz and Seal on Solana. Now the decentralized storage is programmable natively with Solana programs.

## Overview
Solana Seal is an ingenious project that bridges the gap between Solana and Walrus' decentralized storage solution. It enables Solana programs and wallets to interact seamlessly with Walrus.xyz (decentralized storage) and Seal (decentralized secrets management), making decentralized storage programmable within the Solana ecosystem.

## Features
- Native integration with Solana programs
- Support for Solana signature, transaction, and simulation in key server
- TypeScript SDK for easy integration
- Decentralized storage capabilities through Walrus.xyz and Seal
- Secure key management through dedicated key servers (leveraging Shamir's secret sharing scheme)
- Pre-built patterns and templates for common use cases
- Demo applications showcasing various implementations

## Architecture
The project consists of several key components:

### Key Server
Located in `/crates/key-server/src/solana`, the key server component manages secure key storage and retrieval operations. It provides a secure interface for Solana programs to interact with decentralized storage networks.

### TypeScript SDK
The `/solana-seal-ts-sdk/solana` SDK provides a developer-friendly interface for integrating Solana Seal functionality into your frontend applications. It includes:
- Helper for session key management in Solana way
- Helper functions and hooks
- Integration utilities
- Example implementations

### Solana Programs
The `/solana-seals-programs/programs` directory contains pre-built Solana programs that implement common patterns for access control for decentralized storage. These programs serve as templates and can be customized for specific use cases.

### Demo Applications
The `/solana-seals-dapps` directory contains example applications demonstrating the capabilities of Solana Seal:
- **Starter Dapp**: A basic implementation showcasing the complete encryption and decryption flow for developers to get started easily
- **Whitelist Dapp**: An advanced example with access control features based on whitelists

## Deployed Infrastructure

### Key Servers
- Server #1
  - URL: https://solana-seal-key-server-1.up.railway.app
  - Sui Object: https://suiscan.xyz/testnet/object/0xc99e3323d679ab4d26de2c984cda693698c453c9ae12baaf218c7ea3518428b0/tx-blocks
- Server #2
  - URL: https://solana-seal-key-server-2.up.railway.app
  - Sui Object: https://suiscan.xyz/testnet/object/0xa6a2f5713b84cfc0572b29d9b3edf4fa9d88915e821f6ac10c77fcf84d57181f/tx-blocks

### Deployed Programs
- Starter Program: A basic implementation for getting started
 - https://explorer.solana.com/address/HMyQGJVyXw5MvpHbKQ8noKXcbtX9TyPkwM8TcyHSFdTJ?cluster=devnet
- Whitelist Program: Advanced implementation with access control features
 - https://explorer.solana.com/address/5E7FfNPZjzbxLJCTz64oTsk1ZpKZKDsqAiG5H3igxe9x?cluster=devnet

 ## seal_approve for Solana programs

 `seal_approve` is used as access policy control programmable in Solana program. It is checked by the key servers to determine access.

 It can be tweaked to define any logic.

 ```rust
// seal_approve can takes other params after `ctx` and `id`
pub fn seal_approve(ctx: Context<SealApprove>, id: Vec<u8>) -> Result<String> {

    // any logic

    // it must return ok or not_ok
    if success {
        Ok("ok".to_string())
    } else {
        Ok("not_ok".to_string())
    }
}

// SealApprove context's first account must be user's account
// user's account is checked against user from sessionKey/certificate by the key servers
#[derive(Accounts)]
pub struct SealApprove<'info> {
  pub user: AccountInfo<'info>,
  // other accounts or PDAs
}
 ```

## Getting Started

### Prerequisites
- Node.js (v16 or higher)
- Solana CLI tools
- Rust toolchain
- TypeScript

### Installation
1. Clone the repository:
```bash
git clone https://github.com/vibebits/solana-seal.git
cd solana-seal
```

2. Install dependencies:
```bash
pnpm install
```

3. Set .env variables and set them:
```bash
cp example.env .env
```

4. Run the dev locally:
```bash
pnpm run dev
```

5. Check out the demos:
- http://localhost:3000/starter
- http://localhost:3000/whitelist

### Usage of hooks
1. useSolanaSealClient hook:
```typescript
import { useSolanaSealClient } from "@/hooks/useSolanaSealClient";

const solanaSealClient = useSolanaSealClient();
```

2. useSolanaSessionKey hook:
```typescript
import useSolanaSessionKey from "@/hooks/useSolanaSessionKey";

const {
  sessionKey,
  isGenerating,
  error: sessionKeyError,
  generateSessionKey,
} = useSolanaSessionKey('YOUR-SOLANA-PROGRAM-ID');
```

## Contributing
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support
For support, please open an issue in the GitHub repository or contact the maintainers.

## Roadmap
- [ ] Additional program patterns
- [ ] Enhanced security features
- [ ] More demo applications
- [ ] Cross-chain integration capabilities
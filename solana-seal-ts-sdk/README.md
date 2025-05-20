# Solana Seal Typescript SDK

refer to the `solana-seal-ts-sdk/solana` folder.

## useSolanaSealClient hook

```typescript
import { useSolanaSealClient } from "@/hooks/useSolanaSealClient";

const solanaSealClient = useSolanaSealClient();
```

## useSolanaSessionKey hook

```typescript
import useSolanaSessionKey from "@/hooks/useSolanaSessionKey";

const {
  sessionKey,
  isGenerating,
  error: sessionKeyError,
  generateSessionKey,
} = useSolanaSessionKey('YOUR-SOLANA-PROGRAM-ID');
```

It can be used alongside with `@mysten/seal` sdk.
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import NetworkProvider from "@/contexts/NetworkContext";
import WalletClientWrapper from "@/components/WalletClientWrapper";
// import { SuiClientProvider, createNetworkConfig } from "@mysten/dapp-kit";
// import { getFullnodeUrl } from "@mysten/sui/client";

// export const TESTNET_PACKAGE_ID = '0x4cb081457b1e098d566a277f605ba48410e26e66eaab5b3be4f6c560e9501800';
// const { networkConfig } = createNetworkConfig({
//   testnet: {
//     url: getFullnodeUrl('testnet'),
//     variables: {
//       packageId: TESTNET_PACKAGE_ID,
//       gqlClient: 'https://sui-testnet.mystenlabs.com/graphql',
//     },
//   },
// });

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Solana Seal Key Server Demo",
  description: "A demo application for Solana Seal key server integration",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <NetworkProvider>
          <WalletClientWrapper>
            {/* <SuiClientProvider
              networks={networkConfig} defaultNetwork="testnet"
            > */}
              {children}
            {/* </SuiClientProvider> */}
          </WalletClientWrapper>
        </NetworkProvider>
      </body>
    </html>
  );
}

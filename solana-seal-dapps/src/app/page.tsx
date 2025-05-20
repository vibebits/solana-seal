"use client";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center p-8">
      <div className="flex flex-col items-center justify-center w-full max-w-3xl gap-8">
        <h1 className="text-4xl font-bold text-center mt-8">
          Solana Seal Demo
        </h1>

        <div className="w-full">
          <div className="bg-white p-6 rounded-lg shadow-lg w-full">
            <img src="https://i.imgpost.net/2025/05/20/u6cn.webp" alt="main" width="80%" className="mx-auto text-center" />
            <div className="flex flex-col items-center gap-4 mt-6 mb-6">
              <h2 className="text-2xl font-bold text-center text-gray-800">
                Unleashing the power of Walrus.xyz and Seal on Solana.
              </h2>
              <h3 className="text-medium text-center text-gray-500">
                Now the decentralized storage is programmable natively with Solana programs.
              </h3>
              <div className="flex gap-4 mt-4">
                <a href="/starter" className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
                  Starter Demo
                </a>
                <a href="/whitelist" className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">
                  Whitelist Demo
                </a>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-8 text-center text-sm text-gray-500">
          <p>
            This demo app interacts with the Solana Seal key server - secrets
            managed in decentralized and trustless way using Shamir&apos;s
            Secret Sharing algorithm.
            <br />
            Client side encrypted assets are stored safely on Walrus.xyz.
            <br />
            They can be decrypted only if `seal_approve` check in Solana program
            passed and threshold is met.
          </p>
        </div>
    </div>
    </main>
  );
}

// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crypto::elgamal;
use crypto::ibe;

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;
type IbeDerivedKey = ibe::UserSecretKey;
type IbePublicKey = ibe::PublicKey;

/// ElGamal related types.
pub type ElGamalPublicKey = elgamal::PublicKey<IbeDerivedKey>;
pub type ElgamalEncryption = elgamal::Encryption<IbeDerivedKey>;
pub type ElgamalVerificationKey = elgamal::VerificationKey<IbePublicKey>;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

#[derive(Clone, Debug, PartialEq)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
    Custom {
        node_url: String,
        graphql_url: String,
    },
    #[cfg(test)]
    TestCluster,
}

impl Network {
    pub fn node_url(&self) -> String {
        match self {
            Network::Devnet => "https://fullnode.devnet.sui.io:443".into(),
            Network::Testnet => "https://fullnode.testnet.sui.io:443".into(),
            Network::Mainnet => "https://fullnode.mainnet.sui.io:443".into(),
            Network::Custom { node_url, .. } => node_url.clone(),
            #[cfg(test)]
            Network::TestCluster => panic!(), // Currently not used, but can be found from cluster.rpc_url() if needed
        }
    }

    pub fn graphql_url(&self) -> String {
        match self {
            Network::Devnet => "https://sui-devnet.mystenlabs.com/graphql".into(),
            Network::Testnet => "https://sui-testnet.mystenlabs.com/graphql".into(),
            Network::Mainnet => "https://sui-mainnet.mystenlabs.com/graphql".into(),
            Network::Custom { graphql_url, .. } => graphql_url.clone(),
            #[cfg(test)]
            Network::TestCluster => panic!("GraphQL is not available on test cluster"),
        }
    }

    pub fn from_str(str: &str) -> Self {
        match str.to_ascii_lowercase().as_str() {
            "devnet" => Network::Devnet,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Mainnet,
            "custom" => Network::Custom {
                node_url: std::env::var("NODE_URL").expect("NODE_URL must be set"),
                graphql_url: std::env::var("GRAPHQL_URL").expect("GRAPHQL_URL must be set"),
            },
            _ => panic!("Unknown network: {}", str),
        }
    }
}

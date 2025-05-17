'use client';

import { createContext, useState, useContext, ReactNode, useEffect } from 'react';
import { clusterApiUrl } from '@solana/web3.js';

// Define network options
export type NetworkOption = 'mainnet-beta' | 'testnet' | 'devnet';

// Create context interface
interface NetworkContextType {
  network: NetworkOption;
  setNetwork: (network: NetworkOption) => void;
  endpoint: string;
  isMainnet: boolean;
}

// Default values
const defaultNetwork: NetworkOption = 'devnet';
const defaultEndpoint = clusterApiUrl('devnet');

// Create the context
const NetworkContext = createContext<NetworkContextType>({
  network: defaultNetwork,
  setNetwork: () => {},
  endpoint: defaultEndpoint,
  isMainnet: false,
});

// Network provider props
interface NetworkProviderProps {
  children: ReactNode;
}

// Hook to use the network context
export const useNetwork = () => useContext(NetworkContext);

// Provider component
export const NetworkProvider = ({ children }: NetworkProviderProps) => {
  // Start with default values to avoid hydration mismatches
  const [network, setNetwork] = useState<NetworkOption>(defaultNetwork);
  const [endpoint, setEndpoint] = useState<string>(defaultEndpoint);
  
  // Load from localStorage only after component is mounted to avoid hydration issues
  useEffect(() => {
    const savedNetwork = localStorage.getItem('solanaNetwork') as NetworkOption;
    if (savedNetwork && ['mainnet-beta', 'testnet', 'devnet'].includes(savedNetwork)) {
      setNetwork(savedNetwork);
      setEndpoint(clusterApiUrl(savedNetwork));
    }
  }, []);
  
  // Update endpoint when network changes and save to localStorage
  const updateNetwork = (newNetwork: NetworkOption) => {
    setNetwork(newNetwork);
    setEndpoint(clusterApiUrl(newNetwork));
    
    // Save to localStorage (this is safe now since we're in the browser)
    localStorage.setItem('solanaNetwork', newNetwork);
  };
  
  // Compute isMainnet
  const isMainnet = network === 'mainnet-beta';
  
  // Context value
  const value = {
    network,
    setNetwork: updateNetwork,
    endpoint,
    isMainnet,
  };
  
  return (
    <NetworkContext.Provider value={value}>
      {children}
    </NetworkContext.Provider>
  );
};

export default NetworkProvider; 
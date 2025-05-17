'use client';

import React from 'react';
import WalletContextProvider from '@/contexts/WalletContextProvider';

export default function WalletClientWrapper({ 
  children 
}: { 
  children: React.ReactNode 
}) {
  return (
    <WalletContextProvider>
      {children}
    </WalletContextProvider>
  );
} 
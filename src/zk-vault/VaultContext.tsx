// src/zk-vault/VaultContext.tsx

import React, { createContext, useContext, useState, useCallback } from 'react';
import { IVaultStorageAdapter } from './types';
import { 
  generateDEK, deriveKeyFromPin, wrapKey, unwrapKey, 
  authenticatePasskey, registerPasskey 
} from './crypto';

interface VaultContextType {
  isUnlocked: boolean;
  sessionKey: CryptoKey | null;
  setupVault: (pin: string, userId: string, email: string) => Promise<boolean>;
  unlockWithPin: (pin: string, userId: string) => Promise<boolean>;
  unlockWithPasskey: (userId: string) => Promise<boolean>;
  resetPin: (newPin: string, userId: string) => Promise<boolean>;
  resetPasskey: (userId: string, email: string) => Promise<boolean>;
  lock: () => void;
}

export const VaultContext = createContext<VaultContextType | undefined>(undefined);

interface VaultProviderProps {
  storageAdapter: IVaultStorageAdapter;
  children: React.ReactNode;
}

export function VaultProvider({ storageAdapter, children }: VaultProviderProps) {
  const [sessionKey, setSessionKey] = useState<CryptoKey | null>(null);

  const setupVault = async (pin: string, userId: string, email: string) => {
    try {
      const dek = await generateDEK();
      
      const salt = crypto.getRandomValues(new Uint8Array(32)); 
      const pinWrappingKey = await deriveKeyFromPin(pin, salt.buffer);
      const pinEnvelope = await wrapKey(dek, pinWrappingKey);
      const base64Salt = btoa(String.fromCharCode(...salt));

      let passkeyId = null;
      let passkeyEnvelope = null;
      try {
        const { id, key: passkeyWrappingKey } = await registerPasskey(userId, email);
        passkeyId = id;
        passkeyEnvelope = await wrapKey(dek, passkeyWrappingKey);
      } catch (err) {
        console.warn('Passkey skipped during setup');
      }

      await storageAdapter.saveEnvelopes(userId, {
        pinEnvelope: JSON.stringify(pinEnvelope),
        pinSalt: base64Salt,
        passkeyEnvelope: passkeyEnvelope ? JSON.stringify(passkeyEnvelope) : null,
        passkeyId
      });

      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('Setup failed:', err);
      return false;
    }
  };

  const unlockWithPin = async (pin: string, userId: string) => {
    try {
      const data = await storageAdapter.loadEnvelopes(userId);
      if (!data.pinEnvelope || !data.pinSalt) return false;

      const saltString = atob(data.pinSalt);
      const salt = new Uint8Array(saltString.length);
      for (let i = 0; i < saltString.length; i++) salt[i] = saltString.charCodeAt(i);

      const kek = await deriveKeyFromPin(pin, salt);
      const envelope = JSON.parse(data.pinEnvelope);
      const dek = await unwrapKey(envelope, kek);
      
      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('PIN Unlock failed:', err);
      return false;
    }
  };

  const unlockWithPasskey = async (userId: string) => {
    try {
      const data = await storageAdapter.loadEnvelopes(userId);
      if (!data.passkeyEnvelope) return false;

      const passkeyWrappingKey = await authenticatePasskey(userId);
      const envelope = JSON.parse(data.passkeyEnvelope);
      const dek = await unwrapKey(envelope, passkeyWrappingKey);
      
      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('Passkey Unlock failed:', err);
      return false;
    }
  };

  const resetPin = async (newPin: string, userId: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked to reset PIN.");

      // 1. Generate new salt and derive new KEK
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const base64Salt = btoa(String.fromCharCode(...salt));
      const newPinWrappingKey = await deriveKeyFromPin(newPin, salt.buffer);
      
      // 2. Wrap the active session key (DEK) with the new PIN KEK
      const newPinEnvelope = await wrapKey(sessionKey, newPinWrappingKey);

      // 3. Save via adapter (only overwriting PIN fields)
      await storageAdapter.saveEnvelopes(userId, {
        pinEnvelope: JSON.stringify(newPinEnvelope),
        pinSalt: base64Salt
      });

      return true;
    } catch (err) {
      console.error('Failed to reset PIN:', err);
      return false;
    }
  };

  const resetPasskey = async (userId: string, email: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked to reset Passkey.");

      // 1. Register new Passkey
      const { id: passkeyId, key: newPasskeyWrappingKey } = await registerPasskey(userId, email);
      
      // 2. Wrap the active session key (DEK) with the new Passkey KEK
      const newPasskeyEnvelope = await wrapKey(sessionKey, newPasskeyWrappingKey);

      // 3. Save via adapter (only overwriting Passkey fields)
      await storageAdapter.saveEnvelopes(userId, {
        passkeyEnvelope: JSON.stringify(newPasskeyEnvelope),
        passkeyId
      });

      return true;
    } catch (err) {
      console.error('Failed to reset Passkey:', err);
      return false;
    }
  };

  const lock = useCallback(() => setSessionKey(null), []);

  return (
    <VaultContext.Provider value={{
      isUnlocked: !!sessionKey,
      sessionKey,
      setupVault,
      unlockWithPin,
      unlockWithPasskey,
      resetPin,
      resetPasskey,
      lock
    }}>
      {children}
    </VaultContext.Provider>
  );
}

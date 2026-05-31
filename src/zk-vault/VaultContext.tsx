// src/zk-vault/VaultContext.tsx

import React, { createContext, useState, useCallback } from 'react';
import { IVaultStorageAdapter } from './types';
import { 
  generateDEK, deriveKeyFromPin, wrapKey, unwrapKey, 
  authenticatePasskey, registerPasskey, 
  encryptData, decryptData, EncryptedPayload,
  bufToHex, hexToBuf
} from './crypto';

interface VaultContextType {
  isUnlocked: boolean;
  setupVault: (pin: string, userId: string, email: string) => Promise<boolean>;
  unlockWithPin: (pin: string, userId: string) => Promise<boolean>;
  unlockWithPasskey: (userId: string) => Promise<boolean>;
  resetPin: (newPin: string, userId: string) => Promise<boolean>;
  resetPasskey: (userId: string, email: string) => Promise<boolean>;
  encryptPayload: (data: any) => Promise<EncryptedPayload>;
  decryptPayload: (payload: EncryptedPayload) => Promise<any>;
  lock: () => void;
}

export const VaultContext = createContext<VaultContextType | undefined>(undefined);

interface VaultProviderProps {
  storageAdapter: IVaultStorageAdapter;
  children: React.ReactNode;
}

export function VaultProvider({ storageAdapter, children }: VaultProviderProps) {
  // HIDDEN: The session key never leaves this file, protecting it from generic XSS reading the Context.
  const [sessionKey, setSessionKey] = useState<CryptoKey | null>(null);

  const setupVault = useCallback(async (pin: string, userId: string, email: string) => {
    try {
      const dek = await generateDEK();
      
      const salt = crypto.getRandomValues(new Uint8Array(32)); 
      const hexSalt = bufToHex(salt.buffer); // Safer than Base64
      const pinWrappingKey = await deriveKeyFromPin(pin, salt.buffer);
      const pinEnvelope = await wrapKey(dek, pinWrappingKey);

      let passkeyId = null;
      let passkeyEnvelope = null;
      try {
        const { id, key: passkeyWrappingKey } = await registerPasskey(userId, email);
        passkeyId = id;
        passkeyEnvelope = await wrapKey(dek, passkeyWrappingKey);
      } catch (err) {
        console.warn('Passkey skipped or unsupported during setup', err);
      }

      await storageAdapter.saveEnvelopes(userId, {
        pinEnvelope: JSON.stringify(pinEnvelope),
        pinSalt: hexSalt,
        passkeyEnvelope: passkeyEnvelope ? JSON.stringify(passkeyEnvelope) : null,
        passkeyId
      });

      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('Setup failed:', err);
      return false;
    }
  }, [storageAdapter]);

  const unlockWithPin = useCallback(async (pin: string, userId: string) => {
    try {
      const data = await storageAdapter.loadEnvelopes(userId);
      if (!data.pinEnvelope || !data.pinSalt) return false;

      const saltBuf = hexToBuf(data.pinSalt);
      const kek = await deriveKeyFromPin(pin, saltBuf);
      const envelope = JSON.parse(data.pinEnvelope);
      const dek = await unwrapKey(envelope, kek);
      
      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('PIN Unlock failed:', err);
      return false;
    }
  }, [storageAdapter]);

  const unlockWithPasskey = useCallback(async (userId: string) => {
    try {
      const data = await storageAdapter.loadEnvelopes(userId);
      if (!data.passkeyEnvelope || !data.passkeyId) return false;

      const passkeyWrappingKey = await authenticatePasskey(data.passkeyId);
      const envelope = JSON.parse(data.passkeyEnvelope);
      const dek = await unwrapKey(envelope, passkeyWrappingKey);
      
      setSessionKey(dek);
      return true;
    } catch (err) {
      console.error('Passkey Unlock failed:', err);
      return false;
    }
  }, [storageAdapter]);

  const resetPin = useCallback(async (newPin: string, userId: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked.");

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const hexSalt = bufToHex(salt.buffer);
      const newPinWrappingKey = await deriveKeyFromPin(newPin, salt.buffer);
      const newPinEnvelope = await wrapKey(sessionKey, newPinWrappingKey);

      await storageAdapter.saveEnvelopes(userId, {
        pinEnvelope: JSON.stringify(newPinEnvelope),
        pinSalt: hexSalt
      });
      return true;
    } catch (err) {
      console.error('Failed to reset PIN:', err);
      return false;
    }
  }, [sessionKey, storageAdapter]);

  const resetPasskey = useCallback(async (userId: string, email: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked.");

      const { id: passkeyId, key: newPasskeyWrappingKey } = await registerPasskey(userId, email);
      const newPasskeyEnvelope = await wrapKey(sessionKey, newPasskeyWrappingKey);

      await storageAdapter.saveEnvelopes(userId, {
        passkeyEnvelope: JSON.stringify(newPasskeyEnvelope),
        passkeyId
      });
      return true;
    } catch (err) {
      console.error('Failed to reset Passkey:', err);
      return false;
    }
  }, [sessionKey, storageAdapter]);

  const encryptPayload = useCallback(async (data: any) => {
    if (!sessionKey) throw new Error("Vault is locked");
    return await encryptData(data, sessionKey);
  }, [sessionKey]);

  const decryptPayload = useCallback(async (payload: EncryptedPayload) => {
    if (!sessionKey) throw new Error("Vault is locked");
    return await decryptData(payload, sessionKey);
  }, [sessionKey]);

  const lock = useCallback(() => setSessionKey(null), []);

  return (
    <VaultContext.Provider value={{
      isUnlocked: !!sessionKey,
      setupVault,
      unlockWithPin,
      unlockWithPasskey,
      resetPin,
      resetPasskey,
      encryptPayload,
      decryptPayload,
      lock
    }}>
      {children}
    </VaultContext.Provider>
  );
}

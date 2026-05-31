// src/zk-vault/VaultContext.tsx

import React, { createContext, useState, useCallback, useEffect, useRef } from 'react';
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
  lockOnWindowBlur?: boolean;
  autoLockTimeoutMs?: number;
  onError?: (err: Error) => void;
  children: React.ReactNode;
}

export function VaultProvider({ 
  storageAdapter, 
  lockOnWindowBlur = true, 
  autoLockTimeoutMs = 300000, // 5 minutes default
  onError,
  children 
}: VaultProviderProps) {
  const [sessionKey, setSessionKey] = useState<CryptoKey | null>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  const handleError = useCallback((err: unknown) => {
    const error = err instanceof Error ? err : new Error(String(err));
    if (onError) onError(error);
    else console.error('[zk-vault]', error);
  }, [onError]);

  const lock = useCallback(() => {
    setSessionKey(null);
  }, []);

  // --- Auto-Locking Logic ---
  useEffect(() => {
    if (!sessionKey) return;

    const resetTimer = () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      if (autoLockTimeoutMs > 0) {
        timeoutRef.current = setTimeout(lock, autoLockTimeoutMs);
      }
    };

    const handleVisibilityChange = () => {
      if (lockOnWindowBlur && document.visibilityState === 'hidden') lock();
    };

    const activityEvents = ['mousemove', 'keydown', 'scroll', 'touchstart'];
    activityEvents.forEach(e => window.addEventListener(e, resetTimer));
    document.addEventListener('visibilitychange', handleVisibilityChange);

    resetTimer();

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      activityEvents.forEach(e => window.removeEventListener(e, resetTimer));
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [sessionKey, autoLockTimeoutMs, lockOnWindowBlur, lock]);

  // --- Core Methods ---
  const setupVault = useCallback(async (pin: string, userId: string, email: string) => {
    try {
      const dek = await generateDEK();
      const salt = crypto.getRandomValues(new Uint8Array(32)); 
      const hexSalt = bufToHex(salt.buffer); 
      const pinWrappingKey = await deriveKeyFromPin(pin, salt.buffer);
      const pinEnvelope = await wrapKey(dek, pinWrappingKey);

      let passkeyId = null;
      let passkeyEnvelope = null;
      try {
        const { id, key: passkeyWrappingKey } = await registerPasskey(userId, email);
        passkeyId = id;
        passkeyEnvelope = await wrapKey(dek, passkeyWrappingKey);
      } catch (err) {
        handleError(new Error('Passkey skipped or unsupported during setup: ' + String(err)));
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
      handleError(err);
      return false;
    }
  }, [storageAdapter, handleError]);

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
      handleError(err);
      return false;
    }
  }, [storageAdapter, handleError]);

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
      handleError(err);
      return false;
    }
  }, [storageAdapter, handleError]);

  const resetPin = useCallback(async (newPin: string, userId: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked.");

      const currentEnvelopes = await storageAdapter.loadEnvelopes(userId);

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const hexSalt = bufToHex(salt.buffer);
      const newPinWrappingKey = await deriveKeyFromPin(newPin, salt.buffer);
      const newPinEnvelope = await wrapKey(sessionKey, newPinWrappingKey);

      try {
        await storageAdapter.saveEnvelopes(userId, {
          pinEnvelope: JSON.stringify(newPinEnvelope),
          pinSalt: hexSalt
        });
        return true;
      } catch (saveError) {
        // Rollback attempt to prevent permanent corruption
        await storageAdapter.saveEnvelopes(userId, currentEnvelopes).catch(() => {});
        throw saveError;
      }
    } catch (err) {
      handleError(err);
      return false;
    }
  }, [sessionKey, storageAdapter, handleError]);

  const resetPasskey = useCallback(async (userId: string, email: string) => {
    try {
      if (!sessionKey) throw new Error("Vault must be unlocked.");

      const currentEnvelopes = await storageAdapter.loadEnvelopes(userId);
      const { id: passkeyId, key: newPasskeyWrappingKey } = await registerPasskey(userId, email);
      const newPasskeyEnvelope = await wrapKey(sessionKey, newPasskeyWrappingKey);

      try {
        await storageAdapter.saveEnvelopes(userId, {
          passkeyEnvelope: JSON.stringify(newPasskeyEnvelope),
          passkeyId
        });
        return true;
      } catch (saveError) {
        // Rollback attempt
        await storageAdapter.saveEnvelopes(userId, currentEnvelopes).catch(() => {});
        throw saveError;
      }
    } catch (err) {
      handleError(err);
      return false;
    }
  }, [sessionKey, storageAdapter, handleError]);

  const encryptPayload = useCallback(async (data: any) => {
    if (!sessionKey) throw new Error("Vault is locked");
    return await encryptData(data, sessionKey);
  }, [sessionKey]);

  const decryptPayload = useCallback(async (payload: EncryptedPayload) => {
    if (!sessionKey) throw new Error("Vault is locked");
    return await decryptData(payload, sessionKey);
  }, [sessionKey]);

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

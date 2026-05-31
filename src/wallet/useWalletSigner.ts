// src/wallet/useWalletSigner.ts
//
// React hook that owns a single signer-worker instance, ties it to your storage
// adapter, and runs the WebAuthn ceremony (which must happen on the document
// thread) before handing the PRF bytes to the worker.

import { useCallback, useEffect, useRef, useState } from 'react';
import { WalletSignerClient } from './WalletSignerClient';
import { WalletVaultRecord, EthSignature, Argon2Params } from './messages';
import {
  registerPasskeyPrf,
  authenticatePasskeyPrf,
  isWebAuthnAvailable,
} from './webauthn-prf';

export interface WalletStorageAdapter {
  load: (userId: string) => Promise<WalletVaultRecord | null>;
  // Must persist all fields atomically (single transaction / single update).
  save: (userId: string, record: WalletVaultRecord) => Promise<void>;
}

export interface UseWalletSignerOptions {
  storage: WalletStorageAdapter;
  argon2?: Argon2Params;
  onError?: (err: Error) => void;
}

export function useWalletSigner({ storage, argon2, onError }: UseWalletSignerOptions) {
  const clientRef = useRef<WalletSignerClient | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [isUnlocked, setIsUnlocked] = useState(false);

  const getClient = useCallback(() => {
    if (!clientRef.current) clientRef.current = new WalletSignerClient();
    return clientRef.current;
  }, []);

  const fail = useCallback(
    (err: unknown) => {
      const e = err instanceof Error ? err : new Error(String(err));
      onError?.(e);
      return e;
    },
    [onError]
  );

  useEffect(() => {
    return () => {
      clientRef.current?.destroy();
      clientRef.current = null;
    };
  }, []);

  // Create a brand-new wallet. Optionally also bind a passkey.
  const createWallet = useCallback(
    async (
      userId: string,
      passcode: string,
      opts?: { withPasskey?: boolean; email?: string }
    ): Promise<{ address: string } | null> => {
      try {
        let prfFirstHex: string | undefined;
        let passkeyId: string | undefined;
        if (opts?.withPasskey) {
          if (!isWebAuthnAvailable()) throw new Error('WebAuthn not available.');
          const reg = await registerPasskeyPrf(userId, opts.email ?? userId);
          prfFirstHex = reg.prfFirstHex;
          passkeyId = reg.passkeyId;
        }
        const { record, address: addr } = await getClient().generate(passcode, {
          prfFirstHex,
          passkeyId,
          argon2,
        });
        await storage.save(userId, record);
        setAddress(addr);
        setIsUnlocked(true);
        return { address: addr };
      } catch (err) {
        fail(err);
        return null;
      }
    },
    [getClient, storage, argon2, fail]
  );

  const unlockWithPin = useCallback(
    async (userId: string, passcode: string): Promise<boolean> => {
      try {
        const record = await storage.load(userId);
        if (!record) return false;
        const addr = await getClient().unlockWithPin({
          passcode,
          pinSalt: record.pinSalt,
          pinEnvelope: record.pinEnvelope,
          walletEnvelope: record.walletEnvelope,
          argon2,
        });
        setAddress(addr);
        setIsUnlocked(true);
        return true;
      } catch (err) {
        fail(err);
        return false;
      }
    },
    [getClient, storage, argon2, fail]
  );

  const unlockWithPasskey = useCallback(
    async (userId: string): Promise<boolean> => {
      try {
        const record = await storage.load(userId);
        if (!record || !record.passkeyEnvelope || !record.passkeyId) return false;
        const prfFirstHex = await authenticatePasskeyPrf(record.passkeyId);
        const addr = await getClient().unlockWithPasskey({
          prfFirstHex,
          passkeyEnvelope: record.passkeyEnvelope,
          walletEnvelope: record.walletEnvelope,
        });
        setAddress(addr);
        setIsUnlocked(true);
        return true;
      } catch (err) {
        fail(err);
        return false;
      }
    },
    [getClient, storage, fail]
  );

  // Signs a 32-byte digest (hex). Pair this with a user-confirmation step that a
  // compromised page cannot forge (see README-wallet on transaction approval).
  const signDigest = useCallback(
    async (digestHex: string): Promise<EthSignature | null> => {
      try {
        return await getClient().signDigest(digestHex);
      } catch (err) {
        fail(err);
        return null;
      }
    },
    [getClient, fail]
  );

  const personalSign = useCallback(
    async (message: string): Promise<EthSignature | null> => {
      try {
        return await getClient().personalSign(message);
      } catch (err) {
        fail(err);
        return null;
      }
    },
    [getClient, fail]
  );

  const lock = useCallback(async () => {
    await clientRef.current?.lock();
    setIsUnlocked(false);
    setAddress(null);
  }, []);

  return {
    isUnlocked,
    address,
    createWallet,
    unlockWithPin,
    unlockWithPasskey,
    signDigest,
    personalSign,
    lock,
  };
}

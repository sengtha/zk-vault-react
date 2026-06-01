// src/wallet/useWalletSigner.ts
//
// React hook that owns a single signer-worker instance, ties it to your storage
// adapter, and runs the WebAuthn ceremony (which must happen on the document
// thread) before handing the PRF bytes to the worker.
//
// MNEMONIC CHANGE: `createWallet` now returns the mnemonic once (show it on a
// backup screen, then drop it), `importWallet` restores from a phrase, and
// `revealMnemonic` re-exports it for backup while unlocked.

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

  // Shared path for create + import. Returns the mnemonic so the caller can show
  // a one-time backup screen.
  const provision = useCallback(
    async (
      userId: string,
      passcode: string,
      opts?: {
        withPasskey?: boolean;
        email?: string;
        importMnemonic?: string;
        wordCount?: 12 | 24;
        accountIndex?: number;
      }
    ): Promise<{ address: string; mnemonic: string } | null> => {
      try {
        let prfFirstHex: string | undefined;
        let passkeyId: string | undefined;
        if (opts?.withPasskey) {
          if (!isWebAuthnAvailable()) throw new Error('WebAuthn not available.');
          const reg = await registerPasskeyPrf(userId, opts.email ?? userId);
          prfFirstHex = reg.prfFirstHex;
          passkeyId = reg.passkeyId;
        }
        const { record, address: addr, mnemonic } = await getClient().generate(
          passcode,
          {
            prfFirstHex,
            passkeyId,
            argon2,
            importMnemonic: opts?.importMnemonic,
            wordCount: opts?.wordCount,
            accountIndex: opts?.accountIndex,
          }
        );
        await storage.save(userId, record);
        setAddress(addr);
        setIsUnlocked(true);
        return { address: addr, mnemonic };
      } catch (err) {
        fail(err);
        return null;
      }
    },
    [getClient, storage, argon2, fail]
  );

  // Create a brand-new wallet. Optionally also bind a passkey. The returned
  // mnemonic must be shown to the user for backup, then dropped from memory.
  const createWallet = useCallback(
    (
      userId: string,
      passcode: string,
      opts?: { withPasskey?: boolean; email?: string; wordCount?: 12 | 24 }
    ) => provision(userId, passcode, opts),
    [provision]
  );

  // Restore an existing wallet from a recovery phrase.
  const importWallet = useCallback(
    (
      userId: string,
      passcode: string,
      mnemonic: string,
      opts?: { withPasskey?: boolean; email?: string; accountIndex?: number }
    ) => provision(userId, passcode, { ...opts, importMnemonic: mnemonic }),
    [provision]
  );

  const unlockWithPin = useCallback(
    async (userId: string, passcode: string, accountIndex = 0): Promise<boolean> => {
      try {
        const record = await storage.load(userId);
        if (!record) return false;
        const addr = await getClient().unlockWithPin({
          passcode,
          pinSalt: record.pinSalt,
          pinEnvelope: record.pinEnvelope,
          walletEnvelope: record.walletEnvelope,
          argon2,
          accountIndex,
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
    async (userId: string, accountIndex = 0): Promise<boolean> => {
      try {
        const record = await storage.load(userId);
        if (!record || !record.passkeyEnvelope || !record.passkeyId) return false;
        const prfFirstHex = await authenticatePasskeyPrf(record.passkeyId);
        const addr = await getClient().unlockWithPasskey({
          prfFirstHex,
          passkeyEnvelope: record.passkeyEnvelope,
          walletEnvelope: record.walletEnvelope,
          accountIndex,
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

  // Reveal the recovery phrase for backup. GATE THIS behind fresh re-auth and an
  // unforgeable confirmation surface (see README-wallet). Returns null on error.
  const revealMnemonic = useCallback(async (): Promise<string | null> => {
    try {
      return await getClient().exportMnemonic();
    } catch (err) {
      fail(err);
      return null;
    }
  }, [getClient, fail]);

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
    importWallet,
    unlockWithPin,
    unlockWithPasskey,
    revealMnemonic,
    signDigest,
    personalSign,
    lock,
  };
}

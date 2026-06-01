// src/wallet/signer.worker.ts
//
// Isolated signer. The mnemonic and derived private key live ONLY in this
// worker's memory. The main thread can ask it to unlock, sign, report its
// address, and — on the explicit backup path — export the mnemonic. There is no
// other message that returns secret material. A compromised main thread cannot
// read secrets out of here passively; it can only request signatures while
// unlocked, or call exportMnemonic (which is why per-action confirmation still
// matters — see README-wallet).
//
// MNEMONIC CHANGE: the retained secret is the BIP39 mnemonic; the active
// account's private key is derived from it (BIP44) and kept alongside for
// signing. `generate` returns the mnemonic once for the backup screen.

/// <reference lib="webworker" />

import {
  generateWallet,
  unlockWithPin,
  unlockWithPasskey,
  signDigest,
  personalSignDigest,
  unhex,
  DEFAULT_ARGON2,
} from './crypto-core';
import { SignerRequest, SignerResponse } from './messages';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

// Secret material — confined to this worker, never posted out except mnemonic
// on the explicit generate/exportMnemonic paths.
let mnemonic: string | null = null;
let privateKey: Uint8Array | null = null;
let dek: CryptoKey | null = null;
let address: string | null = null;
let accountIndex = 0;

function zeroize() {
  if (privateKey) privateKey.fill(0);
  privateKey = null;
  dek = null;
  address = null;
  accountIndex = 0;
  // JS strings are immutable, so we cannot scrub the bytes; dropping the only
  // reference makes it eligible for GC. For stronger guarantees, keep the
  // unlocked session short and lock aggressively.
  mnemonic = null;
}

function reply(msg: SignerResponse) {
  ctx.postMessage(msg);
}

ctx.addEventListener('message', async (ev: MessageEvent<SignerRequest>) => {
  const req = ev.data;
  try {
    switch (req.type) {
      case 'generate': {
        const prf = req.prfFirstHex ? unhex(req.prfFirstHex) : undefined;
        const res = await generateWallet(req.passcode, req.argon2 ?? DEFAULT_ARGON2, {
          prfFirst: prf,
          importMnemonic: req.importMnemonic,
          wordCount: req.wordCount,
          accountIndex: req.accountIndex,
        });
        // Retain secret material in the worker; expose envelopes + address, plus
        // the mnemonic ONCE so the app can present a backup screen.
        mnemonic = res.mnemonic;
        privateKey = res.privateKey;
        dek = res.dek;
        address = res.address;
        accountIndex = res.accountIndex;
        reply({
          id: req.id,
          ok: true,
          type: 'generate',
          address: res.address,
          mnemonic: res.mnemonic,
          record: {
            pinSalt: res.pinSalt,
            pinEnvelope: JSON.stringify(res.pinEnvelope),
            passkeyEnvelope: res.passkeyEnvelope
              ? JSON.stringify(res.passkeyEnvelope)
              : null,
            passkeyId: req.passkeyId ?? null,
            walletEnvelope: JSON.stringify(res.walletEnvelope),
          },
        });
        break;
      }

      case 'unlockPin': {
        const out = await unlockWithPin(
          req.passcode,
          req.pinSalt,
          JSON.parse(req.pinEnvelope),
          JSON.parse(req.walletEnvelope),
          req.argon2 ?? DEFAULT_ARGON2,
          req.accountIndex ?? 0
        );
        mnemonic = out.mnemonic;
        privateKey = out.privateKey;
        dek = out.dek;
        address = out.address;
        accountIndex = out.accountIndex;
        reply({ id: req.id, ok: true, type: 'unlockPin', address: out.address });
        break;
      }

      case 'unlockPasskey': {
        const out = await unlockWithPasskey(
          unhex(req.prfFirstHex),
          JSON.parse(req.passkeyEnvelope),
          JSON.parse(req.walletEnvelope),
          req.accountIndex ?? 0
        );
        mnemonic = out.mnemonic;
        privateKey = out.privateKey;
        dek = out.dek;
        address = out.address;
        accountIndex = out.accountIndex;
        reply({ id: req.id, ok: true, type: 'unlockPasskey', address: out.address });
        break;
      }

      case 'signDigest': {
        if (!privateKey) throw new Error('Signer is locked.');
        const signature = signDigest(privateKey, unhex(req.digestHex));
        reply({ id: req.id, ok: true, type: 'signDigest', signature });
        break;
      }

      case 'personalSign': {
        if (!privateKey) throw new Error('Signer is locked.');
        const digest = personalSignDigest(req.message);
        const signature = signDigest(privateKey, digest);
        reply({ id: req.id, ok: true, type: 'personalSign', signature });
        break;
      }

      case 'getAddress': {
        reply({ id: req.id, ok: true, type: 'getAddress', address });
        break;
      }

      case 'exportMnemonic': {
        // DELIBERATE isolation breach for backup / "reveal recovery phrase".
        // Only available while unlocked. The caller MUST gate this behind fresh
        // re-authentication and a confirmation surface a compromised page cannot
        // forge (cross-origin iframe). See README-wallet.
        if (!mnemonic) throw new Error('Signer is locked.');
        reply({ id: req.id, ok: true, type: 'exportMnemonic', mnemonic });
        break;
      }

      case 'lock': {
        zeroize();
        reply({ id: req.id, ok: true, type: 'lock' });
        break;
      }
    }
  } catch (err) {
    reply({
      id: (req as { id: number }).id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

// Wipe secrets if the worker is told to terminate gracefully.
ctx.addEventListener('unload', zeroize);

void dek; // retained for potential re-key flows; intentionally unused here

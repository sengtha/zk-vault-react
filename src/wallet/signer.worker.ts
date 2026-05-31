// src/wallet/signer.worker.ts
//
// Isolated signer. The private key lives ONLY in this worker's memory. The main
// thread can ask it to unlock, sign, and report its address — but there is no
// message that returns the raw key. Even a fully compromised main thread cannot
// read the key out of here; it can only request signatures while unlocked
// (which is why per-transaction confirmation still matters — see README-wallet).

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

// Key material — confined to this worker, never posted out.
let privateKey: Uint8Array | null = null;
let dek: CryptoKey | null = null;
let address: string | null = null;

function zeroize() {
  if (privateKey) privateKey.fill(0);
  privateKey = null;
  dek = null;
  address = null;
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
        const res = await generateWallet(req.passcode, req.argon2 ?? DEFAULT_ARGON2, prf);
        // Retain key material in the worker; expose only envelopes + address.
        privateKey = res.privateKey;
        dek = res.dek;
        address = res.address;
        reply({
          id: req.id,
          ok: true,
          type: 'generate',
          address: res.address,
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
          req.argon2 ?? DEFAULT_ARGON2
        );
        privateKey = out.privateKey;
        dek = out.dek;
        address = out.address;
        reply({ id: req.id, ok: true, type: 'unlockPin', address: out.address });
        break;
      }

      case 'unlockPasskey': {
        const out = await unlockWithPasskey(
          unhex(req.prfFirstHex),
          JSON.parse(req.passkeyEnvelope),
          JSON.parse(req.walletEnvelope)
        );
        privateKey = out.privateKey;
        dek = out.dek;
        address = out.address;
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

// Wipe keys if the worker is told to terminate gracefully.
ctx.addEventListener('unload', zeroize);

void dek; // retained for potential re-key flows; intentionally unused here

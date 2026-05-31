// src/wallet/messages.ts
//
// Wire protocol between the main thread (WalletSignerClient) and the isolated
// signer worker. Pure types only — no DOM or WebWorker lib dependency — so this
// file compiles under both tsconfigs.

/** An AES-GCM envelope, hex-encoded. Matches the vault's EncryptedPayload. */
export interface Envelope {
  cipher: string; // hex
  iv: string;     // hex
}

/** What gets persisted by your storage adapter for a wallet vault. */
export interface WalletVaultRecord {
  pinSalt: string;                 // hex (Argon2id salt)
  pinEnvelope: string;             // JSON string of Envelope (DEK wrapped by passcode KEK)
  passkeyEnvelope: string | null;  // JSON string of Envelope (DEK wrapped by passkey PRF KEK)
  passkeyId: string | null;        // hex WebAuthn rawId
  walletEnvelope: string;          // JSON string of Envelope (private key encrypted by DEK)
}

/** Argon2id parameters. Defaults are wallet-grade; tune for your devices. */
export interface Argon2Params {
  memorySizeKiB: number; // e.g. 65536 (64 MiB)
  iterations: number;    // e.g. 3
  parallelism: number;   // e.g. 1
}

// ---- Requests (main thread → worker) ----

export type SignerRequest =
  | {
      id: number;
      type: 'generate';
      passcode: string;
      prfFirstHex?: string;       // optional passkey PRF output to also create a passkey envelope
      passkeyId?: string;         // required if prfFirstHex provided
      argon2?: Argon2Params;
    }
  | {
      id: number;
      type: 'unlockPin';
      passcode: string;
      pinSalt: string;
      pinEnvelope: string;        // JSON Envelope
      walletEnvelope: string;     // JSON Envelope
      argon2?: Argon2Params;
    }
  | {
      id: number;
      type: 'unlockPasskey';
      prfFirstHex: string;
      passkeyEnvelope: string;    // JSON Envelope
      walletEnvelope: string;     // JSON Envelope
    }
  | { id: number; type: 'signDigest'; digestHex: string }
  | { id: number; type: 'personalSign'; message: string }
  | { id: number; type: 'getAddress' }
  | { id: number; type: 'lock' };

// ---- Responses (worker → main thread) ----

export interface EthSignature {
  signatureHex: string; // 0x + r(32)||s(32)||v(1)
  r: string;            // hex, 0x-prefixed
  s: string;            // hex, 0x-prefixed
  v: number;            // 27 or 28
}

export type SignerResponse =
  | { id: number; ok: true; type: 'generate'; record: WalletVaultRecord; address: string }
  | { id: number; ok: true; type: 'unlockPin'; address: string }
  | { id: number; ok: true; type: 'unlockPasskey'; address: string }
  | { id: number; ok: true; type: 'signDigest'; signature: EthSignature }
  | { id: number; ok: true; type: 'personalSign'; signature: EthSignature }
  | { id: number; ok: true; type: 'getAddress'; address: string | null }
  | { id: number; ok: true; type: 'lock' }
  | { id: number; ok: false; error: string };

// src/wallet/index.ts

export * from './messages';
export { WalletSignerClient } from './WalletSignerClient';
export type { GenerateClientOptions } from './WalletSignerClient';
export { useWalletSigner } from './useWalletSigner';
export type { WalletStorageAdapter, UseWalletSignerOptions } from './useWalletSigner';
export {
  isWebAuthnAvailable,
  registerPasskeyPrf,
  authenticatePasskeyPrf,
} from './webauthn-prf';
// Mnemonic helpers (safe to use on the main thread for input validation UX).
// NOTE: privateKeyFromMnemonic / generateWallet / unlock* run inside the worker
// and are intentionally NOT re-exported here to discourage main-thread use.
export {
  newMnemonic,
  normalizeMnemonic,
  isValidMnemonic,
  assertValidMnemonic,
  ethDerivationPath,
} from './crypto-core';

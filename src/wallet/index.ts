// src/wallet/index.ts

export * from './messages';
export { WalletSignerClient } from './WalletSignerClient';
export { useWalletSigner } from './useWalletSigner';
export type { WalletStorageAdapter, UseWalletSignerOptions } from './useWalletSigner';
export {
  isWebAuthnAvailable,
  registerPasskeyPrf,
  authenticatePasskeyPrf,
} from './webauthn-prf';

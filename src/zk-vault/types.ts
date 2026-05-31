
// src/zk-vault/types.ts

export interface VaultEnvelopes {
  pinEnvelope: string | null;     // JSON string of EncryptedPayload
  pinSalt: string | null;         // Hex string (switched from Base64 for stability)
  passkeyEnvelope: string | null; // JSON string of EncryptedPayload
  passkeyId: string | null;       // Hex string of the WebAuthn rawId
}

export interface IVaultStorageAdapter {
  /** Retrieves the cryptographic envelopes for a specific user */
  loadEnvelopes: (userId: string) => Promise<VaultEnvelopes>;
  /** Saves updated cryptographic envelopes for a specific user atomically */
  saveEnvelopes: (userId: string, envelopes: Partial<VaultEnvelopes>) => Promise<void>;
}

// src/zk-vault/types.ts

export interface VaultEnvelopes {
  pinEnvelope: string | null;
  pinSalt: string | null;
  passkeyEnvelope: string | null;
  passkeyId: string | null;
}

export interface IVaultStorageAdapter {
  /** Retrieves the cryptographic envelopes for a specific user */
  loadEnvelopes: (userId: string) => Promise<VaultEnvelopes>;
  /** Saves updated cryptographic envelopes for a specific user */
  saveEnvelopes: (userId: string, envelopes: Partial<VaultEnvelopes>) => Promise<void>;
}

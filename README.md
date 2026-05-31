# Zero-Knowledge React Vault (`zk-vault-react`)

A headless, database-agnostic React provider for Dual-Envelope (PIN + WebAuthn) cryptography. 

This library allows you to easily add End-to-End Encryption (E2EE) to any React application. It handles the complex WebCrypto and WebAuthn (Passkey) math while letting you bring your own database (Supabase, Firebase, etc.) for cross-device synchronization.

## ✨ Features
* **Dual-Envelope Cryptography**: Users can unlock their vault using either a hardware Passkey (FaceID/TouchID) OR a cross-device 6-digit PIN.
* **Zero-Knowledge**: The server only ever sees ciphertext. Keys never leave the browser.
* **Database Agnostic**: Bring your own backend by implementing a simple 2-function Storage Adapter.
* **Ready-to-use UI**: Drop-in Tailwind components for Setup, Unlock, and Settings.

---

## 🚀 Getting Started: Step-by-Step Integration

### Step 1: Prepare Your Database
You need a place to store the cryptographic envelopes. Because this library is zero-knowledge, these columns will only ever contain random alphanumeric strings (Base64) or JSON ciphertext.

**Example Supabase (PostgreSQL) Schema:**
Run this SQL in your Supabase SQL Editor to add the required columns to your user profiles table:

```sql
ALTER TABLE user_profiles 
ADD COLUMN vault_envelope_pin TEXT,
ADD COLUMN vault_pin_salt TEXT,
ADD COLUMN vault_envelope_passkey TEXT,
ADD COLUMN passkey_id TEXT;
```

### Step 2: Copy the Library into Your Project
Copy the src/zk-vault/ and src/components/ directories from this repository directly into your React project's src/ folder.

### Step 3: Create your Storage Adapter
Create a file (e.g., src/lib/vaultAdapter.ts) to map the Vault's generic storage interface to your specific database.

```ts
import { supabase } from './supabaseClient'; 
import { IVaultStorageAdapter } from '../zk-vault/types';

export const supabaseVaultAdapter: IVaultStorageAdapter = {
  loadEnvelopes: async (userId: string) => {
    const { data } = await supabase.from('user_profiles').select('*').eq('id', userId).single();
    if (!data) return { pinEnvelope: null, pinSalt: null, passkeyEnvelope: null, passkeyId: null };
    
    return {
      pinEnvelope: data.vault_envelope_pin,
      pinSalt: data.vault_pin_salt,
      passkeyEnvelope: data.vault_envelope_passkey,
      passkeyId: data.passkey_id
    };
  },
  
  saveEnvelopes: async (userId: string, envelopes) => {
    const updates: any = {};
    if (envelopes.pinEnvelope !== undefined) updates.vault_envelope_pin = envelopes.pinEnvelope;
    if (envelopes.pinSalt !== undefined) updates.vault_pin_salt = envelopes.pinSalt;
    if (envelopes.passkeyEnvelope !== undefined) updates.vault_envelope_passkey = envelopes.passkeyEnvelope;
    if (envelopes.passkeyId !== undefined) updates.passkey_id = envelopes.passkeyId;

    await supabase.from('user_profiles').update(updates).eq('id', userId);
  }
};

```
### Step 4: Wrap Your App with the Provider
At the root of your authenticated app, wrap your components with the VaultProvider and pass in the adapter you just created.
```
// App.tsx
import { VaultProvider } from './zk-vault';
import { supabaseVaultAdapter } from './lib/vaultAdapter';

function App({ user }) {
  return (
    <VaultProvider storageAdapter={supabaseVaultAdapter}>
      <VaultGatekeeper user={user} />
    </VaultProvider>
  );
}
```
## 🎨 Using the Drop-in UI Components
The easiest way to integrate the Vault is to create a "Gatekeeper" component that checks if the user has set up their vault, and if it is unlocked.
## The Gatekeeper Pattern
Use the included VaultSetup and VaultUnlock components to protect your main application.
```
// VaultGatekeeper.tsx
import React, { useEffect, useState } from 'react';
import { useZkVault } from './zk-vault';
import VaultSetup from './components/VaultSetup';
import VaultUnlock from './components/VaultUnlock';
import MainApplication from './MainApplication';
import { supabase } from './lib/supabaseClient';

export default function VaultGatekeeper({ user }) {
  const { isUnlocked } = useZkVault();
  const [hasVault, setHasVault] = useState<boolean | null>(null);

  // Check if the user has already set up a vault in the DB
  useEffect(() => {
    async function checkStatus() {
      const { data } = await supabase.from('user_profiles').select('vault_envelope_pin').eq('id', user.id).single();
      setHasVault(!!data?.vault_envelope_pin);
    }
    checkStatus();
  }, [user]);

  if (hasVault === null) return <div>Loading...</div>;

  // 1. If no vault exists in DB, show the Setup UI
  if (!hasVault) {
    return <VaultSetup userId={user.id} userEmail={user.email} onSuccess={() => setHasVault(true)} />;
  }

  // 2. If vault exists but is locked in memory, show the Unlock UI
  if (!isUnlocked) {
    return <VaultUnlock userId={user.id} />;
  }

  // 3. Vault is unlocked! Render the main app.
  return <MainApplication />;
}
```
## Allowing Users to Reset Credentials
Inside your application's Settings or Profile page, simply drop in the VaultSettings component. It will automatically handle resetting the PIN or re-registering a Passkey.
```
// ProfilePage.tsx
import VaultSettings from '../components/VaultSettings';

export default function ProfilePage({ user }) {
  return (
    <div className="p-8">
      <h1>Account Settings</h1>
      
      {/* Renders the PIN and Passkey reset forms */}
      <VaultSettings userId={user.id} userEmail={user.email} />
    </div>
  );
}

## 🔐 Encrypting and Decrypting Your Data
Once isUnlocked is true, the Vault Context holds the sessionKey (the unwrapped Master DEK) in memory. You use this key to encrypt your actual application data before sending it to your database.

```
import { encryptData, decryptData } from '../zk-vault/crypto';
import { useZkVault } from '../zk-vault';

function SecureNoteEditor() {
  const { sessionKey } = useZkVault();

  const saveSecretNote = async (text: string) => {
    if (!sessionKey) return;
    
    // Encrypts the payload with AES-GCM
    const encryptedPayload = await encryptData({ note: text }, sessionKey);
    
    // Send to your database:
    // await supabase.from('notes').insert({ 
    //   cipher: encryptedPayload.cipher, 
    //   iv: encryptedPayload.iv 
    // });
  };
}
```
## ⚠️ Security Notes
HTTPS Required: The WebCrypto and WebAuthn APIs require a secure context. This library will only work on localhost or over https://.
Zero Recovery: Because the Master Key is derived from user inputs (PIN/Passkey) and the server only holds ciphertext, if a user forgets their PIN and loses their Passkey device simultaneously, their data cannot be recovered by anyone, including the database administrator.

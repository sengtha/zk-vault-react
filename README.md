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

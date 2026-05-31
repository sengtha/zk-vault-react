# Zero-Knowledge React Vault (`zk-vault-react`)

A headless, database-agnostic React provider for Dual-Envelope (Passcode + WebAuthn) cryptography. 

This library allows you to easily add End-to-End Encryption (E2EE) to any React application. It handles the complex WebCrypto and WebAuthn (Passkey) math while letting you bring your own database (Supabase, Firebase, etc.) for cross-device synchronization.

## ✨ Features
* **Dual-Envelope Cryptography**: Users can unlock their vault using either a hardware Passkey (FaceID/TouchID) OR a cross-device 8+ character alphanumeric Passcode.
* **WebAuthn PRF Extension**: Hardware passkeys are fully utilized to generate un-extractable symmetric keys bound to the authenticator device.
* **Zero-Knowledge Architecture**: The server only ever sees ciphertext. The Master Key (DEK) is securely trapped inside React closure memory and never exposed to the DOM.
* **Auto-Locking**: Configurable timeout and window blur detection to lock the vault when inactive.
* **Client-Side Rate Limiting**: Exponential backoff integrated into the Unlock UI to deter local rapid-fire offline guessing.

---

## ⚠️ Important Architectural Considerations

Before implementing, you must understand the following threat-model trade-offs inherent to this client-side E2EE approach:

1. **Host Stability:** The WebAuthn PRF salt is generated dynamically using `window.location.hostname`. The domain you use during Passkey registration must perfectly match the domain used during authentication.
2. **`extractable: true` Requirement:** Due to native `window.crypto.subtle` API constraints, the Master Data Encryption Key (DEK) must be generated as extractable so that it can be wrapped and unwrapped by the Passcode/Passkey KEKs. While the React Provider traps this key inside a secure closure, robust XSS prevention is still required in your application to prevent bad actors from tampering with the helper functions.
3. **Client-Side WebAuthn:** As a true zero-knowledge client, the WebAuthn challenge is generated and validated client-side. The library relies completely on the browser's origin binding for replay prevention rather than a traditional server-side ceremony. 
4. **Zero Recovery:** The server only holds ciphertext. If a user forgets their Passcode and loses their Passkey device simultaneously, their data cannot be recovered.

---

## 🚀 Getting Started

*(Refer to the source files for complete integration patterns, including Database Schema Preparation, Storage Adapter configuration, and wrapping your application with the `VaultProvider`)*

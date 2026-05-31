// src/zk-vault/crypto.ts

const AES_ALGO = 'AES-GCM';
const PBKDF2_ALGO = 'PBKDF2';
const HASH_ALGO = 'SHA-256';
const PRF_SALT = 'zk-vault-prf-salt-v1'; // Constant salt for the hardware PRF extension

export interface EncryptedPayload {
  cipher: string;
  iv: string;
}

// --- Helpers (Exported so the Context can use them for the PIN salt) ---

export function bufToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBuf(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// --- Core API ---

export async function generateDEK(): Promise<CryptoKey> {
  return await window.crypto.subtle.generateKey(
    { name: AES_ALGO, length: 256 },
    true, // Must remain true so it can be wrapped
    ['encrypt', 'decrypt']
  );
}

export async function deriveKeyFromPin(pin: string, saltBuf: ArrayBuffer): Promise<CryptoKey> {
  const pinBuf = encoder.encode(pin);
  const baseKey = await window.crypto.subtle.importKey(
    'raw', pinBuf, { name: PBKDF2_ALGO }, false, ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: PBKDF2_ALGO,
      salt: saltBuf,
      iterations: 600000, // OWASP 2025 standard
      hash: HASH_ALGO,
    },
    baseKey,
    { name: AES_ALGO, length: 256 },
    false, // AUDIT FIX: KEK should never be extractable
    ['wrapKey', 'unwrapKey']
  );
}

export async function encryptData(data: any, key: CryptoKey): Promise<EncryptedPayload> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedData = encoder.encode(JSON.stringify(data));
  const cipher = await window.crypto.subtle.encrypt({ name: AES_ALGO, iv }, key, encodedData);

  return { cipher: bufToHex(cipher), iv: bufToHex(iv.buffer) };
}

export async function decryptData(payload: EncryptedPayload, key: CryptoKey): Promise<any> {
  const cipherBuf = hexToBuf(payload.cipher);
  const ivBuf = hexToBuf(payload.iv);

  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: AES_ALGO, iv: new Uint8Array(ivBuf) }, key, cipherBuf
  );

  return JSON.parse(decoder.decode(decryptedBuf));
}

export async function wrapKey(keyToWrap: CryptoKey, wrappingKey: CryptoKey): Promise<EncryptedPayload> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await window.crypto.subtle.wrapKey(
    'raw', keyToWrap, wrappingKey, { name: AES_ALGO, iv }
  );

  return { cipher: bufToHex(wrapped), iv: bufToHex(iv.buffer) };
}

export async function unwrapKey(wrappedPayload: EncryptedPayload, wrappingKey: CryptoKey): Promise<CryptoKey> {
  const wrappedBuf = hexToBuf(wrappedPayload.cipher);
  const ivBuf = hexToBuf(wrappedPayload.iv);

  return await window.crypto.subtle.unwrapKey(
    'raw', wrappedBuf, wrappingKey,
    { name: AES_ALGO, iv: new Uint8Array(ivBuf) },
    { name: AES_ALGO, length: 256 },
    true, ['encrypt', 'decrypt']
  );
}

// --- Passkey / WebAuthn PRF Logic ---

export async function registerPasskey(userId: string, email: string): Promise<{ id: string, key: CryptoKey }> {
  const challenge = window.crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = encoder.encode(PRF_SALT);
  
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: window.location.hostname, name: 'Secure Vault' }, // Explicit rp.id added
      user: {
        id: encoder.encode(userId),
        name: email,
        displayName: email.split('@')[0],
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
      timeout: 60000,
      extensions: {
        prf: { eval: { first: prfSalt } } // Request the authenticator to compute the PRF
      }
    }
  }) as PublicKeyCredential;

  if (!credential) throw new Error('Passkey registration failed.');

  const ext = (credential.getClientExtensionResults() as any).prf;
  if (!ext?.results?.first) {
    throw new Error('Authenticator does not support the PRF extension required for secure encryption.');
  }

  // Use the hardware-derived PRF output as the wrapping key material directly
  const key = await window.crypto.subtle.importKey(
    'raw', ext.results.first, { name: AES_ALGO }, false, ['wrapKey', 'unwrapKey']
  );
  
  return { id: bufToHex(credential.rawId), key };
}

export async function authenticatePasskey(passkeyIdHex: string): Promise<CryptoKey> {
  const challenge = window.crypto.getRandomValues(new Uint8Array(32));
  const prfSalt = encoder.encode(PRF_SALT);
  const rawId = hexToBuf(passkeyIdHex);
  
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: window.location.hostname, // Explicit rpId
      allowCredentials: [{ type: 'public-key', id: rawId }], // Force correct passkey prompt
      userVerification: 'required',
      timeout: 60000,
      extensions: {
        prf: { eval: { first: prfSalt } } // Request the authenticator to compute the PRF
      }
    }
  }) as PublicKeyCredential;

  if (!assertion) throw new Error('Passkey authentication failed.');

  const ext = (assertion.getClientExtensionResults() as any).prf;
  if (!ext?.results?.first) {
    throw new Error('Authenticator did not return PRF results.');
  }

  return await window.crypto.subtle.importKey(
    'raw', ext.results.first, { name: AES_ALGO }, false, ['wrapKey', 'unwrapKey']
  );
}

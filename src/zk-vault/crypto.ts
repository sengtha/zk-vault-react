
/**
 * Pure Zero-Knowledge Dual-Envelope Encryption Engine
 * Pattern: DEK (Data Encryption Key) -> Encrypts Data -> DEK is wrapped by PIN & Passkey
 */

const AES_ALGO = 'AES-GCM';
const PBKDF2_ALGO = 'PBKDF2';
const HASH_ALGO = 'SHA-256';

export interface EncryptedPayload {
  cipher: string;
  iv: string;
  salt?: string;
}

// --- Internal Helpers ---

function bufToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// --- Core API ---

/**
 * Generates a fresh random Data Encryption Key (DEK)
 */
export async function generateDEK(): Promise<CryptoKey> {
  return await window.crypto.subtle.generateKey(
    { name: AES_ALGO, length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Derives a key from a PIN using PBKDF2
 */
export async function deriveKeyFromPin(pin: string, saltBuf: ArrayBuffer): Promise<CryptoKey> {
  const pinBuf = encoder.encode(pin);
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    pinBuf,
    { name: PBKDF2_ALGO },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: PBKDF2_ALGO,
      salt: saltBuf,
      iterations: 100000,
      hash: HASH_ALGO,
    },
    baseKey,
    { name: AES_ALGO, length: 256 },
    true,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

/**
 * Encrypts arbitrary data (JSON) using a CryptoKey
 */
export async function encryptData(data: any, key: CryptoKey): Promise<EncryptedPayload> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedData = encoder.encode(JSON.stringify(data));
  const cipher = await window.crypto.subtle.encrypt(
    { name: AES_ALGO, iv },
    key,
    encodedData
  );

  return {
    cipher: bufToHex(cipher),
    iv: bufToHex(iv.buffer),
  };
}

/**
 * Decrypts a payload back into JSON
 */
export async function decryptData(payload: EncryptedPayload, key: CryptoKey): Promise<any> {
  const cipherBuf = hexToBuf(payload.cipher);
  const ivBuf = hexToBuf(payload.iv);

  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: AES_ALGO, iv: new Uint8Array(ivBuf) },
    key,
    cipherBuf
  );

  return JSON.parse(decoder.decode(decryptedBuf));
}

/**
 * Wraps (encrypts) one key with another
 */
export async function wrapKey(keyToWrap: CryptoKey, wrappingKey: CryptoKey): Promise<EncryptedPayload> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await window.crypto.subtle.wrapKey(
    'raw',
    keyToWrap,
    wrappingKey,
    { name: AES_ALGO, iv }
  );

  return {
    cipher: bufToHex(wrapped),
    iv: bufToHex(iv.buffer),
  };
}

/**
 * Unwraps (decrypts) a key
 */
export async function unwrapKey(wrappedPayload: EncryptedPayload, wrappingKey: CryptoKey): Promise<CryptoKey> {
  const wrappedBuf = hexToBuf(wrappedPayload.cipher);
  const ivBuf = hexToBuf(wrappedPayload.iv);

  return await window.crypto.subtle.unwrapKey(
    'raw',
    wrappedBuf,
    wrappingKey,
    { name: AES_ALGO, iv: new Uint8Array(ivBuf) },
    { name: AES_ALGO, length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// --- Passkey / WebAuthn Logic ---

/**
 * Registers a new passkey and derives a deterministic wrapping key.
 */
export async function registerPasskey(userId: string, email: string): Promise<{ id: string, key: CryptoKey }> {
  const challenge = window.crypto.getRandomValues(new Uint8Array(32));
  
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: window.location.hostname },
      user: {
        id: encoder.encode(userId),
        name: email,
        displayName: email.split('@')[0],
      },
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }], // ES256
      authenticatorSelection: { 
        userVerification: 'required',
        residentKey: 'required' // Forces it to be a discoverable Passkey
      },
    }
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Passkey registration failed or cancelled.');
  }

  // Derive key deterministically from the constant rawId
  const keySeed = await window.crypto.subtle.digest(HASH_ALGO, credential.rawId);
  const key = await window.crypto.subtle.importKey(
    'raw',
    keySeed,
    { name: AES_ALGO },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
  
  return {
    id: bufToHex(credential.rawId),
    key
  };
}

/**
 * Authenticates an existing passkey and retrieves the deterministic wrapping key.
 * This triggers the browser's native WebAuthn popup.
 */
export async function authenticatePasskey(userId?: string): Promise<CryptoKey> {
  const challenge = window.crypto.getRandomValues(new Uint8Array(32));
  
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: 'required'
    }
  }) as PublicKeyCredential;

  if (!assertion) {
    throw new Error('Passkey authentication failed or cancelled.');
  }

  // Derive exactly the same key from rawId
  const keySeed = await window.crypto.subtle.digest(HASH_ALGO, assertion.rawId);
  return await window.crypto.subtle.importKey(
    'raw',
    keySeed,
    { name: AES_ALGO },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
  );
}

// src/wallet/crypto-core.ts
//
// Environment-agnostic crypto used INSIDE the signer worker. Uses only the
// global `crypto.subtle` (available in both window and worker scopes), noble
// curves/hashes, and hash-wasm — no DOM-specific APIs — so it compiles and runs
// in a Web Worker.
//
// This module never returns raw private-key bytes to anything outside the
// worker. Callers get addresses and signatures only.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { argon2id } from 'hash-wasm';
import { Envelope, Argon2Params, EthSignature } from './messages';

const AES = 'AES-GCM';

export const DEFAULT_ARGON2: Argon2Params = {
  memorySizeKiB: 65536, // 64 MiB — wallet-grade; lower to 19456 (19 MiB) for low-end mobile
  iterations: 3,
  parallelism: 1,
};

const enc = new TextEncoder();

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(new ArrayBuffer(n));
  crypto.getRandomValues(b);
  return b;
}

function toBuf(u8: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u8.byteLength);
  new Uint8Array(b).set(u8);
  return b;
}

// A Uint8Array guaranteed to be backed by a plain ArrayBuffer (satisfies the
// strict BufferSource overloads under TS 5.7+ typed-array generics).
function bytes(u8: Uint8Array): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(new ArrayBuffer(u8.byteLength));
  b.set(u8);
  return b;
}

export function hex(u8: Uint8Array): string {
  return bytesToHex(u8);
}
export function unhex(s: string): Uint8Array {
  return hexToBytes(s.startsWith('0x') ? s.slice(2) : s);
}

// ---- Argon2id KEK derivation ----
// Returns a non-extractable AES-GCM key used only to wrap/unwrap the DEK.
export async function deriveKekArgon2(
  passcode: string,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2
): Promise<CryptoKey> {
  const raw = await argon2id({
    password: passcode,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memorySizeKiB,
    hashLength: 32,
    outputType: 'binary',
  });
  return crypto.subtle.importKey('raw', toBuf(raw), { name: AES }, false, [
    'wrapKey',
    'unwrapKey',
  ]);
}

// PRF output (from WebAuthn, obtained on the main thread) → non-extractable KEK.
export async function kekFromPrf(prfFirst: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toBuf(prfFirst), { name: AES }, false, [
    'wrapKey',
    'unwrapKey',
  ]);
}

// ---- DEK lifecycle ----
async function generateDek(): Promise<CryptoKey> {
  // Extractable so it can be wrapped; it never leaves the worker.
  return crypto.subtle.generateKey({ name: AES, length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}

async function wrapDek(dek: CryptoKey, kek: CryptoKey): Promise<Envelope> {
  const iv = randomBytes(12);
  const wrapped = await crypto.subtle.wrapKey('raw', dek, kek, {
    name: AES,
    iv,
  });
  return { cipher: hex(new Uint8Array(wrapped)), iv: hex(iv) };
}

async function unwrapDek(env: Envelope, kek: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    'raw',
    toBuf(unhex(env.cipher)),
    kek,
    { name: AES, iv: bytes(unhex(env.iv)) },
    { name: AES, length: 256 },
    false, // DEK stays non-extractable after unlock
    ['encrypt', 'decrypt']
  );
}

// ---- Wallet key <-> envelope (encrypted by the DEK) ----
async function encryptWithDek(dek: CryptoKey, data: Uint8Array): Promise<Envelope> {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: AES, iv }, dek, toBuf(data));
  return { cipher: hex(new Uint8Array(cipher)), iv: hex(iv) };
}

async function decryptWithDek(dek: CryptoKey, env: Envelope): Promise<Uint8Array> {
  const plain = await crypto.subtle.decrypt(
    { name: AES, iv: bytes(unhex(env.iv)) },
    dek,
    toBuf(unhex(env.cipher))
  );
  return new Uint8Array(plain);
}

// ---- Ethereum address (EIP-55 checksummed) ----
export function addressFromPrivateKey(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false); // 65 bytes, 0x04 prefix
  const hash = keccak_256(pub.slice(1));
  const addr = bytesToHex(hash.slice(-20));
  return toChecksumAddress(addr);
}

function toChecksumAddress(addrLowerNo0x: string): string {
  const lower = addrLowerNo0x.toLowerCase();
  const h = bytesToHex(keccak_256(enc.encode(lower)));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

// ---- Signing (recoverable, Ethereum v = recovery + 27) ----
export function signDigest(priv: Uint8Array, digest: Uint8Array): EthSignature {
  if (digest.length !== 32) throw new Error('digest must be 32 bytes');
  const recovered = secp256k1.sign(digest, priv, {
    format: 'recovered',
    prehash: false,
  }); // 65 bytes: [recovery, r(32), s(32)]
  const recovery = recovered[0];
  const r = recovered.slice(1, 33);
  const s = recovered.slice(33, 65);
  const v = recovery + 27;
  return {
    signatureHex: '0x' + hex(r) + hex(s) + v.toString(16).padStart(2, '0'),
    r: '0x' + hex(r),
    s: '0x' + hex(s),
    v,
  };
}

// EIP-191 personal_sign digest.
export function personalSignDigest(message: string): Uint8Array {
  const msg = enc.encode(message);
  const prefix = enc.encode(`\x19Ethereum Signed Message:\n${msg.length}`);
  const joined = new Uint8Array(prefix.length + msg.length);
  joined.set(prefix);
  joined.set(msg, prefix.length);
  return keccak_256(joined);
}

// ---- High-level operations the worker exposes ----

export interface GenerateResult {
  pinSalt: string;
  pinEnvelope: Envelope;
  passkeyEnvelope: Envelope | null;
  walletEnvelope: Envelope;
  address: string;
  // The raw key is intentionally NOT part of this result.
  dek: CryptoKey;
  privateKey: Uint8Array;
}

export async function generateWallet(
  passcode: string,
  argon2: Argon2Params,
  prfFirst?: Uint8Array
): Promise<GenerateResult> {
  const dek = await generateDek();

  const salt = randomBytes(32);
  const pinKek = await deriveKekArgon2(passcode, salt, argon2);
  const pinEnvelope = await wrapDek(dek, pinKek);

  let passkeyEnvelope: Envelope | null = null;
  if (prfFirst) {
    const passkeyKek = await kekFromPrf(prfFirst);
    passkeyEnvelope = await wrapDek(dek, passkeyKek);
  }

  const privateKey = secp256k1.utils.randomSecretKey();
  const walletEnvelope = await encryptWithDek(dek, privateKey);
  const address = addressFromPrivateKey(privateKey);

  return {
    pinSalt: hex(salt),
    pinEnvelope,
    passkeyEnvelope,
    walletEnvelope,
    address,
    dek,
    privateKey,
  };
}

export async function unlockWithPin(
  passcode: string,
  pinSalt: string,
  pinEnvelope: Envelope,
  walletEnvelope: Envelope,
  argon2: Argon2Params
): Promise<{ dek: CryptoKey; privateKey: Uint8Array; address: string }> {
  const kek = await deriveKekArgon2(passcode, unhex(pinSalt), argon2);
  const dek = await unwrapDek(pinEnvelope, kek);
  const privateKey = await decryptWithDek(dek, walletEnvelope);
  return { dek, privateKey, address: addressFromPrivateKey(privateKey) };
}

export async function unlockWithPasskey(
  prfFirst: Uint8Array,
  passkeyEnvelope: Envelope,
  walletEnvelope: Envelope
): Promise<{ dek: CryptoKey; privateKey: Uint8Array; address: string }> {
  const kek = await kekFromPrf(prfFirst);
  const dek = await unwrapDek(passkeyEnvelope, kek);
  const privateKey = await decryptWithDek(dek, walletEnvelope);
  return { dek, privateKey, address: addressFromPrivateKey(privateKey) };
}

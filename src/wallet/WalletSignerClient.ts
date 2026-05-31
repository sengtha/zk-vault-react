// src/wallet/WalletSignerClient.ts
//
// Main-thread handle to the isolated signer worker. Provides a promise-based API
// and correlates requests/responses by id. The raw private key is never received
// here — only addresses and signatures cross back.

import {
  SignerRequest,
  SignerResponse,
  WalletVaultRecord,
  EthSignature,
  Argon2Params,
} from './messages';

type WithoutId<T> = T extends { id: number } ? Omit<T, 'id'> : never;

type Pending = {
  resolve: (value: SignerResponse) => void;
  reject: (reason: Error) => void;
};

export class WalletSignerClient {
  private worker: Worker;
  private seq = 0;
  private pending = new Map<number, Pending>();

  constructor() {
    // Bundler-friendly worker URL. Works with Vite, webpack 5, Next, etc.
    this.worker = new Worker(new URL('./signer.worker.ts', import.meta.url), {
      type: 'module',
    });
    this.worker.onmessage = (ev: MessageEvent<SignerResponse>) => {
      const res = ev.data;
      const entry = this.pending.get(res.id);
      if (!entry) return;
      this.pending.delete(res.id);
      if (res.ok) entry.resolve(res);
      else entry.reject(new Error(res.error));
    };
    this.worker.onerror = (ev) => {
      const err = new Error(ev.message || 'Signer worker error');
      for (const [, p] of this.pending) p.reject(err);
      this.pending.clear();
    };
  }

  private call(req: WithoutId<SignerRequest>): Promise<SignerResponse> {
    const id = ++this.seq;
    const full = { ...(req as object), id } as SignerRequest;
    return new Promise<SignerResponse>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage(full);
    });
  }

  async generate(
    passcode: string,
    opts?: { prfFirstHex?: string; passkeyId?: string; argon2?: Argon2Params }
  ): Promise<{ record: WalletVaultRecord; address: string }> {
    const res = await this.call({
      type: 'generate',
      passcode,
      prfFirstHex: opts?.prfFirstHex,
      passkeyId: opts?.passkeyId,
      argon2: opts?.argon2,
    });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'generate') throw new Error('Unexpected response');
    return { record: res.record, address: res.address };
  }

  async unlockWithPin(args: {
    passcode: string;
    pinSalt: string;
    pinEnvelope: string;
    walletEnvelope: string;
    argon2?: Argon2Params;
  }): Promise<string> {
    const res = await this.call({ type: 'unlockPin', ...args });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'unlockPin') throw new Error('Unexpected response');
    return res.address;
  }

  async unlockWithPasskey(args: {
    prfFirstHex: string;
    passkeyEnvelope: string;
    walletEnvelope: string;
  }): Promise<string> {
    const res = await this.call({ type: 'unlockPasskey', ...args });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'unlockPasskey') throw new Error('Unexpected response');
    return res.address;
  }

  async signDigest(digestHex: string): Promise<EthSignature> {
    const res = await this.call({ type: 'signDigest', digestHex });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'signDigest') throw new Error('Unexpected response');
    return res.signature;
  }

  async personalSign(message: string): Promise<EthSignature> {
    const res = await this.call({ type: 'personalSign', message });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'personalSign') throw new Error('Unexpected response');
    return res.signature;
  }

  async getAddress(): Promise<string | null> {
    const res = await this.call({ type: 'getAddress' });
    if (!res.ok) throw new Error(res.error);
    if (res.type !== 'getAddress') throw new Error('Unexpected response');
    return res.address;
  }

  async lock(): Promise<void> {
    await this.call({ type: 'lock' });
  }

  /** Wipes keys and tears down the worker. Call on logout/unmount. */
  destroy(): void {
    this.worker.terminate();
    for (const [, p] of this.pending) p.reject(new Error('Signer destroyed'));
    this.pending.clear();
  }
}

// src/components/VaultUnlock.tsx

import React, { useState, useEffect } from 'react';
import { useZkVault } from '../zk-vault/hooks';
import { Lock, Loader2, Fingerprint, Key, AlertCircle } from 'lucide-react';

interface VaultUnlockProps {
  userId: string;
  onSuccess?: () => void;
}

export default function VaultUnlock({ userId, onSuccess }: VaultUnlockProps) {
  const { unlockWithPin, unlockWithPasskey } = useZkVault();
  const [passcode, setPasscode] = useState('');
  
  const [isProcessingPasskey, setIsProcessingPasskey] = useState(false);
  const [isProcessingPin, setIsProcessingPin] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Rate Limiting State
  const [attempts, setAttempts] = useState(0);
  const [lockoutUntil, setLockoutUntil] = useState<number>(0);
  const [remainingLockout, setRemainingLockout] = useState(0);

  useEffect(() => {
    if (lockoutUntil <= 0) return;
    
    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.ceil((lockoutUntil - Date.now()) / 1000));
      setRemainingLockout(remaining);
      if (remaining <= 0) clearInterval(interval);
    }, 1000);
    
    return () => clearInterval(interval);
  }, [lockoutUntil]);

  const handlePasskeyUnlock = async () => {
    setIsProcessingPasskey(true);
    setError(null);
    
    const success = await unlockWithPasskey(userId);
    
    if (success) {
      if (onSuccess) onSuccess();
    } else {
      setError('Passkey authentication failed or cancelled.');
    }
    
    setIsProcessingPasskey(false);
  };

  const handlePinUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passcode.length < 8 || remainingLockout > 0) return;

    setIsProcessingPin(true);
    setError(null);
    
    const success = await unlockWithPin(passcode, userId);
    
    if (success) {
      setAttempts(0);
      if (onSuccess) onSuccess();
    } else {
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      setPasscode('');
      
      if (newAttempts >= 3) {
        // Exponential backoff: 1s, 2s, 4s, 8s... max 30s
        const backoffMs = Math.min(Math.pow(2, newAttempts - 3) * 1000, 30000);
        setLockoutUntil(Date.now() + backoffMs);
        setRemainingLockout(Math.ceil(backoffMs / 1000));
        setError(`Too many attempts. Try again in ${Math.ceil(backoffMs / 1000)}s.`);
      } else {
        setError('Incorrect Recovery Passcode.');
      }
    }
    
    setIsProcessingPin(false);
  };

  const isProcessing = isProcessingPasskey || isProcessingPin;
  const isLockedOut = remainingLockout > 0;

  return (
    <div className="max-w-md mx-auto p-8 bg-white border border-stone-200 rounded-3xl shadow-sm text-center">
      <div className="inline-flex w-16 h-16 bg-stone-100 text-stone-700 rounded-2xl items-center justify-center mb-6">
        <Lock size={32} />
      </div>
      
      <h2 className="text-2xl font-bold text-stone-900 mb-2">Vault Locked</h2>
      <p className="text-sm text-stone-500 mb-8 leading-relaxed max-w-xs mx-auto">
        Hardware decryption is required to access your end-to-end encrypted data.
      </p>

      <div className="space-y-6">
        <button
          onClick={handlePasskeyUnlock}
          disabled={isProcessing || isLockedOut}
          className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl flex items-center justify-center gap-3 transition-all disabled:opacity-50 shadow-sm shadow-indigo-600/20"
        >
          {isProcessingPasskey ? <Loader2 size={20} className="animate-spin" /> : <Fingerprint size={20} />}
          Unlock with FaceID / TouchID
        </button>

        <div className="flex items-center gap-4">
          <div className="h-px flex-1 bg-stone-100" />
          <span className="text-[10px] font-bold uppercase tracking-widest text-stone-400">OR USE PASSCODE</span>
          <div className="h-px flex-1 bg-stone-100" />
        </div>

        <form onSubmit={handlePinUnlock} className="space-y-4">
          <div className="relative">
            <input
              type="password"
              value={passcode}
              onChange={(e) => setPasscode(e.target.value)}
              placeholder="Enter recovery passcode"
              disabled={isProcessing || isLockedOut}
              className="w-full bg-stone-50 border border-stone-200 focus:border-stone-400 rounded-xl px-4 py-4 text-center text-lg focus:outline-none transition-all placeholder:text-sm disabled:opacity-50"
            />
            <Key size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-stone-400" />
          </div>

          {error && (
            <div className="flex items-center justify-center gap-1.5 text-red-500">
              <AlertCircle size={14} />
              <p className="text-xs font-bold uppercase tracking-wider">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={isProcessing || passcode.length < 8 || isLockedOut}
            className="w-full py-4 bg-stone-100 hover:bg-stone-200 text-stone-700 font-bold rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50"
          >
            {isProcessingPin ? <Loader2 size={20} className="animate-spin" /> : (
               isLockedOut ? `Locked out (${remainingLockout}s)` : 'Decrypt with Passcode'
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

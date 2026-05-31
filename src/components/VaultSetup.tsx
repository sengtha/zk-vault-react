// src/components/VaultSetup.tsx

import React, { useState } from 'react';
import { useZkVault } from '../zk-vault/hooks';
import { Shield, Loader2, Key, Fingerprint, ArrowRight } from 'lucide-react';

interface VaultSetupProps {
  userId: string;
  userEmail: string;
  onSuccess?: () => void;
}

export default function VaultSetup({ userId, userEmail, onSuccess }: VaultSetupProps) {
  const { setupVault } = useZkVault();
  const [pin, setPin] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (pin.length < 6) return;
    
    setIsProcessing(true);
    setError(null);
    
    // This generates the DEK, wraps it with the PIN, and automatically triggers
    // the WebAuthn Passkey prompt to wrap it a second time.
    const success = await setupVault(pin, userId, userEmail);
    
    if (success) {
      if (onSuccess) onSuccess();
    } else {
      setError('Failed to secure vault. Please try again.');
    }
    
    setIsProcessing(false);
  };

  return (
    <div className="max-w-md mx-auto p-8 bg-white border border-stone-200 rounded-3xl shadow-sm">
      <div className="text-center mb-8">
        <div className="inline-flex w-16 h-16 bg-indigo-50 text-indigo-600 rounded-2xl items-center justify-center mb-4">
          <Shield size={32} />
        </div>
        <h2 className="text-2xl font-bold text-stone-900 mb-2">Initialize Your Vault</h2>
        <p className="text-sm text-stone-500 leading-relaxed">
          Your vault is secured by two keys. First, create a recovery PIN. 
          Then, link this device's biometrics.
        </p>
      </div>

      <div className="space-y-4 mb-8">
        <div className="flex items-start gap-4 p-4 bg-stone-50 rounded-2xl border border-stone-100">
          <Key className="text-stone-400 shrink-0 mt-0.5" size={20} />
          <div>
            <p className="text-sm font-bold text-stone-900">1. Recovery PIN</p>
            <p className="text-xs text-stone-500 mt-1">Used to recover your data on new devices.</p>
          </div>
        </div>
        
        <div className="flex items-start gap-4 p-4 bg-indigo-50/50 rounded-2xl border border-indigo-100/50">
          <Fingerprint className="text-indigo-400 shrink-0 mt-0.5" size={20} />
          <div>
            <p className="text-sm font-bold text-stone-900">2. Hardware Passkey</p>
            <p className="text-xs text-stone-500 mt-1">You will be prompted to use FaceID or TouchID after submitting your PIN.</p>
          </div>
        </div>
      </div>

      <form onSubmit={handleSetup} className="space-y-4">
        <input
          type="password"
          maxLength={6}
          value={pin}
          onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))} // Restrict to numbers
          placeholder="Create 6-digit PIN"
          className="w-full bg-stone-50 border border-stone-200 focus:border-indigo-500 rounded-xl px-4 py-4 text-center text-xl tracking-[0.5em] focus:outline-none transition-all placeholder:tracking-normal placeholder:text-sm"
        />
        
        {error && <p className="text-xs text-red-500 font-bold uppercase tracking-wider text-center">{error}</p>}

        <button
          type="submit"
          disabled={isProcessing || pin.length < 6}
          className="w-full py-4 bg-stone-900 hover:bg-stone-800 text-white font-bold rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50"
        >
          {isProcessing ? <Loader2 size={20} className="animate-spin" /> : (
            <>Secure Vault & Link Device <ArrowRight size={18} /></>
          )}
        </button>
      </form>
    </div>
  );
}

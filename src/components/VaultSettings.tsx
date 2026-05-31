// src/components/VaultSettings.tsx

import React, { useState } from 'react';
import { useZkVault } from '../zk-vault/hooks';
import { Key, Fingerprint, ShieldAlert, Loader2, ChevronRight, X } from 'lucide-react';

interface VaultSettingsProps {
  userId: string;
  userEmail: string;
}

export default function VaultSettings({ userId, userEmail }: VaultSettingsProps) {
  const { isUnlocked, resetPin, resetPasskey } = useZkVault();
  
  const [isResettingPasskey, setIsResettingPasskey] = useState(false);
  const [showPinForm, setShowPinForm] = useState(false);
  const [newPin, setNewPin] = useState('');
  const [isSubmittingPin, setIsSubmittingPin] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

  // Safety check: Don't show these settings if the vault is currently locked.
  if (!isUnlocked) {
    return (
      <div className="p-6 bg-amber-50 border border-amber-200 rounded-3xl flex items-start gap-4">
        <ShieldAlert className="text-amber-500 shrink-0 mt-0.5" size={24} />
        <div>
          <p className="text-sm font-bold text-stone-900">Vault is Locked</p>
          <p className="text-sm text-stone-600 mt-1">
            You must unlock your vault before you can modify your hardware security credentials.
          </p>
        </div>
      </div>
    );
  }

  const handlePasskeyReset = async () => {
    setIsResettingPasskey(true);
    setMessage(null);
    try {
      const success = await resetPasskey(userId, userEmail);
      if (success) {
        setMessage({ type: 'success', text: 'Passkey updated successfully!' });
      } else {
        setMessage({ type: 'error', text: 'Failed to update Passkey.' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'An unexpected error occurred.' });
    } finally {
      setIsResettingPasskey(false);
    }
  };

  const handlePinSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPin.length < 6) return;
    
    setIsSubmittingPin(true);
    setMessage(null);
    try {
      const success = await resetPin(newPin, userId);
      if (success) {
        setMessage({ type: 'success', text: 'Recovery PIN updated successfully!' });
        setShowPinForm(false);
        setNewPin('');
      } else {
        setMessage({ type: 'error', text: 'Failed to update PIN.' });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'An unexpected error occurred.' });
    } finally {
      setIsSubmittingPin(false);
    }
  };

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div className="mb-8">
        <h3 className="text-lg font-bold text-stone-900 tracking-tight">Vault Security</h3>
        <p className="text-sm text-stone-500 mt-1">
          Manage your hardware-backed encryption credentials. 
        </p>
      </div>

      {message && (
        <div className={`p-4 rounded-xl text-sm font-bold ${message.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
          {message.text}
        </div>
      )}

      {/* Reset Passkey Action */}
      <div className="p-6 bg-white border border-stone-200 rounded-3xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all hover:border-indigo-200">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-indigo-50 rounded-2xl flex items-center justify-center text-indigo-600">
            <Fingerprint size={24} />
          </div>
          <div>
            <p className="text-sm font-bold text-stone-900">Update Passkey</p>
            <p className="text-xs text-stone-500 mt-0.5 max-w-[250px] leading-relaxed">
              Replace your current hardware passkey with a new one from this device.
            </p>
          </div>
        </div>
        <button
          onClick={handlePasskeyReset}
          disabled={isResettingPasskey}
          className="shrink-0 px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold uppercase tracking-wider rounded-xl transition-all disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {isResettingPasskey ? <Loader2 size={16} className="animate-spin" /> : 'Register New'}
        </button>
      </div>

      {/* Reset PIN Action */}
      <div className="p-6 bg-white border border-stone-200 rounded-3xl transition-all hover:border-stone-300">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-stone-100 rounded-2xl flex items-center justify-center text-stone-600">
              <Key size={24} />
            </div>
            <div>
              <p className="text-sm font-bold text-stone-900">Change Recovery PIN</p>
              <p className="text-xs text-stone-500 mt-0.5 max-w-[250px] leading-relaxed">
                Update the 6-digit fallback PIN used to decrypt your vault if your passkey is lost.
              </p>
            </div>
          </div>
          
          {!showPinForm && (
            <button
              onClick={() => setShowPinForm(true)}
              className="shrink-0 px-6 py-3 bg-stone-100 hover:bg-stone-200 text-stone-700 text-xs font-bold uppercase tracking-wider rounded-xl transition-all"
            >
              Change PIN
            </button>
          )}
        </div>

        {/* Expandable PIN Form */}
        {showPinForm && (
          <div className="pt-6 mt-6 border-t border-stone-100 animate-in fade-in slide-in-from-top-4">
            <form onSubmit={handlePinSubmit} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1 max-w-xs">
                <input 
                  type="password" 
                  maxLength={6}
                  value={newPin}
                  onChange={(e) => setNewPin(e.target.value.replace(/\D/g, ''))}
                  placeholder="Enter new 6-digit PIN"
                  className="w-full bg-stone-50 border border-stone-200 focus:border-stone-400 rounded-xl px-4 py-3 text-center text-lg tracking-[0.5em] focus:outline-none transition-all placeholder:tracking-normal placeholder:text-sm"
                />
              </div>
              
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowPinForm(false);
                    setNewPin('');
                  }}
                  className="px-4 py-3 bg-stone-100 hover:bg-stone-200 text-stone-500 rounded-xl transition-all flex items-center justify-center"
                >
                  <X size={20} />
                </button>
                <button 
                  type="submit"
                  disabled={isSubmittingPin || newPin.length < 6}
                  className="px-6 py-3 bg-stone-900 hover:bg-stone-800 text-white font-bold rounded-xl flex items-center justify-center gap-2 transition-all disabled:opacity-50"
                >
                  {isSubmittingPin ? <Loader2 size={18} className="animate-spin" /> : (
                    <>Save PIN <ChevronRight size={18} /></>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}

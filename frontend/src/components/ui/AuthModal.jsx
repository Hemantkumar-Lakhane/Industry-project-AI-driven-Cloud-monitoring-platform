import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import LoginPage from '../LoginPage';
import './AuthModal.css';

export default function AuthModal({ isOpen, onClose, onLogin }) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="auth-modal-backdrop" onClick={onClose}>
      <div className="auth-modal-card" onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          className="auth-modal-close"
          onClick={onClose}
          aria-label="Close modal"
        >
          <X size={18} />
        </button>
        <LoginPage onLogin={onLogin} />
      </div>
    </div>
  );
}

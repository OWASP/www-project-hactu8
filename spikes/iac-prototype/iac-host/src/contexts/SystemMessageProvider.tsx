// src/contexts/SystemMessageProvider.tsx
import React, { useState, useCallback, useEffect } from 'react';
import { getEffectiveConfig } from '../config/environmentConfig';
import { SystemMessageContext } from './SystemMessageContext';
import type { MessageType, SystemMessage } from './SystemMessageContext';

export const SystemMessageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Initialize with environment message if configured
  const envConfig = getEffectiveConfig();
  const initialMessage: SystemMessage = envConfig.showOnLoad ? {
    text: envConfig.message,
    type: envConfig.messageType,
    timestamp: Date.now(),
    duration: 0, // Persist environment message
  } : {
    text: '',
    type: 'info',
    timestamp: Date.now(),
    duration: 0,
  };

  const [currentMessage, setCurrentMessage] = useState<SystemMessage>(initialMessage);

  const setMessage = useCallback((text: string, type: MessageType = 'info', duration: number = 0) => {
    setCurrentMessage({
      text,
      type,
      timestamp: Date.now(),
      duration,
    });
  }, []);

  const clearMessage = useCallback(() => {
    setCurrentMessage({
      text: '',
      type: 'info',
      timestamp: Date.now(),
      duration: 0,
    });
  }, []);

  const showInfo = useCallback((text: string, duration: number = 5000) => {
    setMessage(text, 'info', duration);
  }, [setMessage]);

  const showWarning = useCallback((text: string, duration: number = 8000) => {
    setMessage(text, 'warning', duration);
  }, [setMessage]);

  const showError = useCallback((text: string, duration: number = 10000) => {
    setMessage(text, 'error', duration);
  }, [setMessage]);

  const showSuccess = useCallback((text: string, duration: number = 5000) => {
    setMessage(text, 'success', duration);
  }, [setMessage]);

  // Auto-clear messages after duration
  useEffect(() => {
    if (currentMessage.duration && currentMessage.duration > 0 && currentMessage.text) {
      const timer = setTimeout(() => {
        clearMessage();
      }, currentMessage.duration);

      return () => clearTimeout(timer);
    }
  }, [currentMessage, clearMessage]);

  return (
    <SystemMessageContext.Provider
      value={{
        message: currentMessage.text,
        messageType: currentMessage.type,
        setMessage,
        clearMessage,
        showInfo,
        showWarning,
        showError,
        showSuccess,
      }}
    >
      {children}
    </SystemMessageContext.Provider>
  );
};

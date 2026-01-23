// src/contexts/SystemMessageContext.tsx
import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { getEffectiveConfig } from '../config/environmentConfig';

export type MessageType = 'info' | 'warning' | 'error' | 'success';

interface SystemMessage {
  text: string;
  type: MessageType;
  timestamp: number;
  duration?: number; // Auto-clear after duration (ms), 0 = persist
}

interface SystemMessageContextType {
  message: string;
  messageType: MessageType;
  setMessage: (text: string, type?: MessageType, duration?: number) => void;
  clearMessage: () => void;
  showInfo: (text: string, duration?: number) => void;
  showWarning: (text: string, duration?: number) => void;
  showError: (text: string, duration?: number) => void;
  showSuccess: (text: string, duration?: number) => void;
}

const SystemMessageContext = createContext<SystemMessageContextType | undefined>(undefined);

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

export const useSystemMessage = (): SystemMessageContextType => {
  const context = useContext(SystemMessageContext);
  if (!context) {
    throw new Error('useSystemMessage must be used within a SystemMessageProvider');
  }
  return context;
};

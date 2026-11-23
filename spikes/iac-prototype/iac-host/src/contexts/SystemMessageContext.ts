// src/contexts/SystemMessageContext.ts
import { createContext, useContext } from 'react';

export type MessageType = 'info' | 'warning' | 'error' | 'success';

export interface SystemMessage {
  text: string;
  type: MessageType;
  timestamp: number;
  duration?: number; // Auto-clear after duration (ms), 0 = persist
}

export interface SystemMessageContextType {
  message: string;
  messageType: MessageType;
  setMessage: (text: string, type?: MessageType, duration?: number) => void;
  clearMessage: () => void;
  showInfo: (text: string, duration?: number) => void;
  showWarning: (text: string, duration?: number) => void;
  showError: (text: string, duration?: number) => void;
  showSuccess: (text: string, duration?: number) => void;
}

export const SystemMessageContext = createContext<SystemMessageContextType | undefined>(undefined);

export const useSystemMessage = (): SystemMessageContextType => {
  const context = useContext(SystemMessageContext);
  if (!context) {
    throw new Error('useSystemMessage must be used within a SystemMessageProvider');
  }
  return context;
};

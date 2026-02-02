declare module 'react-markdown' {
  import type { ComponentType } from 'react';

  const ReactMarkdown: ComponentType<{ children?: string } & Record<string, unknown>>;
  export default ReactMarkdown;
}
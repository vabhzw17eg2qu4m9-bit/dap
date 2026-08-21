/**
 * oh-my-pi ExtensionAPI surface used by this extension
 * (shape per docs/research.md, "pi/omp" row).
 */
export interface ToolDefinition {
  name: string;
  description: string;
  /** JSON Schema for the tool arguments. */
  parameters?: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface SendMessageOptions {
  /** steer injects into the live turn and wakes an idle one. */
  type?: 'steer' | 'followUp' | 'triggerTurn';
}

export interface ExtensionAPI {
  registerTool(tool: ToolDefinition): void;
  sendMessage(message: string, opts?: SendMessageOptions): void;
  /** Durable state: append-only entries the harness persists. */
  appendEntry(entry: unknown): void;
  setInterval?(fn: () => void, ms: number): unknown;
  clearInterval?(handle: unknown): void;
}

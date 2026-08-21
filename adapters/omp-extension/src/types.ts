/**
 * oh-my-pi ExtensionAPI surface used by this extension
 * (verified against omp's own extensions documentation).
 */

/** Per-session context handed to event handlers. */
export interface SessionCtx {
  ui?: { notify(text: string, level?: string): void };
  hasUI: boolean;
  isIdle(): boolean;
  /** Managed, error-isolated timers (unlike raw timers). */
  setInterval(fn: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
}

export interface SendMessageOptions {
  /** steer injects into the live turn; triggerTurn starts a turn when idle. */
  deliverAs?: 'steer' | 'followUp' | 'nextTurn';
  triggerTurn?: boolean;
}

export interface AgentToolResult {
  content: Array<{ type: 'text'; text: string }>;
  details?: unknown;
}

export interface ToolDefinition {
  name: string;
  label?: string;
  description: string;
  /** Plain JSON Schema ({type:'object', properties, required}). */
  parameters: Record<string, unknown>;
  execute: (
    toolCallId: string,
    params: Record<string, unknown>,
    signal?: unknown,
    onUpdate?: unknown,
    ctx?: unknown,
  ) => Promise<AgentToolResult>;
}

export interface ExtensionAPI {
  sendMessage(message: string, opts?: SendMessageOptions): void;
  /** Durable state: append-only entries the harness persists
   *  (customType is a namespaced string, e.g. 'io.dap.message'). */
  appendEntry(customType: string, data: unknown): void;
  on(event: string, handler: (event: unknown, ctx: SessionCtx) => void | Promise<void>): void;
  registerTool(def: ToolDefinition): void;
  /** Extension label shown in the UI. */
  setLabel(label: string): void;
}

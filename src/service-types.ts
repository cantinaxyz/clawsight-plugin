/**
 * @module service-types
 * @description Core TypeScript type definitions for the ClawSight plugin.
 *
 * Defines the shared contracts used across all modules:
 * - {@link ClawsightPluginConfig} — resolved plugin configuration
 * - {@link TelemetryEnvelope} — schema for all telemetry events sent to the SIEM
 * - {@link ToolDecision} / {@link MessageDecision} / {@link IntentDecision} — policy decision types
 * - {@link ClawsightRuntime} — the unified runtime interface produced by all modes
 *
 * These types are the API boundary between the plugin entry (index.ts), the service
 * layer (service.ts), the local policy engine, and the platform client.
 */

/** Operating mode. "off" disables entirely, "audit" logs only, "enforce" blocks, "local" uses on-disk rules. */
export type ClawsightMode = "off" | "audit" | "enforce" | "local";

export type ClawsightCaptureConfig = {
  messages: boolean;
  messageBody: boolean;
  tools: boolean;
  toolParams: boolean;
  toolResult: boolean;
  diagnostics: boolean;
  logs: boolean;
};

export type ClawsightNetworkConfig = {
  timeoutMs: number;
};

export type ClawsightTelemetrySeverity = "trace" | "debug" | "info" | "warn" | "error";

export type ClawsightPluginConfig = {
  enabled: boolean;
  mode: ClawsightMode;
  platformUrl: string;
  localRulesPath?: string;
  apiToken?: string;
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  identityPath?: string;
  ingestPath: string;
  decidePath: string;
  paymentsSendPath: string;
  flushIntervalMs: number;
  batchMaxEvents: number;
  capture: ClawsightCaptureConfig;
  network: ClawsightNetworkConfig;
};

export type TelemetryEnvelope = {
  eventId: string;
  ts: number;
  severity: ClawsightTelemetrySeverity;
  category:
    | "agent"
    | "message"
    | "tool"
    | "session"
    | "gateway"
    | "diagnostic"
    | "log"
    | "policy"
    | "payment";
  action: string;
  openclaw?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    messageProvider?: string;
    toolName?: string;
    toolCallId?: string;
    gatewayPort?: number;
  };
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  payload?: unknown;
  requestId?: string;
  correlationId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  result?: "ok" | "blocked" | "modified" | "error";
  outcome?: "allow" | "warn" | "block" | "modify" | "error" | "unknown";
  outcomeReason?: string;
  policyRuleId?: string;
  policyDecisionId?: string;
  durationMs?: number;
  latencyMs?: number;
  errorClass?: string;
  errorCode?: string;
  toolExitCode?: number;
  schemaVersion?: number;
  policyDecision?: {
    requestId?: string;
    decisionId?: string;
    action?: "allow" | "warn" | "block" | "modify";
    reason?: string;
    latencyMs?: number;
    ruleId?: string;
  };
};

/** Request payload sent to the policy engine for a tool call decision. */
export type ToolDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  toolName: string;
  params: Record<string, unknown>;
  requestId?: string;
  traceId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  parentSpanId?: string;
};

/**
 * Policy decision returned by the tool call guardrail.
 * - "allow" — tool executes normally
 * - "warn" — logged, tool executes (audit behavior)
 * - "block" — tool prevented, reason returned to LLM
 * - "modify" — tool params altered before execution (platform mode)
 * - "confirm" — tool blocked pending user approval via /cs approve (local mode)
 */
export type ToolDecision =
  | { action: "allow"; decisionId?: string; ruleId?: string }
  | { action: "warn"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "block"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "modify"; params: Record<string, unknown>; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "confirm"; reason?: string; decisionId?: string; ruleId?: string };

/** Request payload sent to the policy engine for an outbound message decision. */
export type MessageDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  channelId: string;
  accountId?: string;
  sessionId?: string;
  sessionKey?: string;
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
};

/** Policy decision returned by the outbound message guardrail. */
export type MessageDecision =
  | { action: "allow"; decisionId?: string; ruleId?: string }
  | { action: "warn"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "block"; reason?: string; decisionId?: string; ruleId?: string }
  | { action: "modify"; content: string; reason?: string; decisionId?: string; ruleId?: string };

/** Request payload for evaluating an incoming user message (platform mode only). */
export type InboundMessageDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  channelId: string;
  accountId?: string;
  conversationId?: string;
  from: string;
  content: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
  sessionKey?: string;
};

/** Decision returned for an inbound user message. "hard" enforcement blocks the message; "advisory" logs only. */
export type InboundMessageDecision = {
  action: "allow" | "block";
  enforcement?: "advisory" | "hard";
  decisionId?: string;
  ruleId?: string;
  reason?: string;
  signals?: string[];
};

export type IntentDecisionAction = "allow" | "warn" | "block" | "modify";

/** Request to establish the intent baseline from the LLM prompt and history (platform mode). */
export type IntentBaselineDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  sessionKey?: string;
  runId?: string;
  sourceType?: string;
  prompt?: string;
  systemPrompt?: string;
  historyMessages?: string[];
  provider?: string;
  model?: string;
};

/** Request to check a tool call against the established intent baseline (platform mode). */
export type IntentActionDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  sessionKey?: string;
  runId?: string;
  toolName: string;
  params: Record<string, unknown>;
};

/** Request to analyze tool output for suspicious content (platform mode). */
export type IntentOutputDecisionRequest = {
  projectId?: string;
  agentInstanceId?: string;
  agentName?: string;
  managedAgentKey?: string;
  requestId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  traceId?: string;
  spanId?: string;
  sessionKey?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
  content: string;
  isSynthetic?: boolean;
};

/** LLM-powered intent analysis result from the platform. Includes drift scoring and signal detection. */
export type IntentDecision = {
  action: IntentDecisionAction;
  mode?: "off" | "audit" | "enforce";
  reason?: string;
  decisionId?: string;
  scoreDelta?: number;
  driftScore?: number;
  confidence?: number;
  signals?: string[];
  targetDomains?: string[];
  expectedDomains?: string[];
  expectedScopes?: string[];
  sanitizedContent?: string;
};

export type PaymentsSendRequest = {
  chain?: string;
  asset?: string;
  toAddress: string;
  amount: string;
  memo?: string;
  idempotencyKey?: string;
};

export type PaymentsSendResponse = {
  status: "submitted" | "blocked" | "error";
  txId?: string;
  decisionId?: string;
  reason?: string;
};

/**
 * Unified runtime interface produced by all operating modes.
 *
 * Hook handlers call methods like `rt.decideToolCall()` without knowing whether
 * the decision comes from local rules (in-process) or the remote platform (HTTP).
 * In local mode, intent methods return null; in platform mode, they proxy to the SIEM.
 */
export type ClawsightRuntime = {
  config: ClawsightPluginConfig;
  emit: (evt: Omit<TelemetryEnvelope, "eventId" | "ts"> & { eventId?: string; ts?: number }) => void;
  decideToolCall: (req: ToolDecisionRequest) => Promise<ToolDecision | null>;
  decideOutboundMessage: (req: MessageDecisionRequest) => Promise<MessageDecision | null>;
  decideInboundMessage: (req: InboundMessageDecisionRequest) => Promise<InboundMessageDecision | null>;
  decideIntentBaseline: (req: IntentBaselineDecisionRequest) => Promise<IntentDecision | null>;
  decideIntentAction: (req: IntentActionDecisionRequest) => Promise<IntentDecision | null>;
  decideIntentOutput: (req: IntentOutputDecisionRequest) => Promise<IntentDecision | null>;
  paymentsSend: (req: PaymentsSendRequest) => Promise<PaymentsSendResponse>;
  stop: () => Promise<void>;
};

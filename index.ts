/**
 * @module index
 * @description ClawSight plugin entry point — registers all hooks, commands, and the service.
 *
 * This is the main file loaded by OpenClaw's plugin system. It:
 *
 * 1. **Registers the service** ({@link createClawsightService}) which manages the runtime lifecycle.
 * 2. **Instantiates the approval manager** for human-in-the-loop confirm rules.
 * 3. **Wires 20+ hook handlers** to OpenClaw's event system:
 *    - `before_tool_call` — policy evaluation, approval flow, intent action check
 *    - `message_sending` — outbound message policy + deterministic output enforcement
 *    - `tool_result_persist`, `message_received`, `message_sent` — telemetry
 *    - `llm_input`, `llm_output` — intent baseline tracking
 *    - `before_agent_start`, `before_prompt_build` — security directive injection
 *    - Session/gateway lifecycle hooks — tracing and telemetry
 * 4. **Registers the /cs command** for interactive rule management via chat.
 * 5. **Manages distributed trace context** across sessions, runs, and tool calls.
 *
 * All hook handlers follow the pattern: get runtime → emit telemetry → evaluate policy → return decision.
 * If the runtime is null (plugin disabled or not yet started), hooks return immediately (no-op).
 */
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import crypto from "node:crypto";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { getRuntime } from "./src/runtime.js";
import { redactHookEventForTelemetry } from "./src/telemetry/redact.js";
import { createClawsightService, localRuleStoreRef } from "./src/service.js";
import type { ClawsightRuntime } from "./src/service-types.js";
import { buildSystemDirectives, buildSecurityDirectives } from "./src/local/prompt-directives.js";

import { ApprovalManager } from "./src/local/approval-manager.js";

type RuntimeEmitEvent = Parameters<ClawsightRuntime["emit"]>[0];
type TraceContext = {
  traceId: string;
  runId?: string;
  sessionKey?: string;
  sessionId?: string;
  rootExecutionId?: string;
  rootMessageId?: string;
  lastSpanId?: string;
  updatedAt: number;
};
type ParentSpanRef = {
  spanId: string;
  traceId: string;
  updatedAt: number;
};
type InboundAnchor = {
  trace: TraceContext;
  channelId?: string;
  conversationId?: string;
  createdAt: number;
};

function compactText(value: unknown, max = 280): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) {
    return undefined;
  }
  if (normalized.length <= max) {
    return normalized;
  }
  return `${normalized.slice(0, max)}…`;
}

function stableJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value ?? "");
  }
}

function extractHistorySnippets(value: unknown, maxItems = 8): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .slice(-maxItems)
    .map((entry) => compactText(typeof entry === "string" ? entry : stableJson(entry), 320))
    .filter((entry): entry is string => Boolean(entry));
}

const plugin = {
  id: "clawsight",
  name: "ClawSight",
  description: "Telemetry + guardrails exporter (no OpenClaw source changes required).",
  // NOTE: OpenClaw uses openclaw.plugin.json for config validation. This runtime schema is best-effort.
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    // Services run once per gateway boot and can subscribe to global event sources.
    api.registerService(
      createClawsightService({
        pluginConfig: api.pluginConfig ?? {},
        runtime: api.runtime,
      }),
    );

    const approvalManager = new ApprovalManager();

    const traceBySession = new Map<string, TraceContext>();
    const traceByRun = new Map<string, TraceContext>();
    const traceByRequest = new Map<string, TraceContext>();
    const traceByToolCall = new Map<string, TraceContext>();
    const traceByRootExecution = new Map<string, TraceContext>();
    const traceByRootMessage = new Map<string, TraceContext>();
    const recentTraceByToolName = new Map<string, TraceContext>();
    const parentSpanByRequest = new Map<string, ParentSpanRef>();
    const parentSpanByToolCall = new Map<string, ParentSpanRef>();
    const pendingInboundAnchors: InboundAnchor[] = [];
    const TRACE_TTL_MS = 30 * 60 * 1000;
    const TOOL_RECENT_TTL_MS = 60 * 1000;
    const INBOUND_ANCHOR_TTL_MS = 2 * 60 * 1000;
    const MAX_CACHE_SIZE = 4096;

    function safeKey(value?: string): string | undefined {
      const raw = value?.trim();
      return raw && raw.length > 0 ? raw : undefined;
    }

    function safeSegment(value?: string): string | undefined {
      const raw = safeKey(value);
      if (!raw) return undefined;
      const normalized = raw.toLowerCase().replace(/[^a-z0-9._:@-]+/g, "_").slice(0, 120);
      return normalized || undefined;
    }

    function isExpired(ctx: TraceContext, ttl = TRACE_TTL_MS): boolean {
      return Date.now() - ctx.updatedAt > ttl;
    }

    function isParentRefExpired(ref: ParentSpanRef): boolean {
      return Date.now() - ref.updatedAt > TRACE_TTL_MS;
    }

    function deriveRootExecutionId(params: {
      rootExecutionId?: string;
      rootMessageId?: string;
      channelId?: string;
      conversationId?: string;
    }): string | undefined {
      const explicit = safeKey(params.rootExecutionId);
      if (explicit) return explicit;
      const rootMessageId = safeKey(params.rootMessageId);
      if (!rootMessageId) return undefined;
      const channel = safeSegment(params.channelId) ?? "channel";
      const conversation = safeSegment(params.conversationId) ?? "conversation";
      return `msg:${channel}:${conversation}:${rootMessageId}`;
    }

    function toMessageId(value: unknown): string | undefined {
      if (typeof value === "string") {
        const trimmed = value.trim();
        return trimmed.length > 0 ? trimmed : undefined;
      }
      if (typeof value === "number" && Number.isFinite(value)) {
        return String(Math.trunc(value));
      }
      return undefined;
    }

    function extractRootMessageId(metadata: unknown): string | undefined {
      if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
        return undefined;
      }
      const rec = metadata as Record<string, unknown>;
      const direct = [
        rec.rootMessageId,
        rec.root_message_id,
        rec.messageId,
        rec.message_id,
        rec.id,
      ];
      for (const candidate of direct) {
        const value = toMessageId(candidate);
        if (value) return value;
      }

      const nested = rec.message;
      if (nested && typeof nested === "object" && !Array.isArray(nested)) {
        const nestedRec = nested as Record<string, unknown>;
        const nestedCandidates = [
          nestedRec.rootMessageId,
          nestedRec.root_message_id,
          nestedRec.messageId,
          nestedRec.message_id,
          nestedRec.id,
        ];
        for (const candidate of nestedCandidates) {
          const value = toMessageId(candidate);
          if (value) return value;
        }
      }
      return undefined;
    }

    function cleanupTraceCaches() {
      const now = Date.now();
      if (
        traceBySession.size < MAX_CACHE_SIZE &&
        traceByRun.size < MAX_CACHE_SIZE &&
        traceByRequest.size < MAX_CACHE_SIZE &&
        traceByToolCall.size < MAX_CACHE_SIZE &&
        traceByRootExecution.size < MAX_CACHE_SIZE &&
        traceByRootMessage.size < MAX_CACHE_SIZE &&
        recentTraceByToolName.size < MAX_CACHE_SIZE &&
        pendingInboundAnchors.length < MAX_CACHE_SIZE
      ) {
        if (
          parentSpanByRequest.size < MAX_CACHE_SIZE * 2 &&
          parentSpanByToolCall.size < MAX_CACHE_SIZE * 2
        ) {
          return;
        }
      }
      for (const [key, ctx] of traceBySession) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceBySession.delete(key);
      }
      for (const [key, ctx] of traceByRun) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceByRun.delete(key);
      }
      for (const [key, ctx] of traceByRequest) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceByRequest.delete(key);
      }
      for (const [key, ctx] of traceByToolCall) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceByToolCall.delete(key);
      }
      for (const [key, ctx] of traceByRootExecution) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceByRootExecution.delete(key);
      }
      for (const [key, ctx] of traceByRootMessage) {
        if (now - ctx.updatedAt > TRACE_TTL_MS) traceByRootMessage.delete(key);
      }
      for (const [key, ctx] of recentTraceByToolName) {
        if (now - ctx.updatedAt > TOOL_RECENT_TTL_MS) recentTraceByToolName.delete(key);
      }
      for (const [key, ref] of parentSpanByRequest) {
        if (now - ref.updatedAt > TRACE_TTL_MS) parentSpanByRequest.delete(key);
      }
      for (const [key, ref] of parentSpanByToolCall) {
        if (now - ref.updatedAt > TRACE_TTL_MS) parentSpanByToolCall.delete(key);
      }
      for (let i = pendingInboundAnchors.length - 1; i >= 0; i -= 1) {
        const anchor = pendingInboundAnchors[i];
        const expired =
          now - anchor.createdAt > INBOUND_ANCHOR_TTL_MS || now - anchor.trace.updatedAt > TRACE_TTL_MS;
        if (expired) {
          pendingInboundAnchors.splice(i, 1);
        }
      }
      if (pendingInboundAnchors.length > MAX_CACHE_SIZE) {
        pendingInboundAnchors.splice(0, pendingInboundAnchors.length - MAX_CACHE_SIZE);
      }
    }

    function rememberInboundAnchor(
      trace: TraceContext,
      params: { channelId?: string; conversationId?: string },
    ) {
      const channelId = safeSegment(params.channelId);
      const conversationId = safeSegment(params.conversationId);
      pendingInboundAnchors.push({
        trace,
        channelId,
        conversationId,
        createdAt: Date.now(),
      });
      cleanupTraceCaches();
    }

    function claimInboundAnchor(params: {
      channelId?: string;
      conversationId?: string;
    }): TraceContext | undefined {
      cleanupTraceCaches();
      if (pendingInboundAnchors.length === 0) {
        return undefined;
      }

      const channelId = safeSegment(params.channelId);
      const conversationId = safeSegment(params.conversationId);
      let index = -1;

      if (conversationId) {
        index = pendingInboundAnchors.findIndex(
          (entry) =>
            entry.conversationId === conversationId && (!channelId || entry.channelId === channelId),
        );
      }
      if (index === -1 && channelId) {
        index = pendingInboundAnchors.findIndex((entry) => entry.channelId === channelId);
      }
      if (index === -1) {
        index = 0;
      }

      const [claimed] = pendingInboundAnchors.splice(index, 1);
      if (!claimed || isExpired(claimed.trace)) {
        return undefined;
      }
      claimed.trace.updatedAt = Date.now();
      return claimed.trace;
    }

    function indexTraceContext(
      ctx: TraceContext,
      keys: {
        runId?: string;
        sessionKey?: string;
        sessionId?: string;
        requestId?: string;
        toolCallId?: string;
        toolName?: string;
        rootExecutionId?: string;
        rootMessageId?: string;
      },
    ) {
      ctx.updatedAt = Date.now();
      if (keys.runId) {
        ctx.runId = keys.runId;
        traceByRun.set(keys.runId, ctx);
      }
      if (keys.sessionKey) {
        ctx.sessionKey = keys.sessionKey;
        traceBySession.set(keys.sessionKey, ctx);
      }
      if (keys.sessionId) {
        ctx.sessionId = keys.sessionId;
        traceBySession.set(keys.sessionId, ctx);
      }
      if (keys.requestId) {
        traceByRequest.set(keys.requestId, ctx);
      }
      if (keys.toolCallId) {
        traceByToolCall.set(keys.toolCallId, ctx);
      }
      if (keys.toolName) {
        recentTraceByToolName.set(keys.toolName.toLowerCase(), ctx);
      }
      if (keys.rootExecutionId) {
        ctx.rootExecutionId = keys.rootExecutionId;
        traceByRootExecution.set(keys.rootExecutionId, ctx);
      }
      if (keys.rootMessageId) {
        ctx.rootMessageId = keys.rootMessageId;
        traceByRootMessage.set(keys.rootMessageId, ctx);
      }
    }

    function resolveTraceContext(params: {
      runId?: string;
      sessionKey?: string;
      sessionId?: string;
      requestId?: string;
      toolCallId?: string;
      toolName?: string;
      rootExecutionId?: string;
      rootMessageId?: string;
      channelId?: string;
      conversationId?: string;
      allowCreate?: boolean;
    }): TraceContext | null {
      cleanupTraceCaches();

      const runId = safeKey(params.runId);
      const sessionKey = safeKey(params.sessionKey);
      const sessionId = safeKey(params.sessionId);
      const requestId = safeKey(params.requestId);
      const toolCallId = safeKey(params.toolCallId);
      const toolName = safeKey(params.toolName)?.toLowerCase();
      const rootExecutionId = safeKey(params.rootExecutionId);
      const rootMessageId = safeKey(params.rootMessageId);
      const channelId = safeKey(params.channelId);
      const conversationId = safeKey(params.conversationId);

      const rootExecutionCandidate =
        rootExecutionId != null ? traceByRootExecution.get(rootExecutionId) : undefined;
      if (rootExecutionCandidate && !isExpired(rootExecutionCandidate)) {
        indexTraceContext(rootExecutionCandidate, {
          runId,
          sessionKey,
          sessionId,
          requestId,
          toolCallId,
          toolName,
          rootExecutionId,
          rootMessageId,
        });
        return rootExecutionCandidate;
      }

      const rootMessageCandidate =
        rootMessageId != null ? traceByRootMessage.get(rootMessageId) : undefined;
      if (rootMessageCandidate && !isExpired(rootMessageCandidate)) {
        indexTraceContext(rootMessageCandidate, {
          runId,
          sessionKey,
          sessionId,
          requestId,
          toolCallId,
          toolName,
          rootExecutionId,
          rootMessageId,
        });
        return rootMessageCandidate;
      }

      if ((rootExecutionId || rootMessageId) && params.allowCreate) {
        const createdFromRoot: TraceContext = {
          traceId: rootExecutionId || `msg:${rootMessageId}`,
          runId,
          sessionKey,
          sessionId,
          rootExecutionId,
          rootMessageId,
          updatedAt: Date.now(),
        };
        indexTraceContext(createdFromRoot, {
          runId,
          sessionKey,
          sessionId,
          requestId,
          toolCallId,
          toolName,
          rootExecutionId,
          rootMessageId,
        });
        return createdFromRoot;
      }

      if (params.allowCreate) {
        const claimed = claimInboundAnchor({ channelId, conversationId });
        if (claimed) {
          indexTraceContext(claimed, {
            runId,
            sessionKey,
            sessionId,
            requestId,
            toolCallId,
            toolName,
            rootExecutionId: rootExecutionId || claimed.rootExecutionId,
            rootMessageId: rootMessageId || claimed.rootMessageId,
          });
          return claimed;
        }
      }

      const candidates = [
        runId ? traceByRun.get(runId) : undefined,
        toolCallId ? traceByToolCall.get(toolCallId) : undefined,
        requestId ? traceByRequest.get(requestId) : undefined,
        sessionKey ? traceBySession.get(sessionKey) : undefined,
        sessionId ? traceBySession.get(sessionId) : undefined,
        toolName ? recentTraceByToolName.get(toolName) : undefined,
      ];
      const resolved = candidates.find((candidate) => {
        if (!candidate) return false;
        const ttl = candidate === recentTraceByToolName.get(toolName ?? "") ? TOOL_RECENT_TTL_MS : TRACE_TTL_MS;
        return !isExpired(candidate, ttl);
      });

      if (resolved) {
        indexTraceContext(resolved, {
          runId,
          sessionKey,
          sessionId,
          requestId,
          toolCallId,
          toolName,
          rootExecutionId,
          rootMessageId,
        });
        return resolved;
      }

      if (!params.allowCreate) {
        return null;
      }

      if (!runId && !sessionKey && !sessionId && !rootExecutionId) {
        return null;
      }

      const created: TraceContext = {
        traceId: runId || rootExecutionId || crypto.randomUUID(),
        runId,
        sessionKey,
        sessionId,
        rootExecutionId,
        rootMessageId,
        updatedAt: Date.now(),
      };
      indexTraceContext(created, {
        runId,
        sessionKey,
        sessionId,
        requestId,
        toolCallId,
        toolName,
        rootExecutionId,
        rootMessageId,
      });
      return created;
    }

    function closeTrace(sessionKey?: string, runId?: string) {
      const ctx =
        (runId ? traceByRun.get(runId) : undefined) ||
        (sessionKey ? traceBySession.get(sessionKey) : undefined);
      if (!ctx) return;
      for (const [key, value] of traceBySession) {
        if (value.traceId === ctx.traceId) traceBySession.delete(key);
      }
      for (const [key, value] of traceByRun) {
        if (value.traceId === ctx.traceId) traceByRun.delete(key);
      }
      for (const [key, value] of traceByRequest) {
        if (value.traceId === ctx.traceId) traceByRequest.delete(key);
      }
      for (const [key, value] of traceByToolCall) {
        if (value.traceId === ctx.traceId) traceByToolCall.delete(key);
      }
      for (const [key, value] of traceByRootExecution) {
        if (value.traceId === ctx.traceId) traceByRootExecution.delete(key);
      }
      for (const [key, value] of traceByRootMessage) {
        if (value.traceId === ctx.traceId) traceByRootMessage.delete(key);
      }
      for (const [key, value] of recentTraceByToolName) {
        if (value.traceId === ctx.traceId) recentTraceByToolName.delete(key);
      }
      for (const [key, value] of parentSpanByRequest) {
        if (value.traceId === ctx.traceId) parentSpanByRequest.delete(key);
      }
      for (const [key, value] of parentSpanByToolCall) {
        if (value.traceId === ctx.traceId) parentSpanByToolCall.delete(key);
      }
      for (let i = pendingInboundAnchors.length - 1; i >= 0; i -= 1) {
        if (pendingInboundAnchors[i].trace.traceId === ctx.traceId) {
          pendingInboundAnchors.splice(i, 1);
        }
      }
    }

    function resolveParentSpanFromMaps(traceId: string, requestId?: string, toolCallId?: string): string | undefined {
      const byToolCall = toolCallId ? parentSpanByToolCall.get(toolCallId) : undefined;
      if (byToolCall && byToolCall.traceId === traceId && !isParentRefExpired(byToolCall)) {
        return byToolCall.spanId;
      }
      const byRequest = requestId ? parentSpanByRequest.get(requestId) : undefined;
      if (byRequest && byRequest.traceId === traceId && !isParentRefExpired(byRequest)) {
        return byRequest.spanId;
      }
      return undefined;
    }

    function withOrphanPayload(payload: unknown, reason: string): unknown {
      if (payload && typeof payload === "object" && !Array.isArray(payload)) {
        return { ...(payload as Record<string, unknown>), __traceOrphan: true, __traceOrphanReason: reason };
      }
      return { __traceOrphan: true, __traceOrphanReason: reason, payload };
    }

    function resolveSessionKind(sessionKey?: string): string | undefined {
      const normalized = safeKey(sessionKey)?.toLowerCase();
      if (!normalized) return undefined;
      if (normalized.startsWith("cron:")) return "cron";
      if (normalized.startsWith("hook:")) return "hook";
      if (normalized === "main" || normalized.endsWith(":main")) return "main";
      if (normalized.includes(":group:")) return "group";
      if (normalized.includes(":dm:") || normalized.includes(":direct:")) return "direct";
      if (normalized.includes(":node:")) return "node";
      if (normalized.startsWith("agent:")) return "agent";
      return "other";
    }

    function resolveTriggerType(params: {
      category?: string;
      action?: string;
      messageProvider?: string;
      sessionKind?: string;
      rootExecutionId?: string;
    }): string {
      const category = String(params.category || "").trim().toLowerCase();
      const action = String(params.action || "").trim().toLowerCase();
      const provider = String(params.messageProvider || "").trim().toLowerCase();
      const sessionKind = String(params.sessionKind || "").trim().toLowerCase();
      const rootExecutionId = String(params.rootExecutionId || "").trim().toLowerCase();

      if (provider === "heartbeat") return "heartbeat";
      if (provider === "cron-event") return "cron";
      if (provider === "exec-event") return "exec_event";
      if (provider.startsWith("hook") || provider === "webhook") return "hook";

      if (sessionKind === "cron") return "cron";
      if (sessionKind === "hook") return "hook";

      if (category === "message" && action === "received") return "user_message";
      if (category === "diagnostic" && action.startsWith("webhook.")) return "hook";
      if (category === "diagnostic" && action === "diagnostic.heartbeat") return "heartbeat";

      if (category === "gateway" || category === "agent") return "system";
      if (rootExecutionId.startsWith("msg:")) return "user_message";
      return "run";
    }

    function emitWithTrace(
      rt: ClawsightRuntime,
      event: RuntimeEmitEvent,
      context: {
        sessionKey?: string;
        sessionId?: string;
        runId?: string;
        requestId?: string;
        toolCallId?: string;
        toolName?: string;
        rootExecutionId?: string;
        rootMessageId?: string;
        parentSpanId?: string;
        channelId?: string;
        accountId?: string;
        conversationId?: string;
      },
      options?: { allowCreate?: boolean; allowOrphan?: boolean },
    ): TraceContext | null {
      const sessionKey = safeKey(context.sessionKey);
      const sessionId = safeKey(context.sessionId);
      const runId = safeKey(context.runId);
      const requestId = safeKey(context.requestId) || safeKey(event.requestId);
      const toolCallId = safeKey(context.toolCallId);
      const toolName = safeKey(context.toolName) || safeKey(event.openclaw?.toolName);
      const channelId = safeKey(context.channelId);
      const accountId = safeKey(context.accountId);
      const conversationId = safeKey(context.conversationId);
      const openclaw = event.openclaw ?? {};
      const effectiveRunId = runId || safeKey(openclaw.runId);
      const payloadRec =
        event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
          ? (event.payload as Record<string, unknown>)
          : null;
      const payloadRootExecutionId =
        payloadRec && typeof payloadRec.rootExecutionId === "string"
          ? safeKey(payloadRec.rootExecutionId)
          : undefined;
      const payloadRootMessageId =
        payloadRec && typeof payloadRec.rootMessageId === "string"
          ? safeKey(payloadRec.rootMessageId)
          : undefined;
      const payloadParentSpanId =
        payloadRec && typeof payloadRec.parentSpanId === "string"
          ? safeKey(payloadRec.parentSpanId)
          : undefined;
      const rootMessageId =
        safeKey(context.rootMessageId) ||
        safeKey(event.rootMessageId) ||
        payloadRootMessageId;
      const rootExecutionId = deriveRootExecutionId({
        rootExecutionId:
          safeKey(context.rootExecutionId) ||
          safeKey(event.rootExecutionId) ||
          payloadRootExecutionId,
        rootMessageId,
        channelId: channelId || safeKey(openclaw.sessionKey) || sessionKey || sessionId,
        conversationId: conversationId || safeKey(openclaw.sessionId) || sessionId || sessionKey,
      });
      const explicitParentSpanId =
        safeKey(context.parentSpanId) ||
        safeKey(event.parentSpanId) ||
        payloadParentSpanId;
      const trace = resolveTraceContext({
        runId: effectiveRunId,
        sessionKey,
        sessionId,
        requestId,
        toolCallId,
        toolName,
        rootExecutionId,
        rootMessageId,
        channelId,
        conversationId,
        allowCreate: options?.allowCreate,
      });
      if (!trace) {
        rt.emit({
          ...event,
          requestId: requestId || event.requestId,
          rootExecutionId: event.rootExecutionId || rootExecutionId,
          rootMessageId: event.rootMessageId || rootMessageId,
          parentSpanId: event.parentSpanId || explicitParentSpanId,
          openclaw: {
            ...openclaw,
            sessionKey: openclaw.sessionKey ?? sessionKey,
            sessionId: openclaw.sessionId ?? sessionId,
            runId: openclaw.runId ?? effectiveRunId,
            messageProvider:
              (typeof openclaw.messageProvider === "string" && openclaw.messageProvider.trim()
                ? openclaw.messageProvider.trim()
                : undefined) || channelId,
          },
          payload: options?.allowOrphan === false ? event.payload : withOrphanPayload(event.payload, "missing_trace_context"),
        });
        return null;
      }

      const spanId = event.spanId || crypto.randomUUID();
      const parentSpanId =
        explicitParentSpanId ||
        resolveParentSpanFromMaps(trace.traceId, requestId, toolCallId) ||
        trace.lastSpanId;
      trace.lastSpanId = spanId;
      indexTraceContext(trace, {
        runId: effectiveRunId,
        sessionKey,
        sessionId,
        requestId,
        toolCallId,
        toolName,
        rootExecutionId: rootExecutionId || trace.rootExecutionId,
        rootMessageId: rootMessageId || trace.rootMessageId,
      });
      const parentRef: ParentSpanRef = { spanId, traceId: trace.traceId, updatedAt: Date.now() };
      if (requestId) {
        parentSpanByRequest.set(requestId, parentRef);
      }
      if (toolCallId) {
        parentSpanByToolCall.set(toolCallId, parentRef);
      }

      const resolvedSessionKey = openclaw.sessionKey ?? sessionKey ?? trace.sessionKey ?? sessionId;
      const messageProvider =
        (typeof openclaw.messageProvider === "string" && openclaw.messageProvider.trim()
          ? openclaw.messageProvider.trim()
          : undefined) || channelId;
      const sessionKind = resolveSessionKind(resolvedSessionKey);
      const triggerType = resolveTriggerType({
        category: event.category,
        action: event.action,
        messageProvider,
        sessionKind,
        rootExecutionId: rootExecutionId || trace.rootExecutionId,
      });

      const executionContext: Record<string, unknown> = {
        trigger: triggerType,
        messageProvider,
        sessionKind,
        channelId,
        accountId,
        conversationId,
        rootExecutionId: rootExecutionId || trace.rootExecutionId,
        rootMessageId: rootMessageId || trace.rootMessageId,
      };

      const payloadBase =
        payloadRec && typeof payloadRec === "object" && !Array.isArray(payloadRec)
          ? { ...payloadRec }
          : {};
      const existingExecution =
        payloadRec &&
        typeof payloadRec.execution === "object" &&
        payloadRec.execution &&
        !Array.isArray(payloadRec.execution)
          ? (payloadRec.execution as Record<string, unknown>)
          : {};

      const payloadWithExecution: Record<string, unknown> = {
        ...payloadBase,
        execution: {
          ...existingExecution,
          ...executionContext,
        },
      };
      if (parentSpanId) {
        payloadWithExecution.parentSpanId = payloadWithExecution.parentSpanId ?? parentSpanId;
      }

      rt.emit({
        ...event,
        payload: payloadWithExecution,
        requestId: requestId || event.requestId,
        rootExecutionId: event.rootExecutionId || rootExecutionId || trace.rootExecutionId,
        rootMessageId: event.rootMessageId || rootMessageId || trace.rootMessageId,
        traceId: event.traceId || trace.traceId,
        spanId,
        parentSpanId: event.parentSpanId || parentSpanId,
        correlationId: event.correlationId || trace.traceId,
        openclaw: {
          ...openclaw,
          sessionKey: openclaw.sessionKey ?? sessionKey ?? trace.sessionKey,
          sessionId: openclaw.sessionId ?? sessionId ?? trace.sessionId,
          runId: openclaw.runId ?? effectiveRunId ?? trace.runId,
          messageProvider: messageProvider ?? openclaw.messageProvider,
        },
      });
      return trace;
    }

    // Typed hook wiring (guardrails + telemetry).
    api.on("before_model_resolve", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_model_resolve",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, messageProvider: ctx.messageProvider },
          payload: { promptLen: typeof event.prompt === "string" ? event.prompt.length : undefined },
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          channelId: ctx.messageProvider,
        },
        { allowCreate: true },
      );
      return;
    });

    api.on("before_prompt_build", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_prompt_build",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, messageProvider: ctx.messageProvider },
          payload: {
            promptLen: typeof event.prompt === "string" ? event.prompt.length : undefined,
            messageCount: Array.isArray(event.messages) ? event.messages.length : undefined,
          },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
        { allowCreate: true },
      );
      // In local mode, reinforce security directives via prependContext each turn.
      // The authoritative system prompt injection happens in before_agent_start.
      // prependContext here serves as per-turn reinforcement at user-message level.
      if (rt.config.mode === "local" && localRuleStoreRef.current) {
        const directives = buildSystemDirectives(localRuleStoreRef.current);
        if (!directives) return;
        return { prependContext: directives };
      }
      return;
    });

    api.on("before_agent_start", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_agent_start",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, messageProvider: ctx.messageProvider },
          payload: {
            hasMessages: Array.isArray(event.messages) && event.messages.length > 0,
            promptLen: typeof event.prompt === "string" ? event.prompt.length : undefined,
          },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
        { allowCreate: true },
      );
      // In local mode, inject security directives into the SYSTEM PROMPT.
      // before_agent_start runs once per session. Its systemPrompt result is
      // cached and applied via applySystemPromptOverrideToSession on every turn,
      // giving directives system-level authority that persists across compaction.
      if (rt.config.mode === "local" && localRuleStoreRef.current) {
        const directives = buildSystemDirectives(localRuleStoreRef.current);
        if (!directives) return;
        // event.prompt here is the user's initial message, NOT the system prompt.
        // We return systemPrompt as a standalone override — OpenClaw's runner will
        // call applySystemPromptOverrideToSession which REPLACES the system prompt.
        // To APPEND instead of replace, we'd need access to the current system prompt.
        // Since we don't have it in this event, we return just our directives.
        // OpenClaw's resolvePromptBuildHookResult merges: if before_prompt_build also
        // returns systemPrompt, it takes precedence. Otherwise this one is used.
        return { systemPrompt: directives };
      }
      return;
    });

    api.on("agent_end", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "agent_end",
          severity: "info",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, messageProvider: ctx.messageProvider },
          outcome: event.success ? "allow" : "error",
          outcomeReason: event.success ? undefined : event.error,
          payload: {
            success: Boolean(event.success),
            error: event.error,
            durationMs: event.durationMs,
            messageCount: Array.isArray(event.messages) ? event.messages.length : undefined,
          },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
        { allowCreate: false },
      );
    });

    api.on("before_compaction", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_compaction",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey },
          payload: { ...event },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
      );
    });

    api.on("after_compaction", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "after_compaction",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey },
          payload: { ...event },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
      );
    });

    api.on("llm_input", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const prompt = typeof event.prompt === "string" ? event.prompt : "";
      const llmTrace = emitWithTrace(
        rt,
        {
          category: "session",
          action: "llm_input",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, runId: event.runId, messageProvider: ctx.messageProvider },
          payload: {
            runId: event.runId,
            sessionId: event.sessionId,
            provider: event.provider,
            model: event.model,
            imagesCount: event.imagesCount,
            historyMessageCount: Array.isArray(event.historyMessages) ? event.historyMessages.length : undefined,
            promptLen: prompt.length || undefined,
            promptPreview: compactText(prompt, 420),
            promptHash: prompt ? crypto.createHash("sha256").update(prompt, "utf8").digest("hex") : undefined,
          },
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          runId: event.runId,
          channelId: ctx.messageProvider,
        },
        { allowCreate: true },
      );
      await rt.decideIntentBaseline({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        requestId: crypto.randomUUID(),
        rootExecutionId: llmTrace?.rootExecutionId,
        rootMessageId: llmTrace?.rootMessageId,
        traceId: llmTrace?.traceId,
        sessionKey: ctx.sessionKey,
        runId: event.runId,
        sourceType: llmTrace?.rootExecutionId?.startsWith("msg:") ? "user_message" : "run",
        prompt,
        systemPrompt: typeof (event as { systemPrompt?: unknown }).systemPrompt === "string"
          ? (event as { systemPrompt?: string }).systemPrompt
          : undefined,
        historyMessages: extractHistorySnippets(event.historyMessages),
        provider: event.provider,
        model: event.model,
      });
    });

    api.on("llm_output", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "llm_output",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, runId: event.runId, messageProvider: ctx.messageProvider },
          payload: {
            runId: event.runId,
            sessionId: event.sessionId,
            provider: event.provider,
            model: event.model,
            assistantTextCount: Array.isArray(event.assistantTexts) ? event.assistantTexts.length : undefined,
            assistantTexts: event.assistantTexts,
            usage: event.usage,
          },
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          runId: event.runId,
          channelId: ctx.messageProvider,
        },
        { allowCreate: true },
      );
      closeTrace(ctx.sessionKey, event.runId);
    });

    api.on("before_reset", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_reset",
          severity: "info",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
          payload: {
            reason: event.reason,
            messageCount: Array.isArray(event.messages) ? event.messages.length : undefined,
            sessionFile: event.sessionFile,
          },
        },
        { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId },
        { allowCreate: false },
      );
      closeTrace(ctx.sessionKey, undefined);
    });

    api.on("before_message_write", (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "before_message_write",
          severity: "debug",
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey },
          payload: {
            role: event.message?.role,
            hasToolCalls:
              Array.isArray((event.message as { toolCalls?: unknown[] } | undefined)?.toolCalls) &&
              ((event.message as { toolCalls?: unknown[] }).toolCalls?.length ?? 0) > 0,
          },
        },
        { sessionKey: ctx.sessionKey, sessionId: undefined },
        { allowCreate: false },
      );
      return;
    });

    api.on("before_tool_call", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const requestId = crypto.randomUUID();

      const toolCallTrace = emitWithTrace(
        rt,
        {
          category: "tool",
          action: "before_tool_call",
          severity: "debug",
          requestId,
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, toolName: event.toolName },
          payload: redactHookEventForTelemetry({ hook: "before_tool_call", event, capture: rt.config.capture }),
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: (ctx as { sessionId?: string }).sessionId,
          requestId,
          toolName: event.toolName,
        },
        { allowCreate: true },
      );

      const decision = await rt.decideToolCall({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        agentId: ctx.agentId,
        sessionKey: ctx.sessionKey,
        sessionId: (ctx as { sessionId?: string }).sessionId,
        toolName: event.toolName,
        params: event.params ?? {},
        requestId,
        traceId: toolCallTrace?.traceId,
        rootExecutionId: toolCallTrace?.rootExecutionId,
        rootMessageId: toolCallTrace?.rootMessageId,
        parentSpanId: toolCallTrace?.lastSpanId,
      });
      let effectiveParams: Record<string, unknown> = (event.params ?? {}) as Record<string, unknown>;
      if (decision) {
        const shouldEmitLocalDecision =
          decision.action !== "allow" || Boolean(decision.decisionId || decision.ruleId);
        if (shouldEmitLocalDecision) {
          emitWithTrace(
            rt,
            {
              category: "policy",
              action: "tool_decision_local",
              severity: decision.action === "block" || decision.action === "warn" || decision.action === "confirm" ? "warn" : "info",
              requestId,
              outcome: decision.action === "confirm" ? "block" : decision.action,
              outcomeReason:
                decision.action === "block" || decision.action === "warn" || decision.action === "modify" || decision.action === "confirm"
                  ? decision.reason
                  : undefined,
              policyRuleId: decision.ruleId,
              policyDecisionId: decision.decisionId,
              openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, toolName: event.toolName },
              payload: {
                result: decision.action,
                reason:
                  decision.action === "block" || decision.action === "warn" || decision.action === "modify" || decision.action === "confirm"
                    ? decision.reason
                    : undefined,
                modify:
                  decision.action === "modify" ? Object.keys((decision.params ?? {}) as Record<string, unknown>).length : 0,
              },
            } as any,
            {
              sessionKey: ctx.sessionKey,
              sessionId: undefined,
              requestId,
              toolName: event.toolName,
            },
            { allowCreate: false },
          );
        }

        if (decision.action === "confirm") {
          const toolParams = (event.params ?? {}) as Record<string, unknown>;
          const priorApproval = approvalManager.checkApproval(event.toolName, toolParams);
          if (priorApproval === "approved") {
            // Previously approved — allow through
          } else if (priorApproval === "denied") {
            return { block: true, blockReason: "Denied by user." };
          } else {
            // No prior decision — create pending approval
            const pending = approvalManager.createPending(
              event.toolName,
              toolParams,
              decision.reason ?? "Requires approval",
              decision.ruleId ?? "",
            );
            return {
              block: true,
              blockReason: [
                `Action requires approval.`,
                `Tool: ${event.toolName}`,
                `Command: ${pending.paramsSummary}`,
                `Pending ID: ${pending.id}`,
                `Tell the user to send: /cs approve ${pending.id}`,
              ].join("\n"),
            };
          }
        }

        if (decision.action === "block") {
          return { block: true, blockReason: decision.reason ?? "Blocked by ClawSight policy" };
        }
        if (decision.action === "modify" && decision.params && typeof decision.params === "object") {
          effectiveParams = decision.params as Record<string, unknown>;
        }
      }

      const intentDecision = await rt.decideIntentAction({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        requestId: crypto.randomUUID(),
        rootExecutionId: toolCallTrace?.rootExecutionId,
        rootMessageId: toolCallTrace?.rootMessageId,
        traceId: toolCallTrace?.traceId,
        spanId: toolCallTrace?.lastSpanId,
        sessionKey: ctx.sessionKey,
        runId: (ctx as { runId?: string }).runId,
        toolName: event.toolName,
        params: effectiveParams,
      });

      if (intentDecision?.action === "block") {
        return { block: true, blockReason: intentDecision.reason ?? "Blocked by intent policy" };
      }

      if (decision?.action === "modify" && decision.params && typeof decision.params === "object") {
        return { params: decision.params as Record<string, unknown> };
      }
      return;
    });

    api.on("after_tool_call", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const afterTrace = emitWithTrace(
        rt,
        {
          category: "tool",
          action: "after_tool_call",
          severity: "debug",
          outcome: event.error ? "error" : "allow",
          outcomeReason: typeof event.error === "string" ? event.error : undefined,
          openclaw: { agentId: ctx.agentId, sessionKey: ctx.sessionKey, toolName: event.toolName },
          payload: redactHookEventForTelemetry({ hook: "after_tool_call", event, capture: rt.config.capture }),
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: (ctx as { sessionId?: string }).sessionId,
          toolName: event.toolName,
        },
        { allowCreate: false },
      );
      const outputText = compactText(
        typeof event.result === "string" ? event.result : stableJson(event.result),
        18_000,
      );
      if (!outputText) {
        return;
      }
      await rt.decideIntentOutput({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        requestId: crypto.randomUUID(),
        rootExecutionId: afterTrace?.rootExecutionId,
        rootMessageId: afterTrace?.rootMessageId,
        traceId: afterTrace?.traceId,
        spanId: afterTrace?.lastSpanId,
        sessionKey: ctx.sessionKey,
        runId: (ctx as { runId?: string }).runId,
        toolName: event.toolName,
        content: outputText,
        isSynthetic: false,
      });
    });

    const resolveCanonicalSessionIdentity = (
      ctx: { sessionKey?: string; sessionId?: string; conversationId?: string },
      event?: { sessionId?: string },
    ) => {
      const sessionKey = ctx.sessionKey ?? event?.sessionId ?? ctx.conversationId;
      const sessionId = ctx.sessionId ?? event?.sessionId;
      return { sessionKey, sessionId };
    };

    api.on("message_received", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const identity = resolveCanonicalSessionIdentity(
        {
          sessionKey: ctx.sessionKey,
          sessionId: (ctx as { sessionId?: string }).sessionId,
          conversationId: ctx.conversationId,
        },
        undefined,
      );
      const requestId = crypto.randomUUID();
      const rootMessageId = extractRootMessageId(event.metadata);
      const rootExecutionId = deriveRootExecutionId({
        rootMessageId,
        channelId: ctx.channelId,
        conversationId: ctx.conversationId,
      });
      const trace = emitWithTrace(
        rt,
        {
          category: "message",
          action: "received",
          requestId,
          rootExecutionId,
          rootMessageId,
          openclaw: {
            sessionKey: identity.sessionKey,
            sessionId: identity.sessionId,
          },
          severity: "debug",
          payload: redactHookEventForTelemetry({
            hook: "message_received",
            event,
            capture: rt.config.capture,
            context: { channelId: ctx.channelId, accountId: ctx.accountId },
          }),
        },
        {
          sessionKey: identity.sessionKey,
          sessionId: identity.sessionId,
          channelId: ctx.channelId,
          accountId: ctx.accountId,
          conversationId: ctx.conversationId,
          requestId,
          rootExecutionId,
          rootMessageId,
        },
        { allowCreate: true },
      );
      if (trace) {
        rememberInboundAnchor(trace, {
          channelId: ctx.channelId,
          conversationId: ctx.conversationId,
        });
      }

      await rt.decideInboundMessage({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        requestId,
        channelId: ctx.channelId,
        accountId: ctx.accountId,
        conversationId: ctx.conversationId,
        sessionKey: identity.sessionKey,
        sessionId: identity.sessionId,
        from: event.from,
        content: event.content,
        metadata: event.metadata,
      });
    });

    api.on("message_sending", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const identity = resolveCanonicalSessionIdentity(
        {
          sessionKey: ctx.sessionKey,
          sessionId: (ctx as { sessionId?: string }).sessionId,
          conversationId: ctx.conversationId,
        },
        undefined,
      );
      const outboundRequestId = crypto.randomUUID();
      const rootMessageId = extractRootMessageId(event.metadata);
      const rootExecutionId = deriveRootExecutionId({
        rootMessageId,
        channelId: ctx.channelId,
        conversationId: ctx.conversationId,
      });
      emitWithTrace(
        rt,
        {
          category: "message",
          action: "sending",
          requestId: outboundRequestId,
          rootExecutionId,
          rootMessageId,
          openclaw: {
            sessionKey: identity.sessionKey,
            sessionId: identity.sessionId,
          },
          severity: "debug",
          payload: redactHookEventForTelemetry({
            hook: "message_sending",
            event,
            capture: rt.config.capture,
            context: { channelId: ctx.channelId, accountId: ctx.accountId },
          }),
        },
        {
          sessionKey: identity.sessionKey,
          sessionId: identity.sessionId,
          channelId: ctx.channelId,
          accountId: ctx.accountId,
          conversationId: ctx.conversationId,
          requestId: outboundRequestId,
          rootExecutionId,
          rootMessageId,
        },
        { allowCreate: false },
      );

      const requestId = outboundRequestId;
      const decision = await rt.decideOutboundMessage({
        projectId: rt.config.projectId,
        agentInstanceId: rt.config.agentInstanceId,
        agentName: rt.config.agentName,
        channelId: ctx.channelId,
        accountId: ctx.accountId,
        sessionKey: identity.sessionKey,
        sessionId: identity.sessionId,
        to: event.to,
        content: event.content,
        metadata: event.metadata,
        requestId,
      });

      const shouldEmitLocalDecision =
        decision != null && (decision.action !== "allow" || Boolean(decision.decisionId || decision.ruleId));
      if (shouldEmitLocalDecision && decision) {
        emitWithTrace(
          rt,
          {
            category: "policy",
            action: "message_decision_local",
            severity: decision.action === "block" || decision.action === "warn" ? "warn" : "info",
            requestId,
            outcome: decision.action,
            outcomeReason: "reason" in decision ? decision.reason : undefined,
            policyRuleId: decision.ruleId,
            policyDecisionId: decision.decisionId,
            openclaw: {
              sessionKey: identity.sessionKey,
              sessionId: identity.sessionId,
            },
            payload: {
              result: decision.action,
              reason: "reason" in decision ? decision.reason : undefined,
              channelId: ctx.channelId,
            },
          } as any,
          {
            sessionKey: identity.sessionKey,
            sessionId: identity.sessionId,
            channelId: ctx.channelId,
            accountId: ctx.accountId,
            conversationId: ctx.conversationId,
            requestId,
            rootExecutionId,
            rootMessageId,
          },
          { allowCreate: false },
        );
      }

      if (decision) {
        if (decision.action === "block") {
          return { cancel: true };
        }
        if (decision.action === "modify" && typeof decision.content === "string") {
          return { content: decision.content };
        }
      }

      // --- Deterministic output enforcement (local mode) ---
      // Output rules run AFTER policy decisions and can modify/block content
      // regardless of what the LLM generated. This is the guarantee layer.
      if (rt.config.mode === "local" && localRuleStoreRef.current) {
        const outputRules = localRuleStoreRef.current.getOutputRules();
        let content = event.content;
        let modified = false;
        for (const rule of outputRules) {
          if (!rule.enforce || !rule.enforceValue) continue;

          if (rule.enforce === "require_contains" && rule.action === "block") {
            if (!content.toLowerCase().includes(rule.enforceValue.toLowerCase())) {
              emitWithTrace(
                rt,
                {
                  category: "policy",
                  action: "output_enforcement_blocked",
                  severity: "warn",
                  outcome: "block",
                  outcomeReason: rule.reason || `Output missing required content: "${rule.enforceValue}"`,
                  policyRuleId: String(rule.id),
                  openclaw: { sessionKey: identity.sessionKey },
                  payload: { enforce: rule.enforce, enforceValue: rule.enforceValue, ruleId: rule.id },
                } as any,
                { sessionKey: identity.sessionKey, channelId: ctx.channelId },
                { allowCreate: false },
              );
              return { cancel: true };
            }
          } else if (rule.enforce === "reject_if_contains" && rule.action === "block") {
            if (content.toLowerCase().includes(rule.enforceValue.toLowerCase())) {
              emitWithTrace(
                rt,
                {
                  category: "policy",
                  action: "output_enforcement_blocked",
                  severity: "warn",
                  outcome: "block",
                  outcomeReason: rule.reason || `Output contains forbidden content: "${rule.enforceValue}"`,
                  policyRuleId: String(rule.id),
                  openclaw: { sessionKey: identity.sessionKey },
                  payload: { enforce: rule.enforce, enforceValue: rule.enforceValue, ruleId: rule.id },
                } as any,
                { sessionKey: identity.sessionKey, channelId: ctx.channelId },
                { allowCreate: false },
              );
              return { cancel: true };
            }
          }
        }
        if (modified) {
          return { content };
        }
      }

      return;
    });

    api.on("message_sent", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const identity = resolveCanonicalSessionIdentity(
        {
          sessionKey: ctx.sessionKey,
          sessionId: (ctx as { sessionId?: string }).sessionId,
          conversationId: ctx.conversationId,
        },
        undefined,
      );
      const rootMessageId = extractRootMessageId((event as { metadata?: unknown }).metadata);
      const rootExecutionId = deriveRootExecutionId({
        rootMessageId,
        channelId: ctx.channelId,
        conversationId: ctx.conversationId,
      });
      emitWithTrace(
        rt,
        {
          category: "message",
          action: "sent",
          rootExecutionId,
          rootMessageId,
          openclaw: {
            sessionKey: identity.sessionKey,
            sessionId: identity.sessionId,
          },
          severity: event.success ? "debug" : "warn",
          outcome: event.success ? "allow" : "error",
          outcomeReason: event.success ? undefined : event.error,
          payload: redactHookEventForTelemetry({
            hook: "message_sent",
            event,
            capture: rt.config.capture,
            context: { channelId: ctx.channelId, accountId: ctx.accountId },
          }),
        },
        {
          sessionKey: identity.sessionKey,
          sessionId: identity.sessionId,
          channelId: ctx.channelId,
          accountId: ctx.accountId,
          conversationId: ctx.conversationId,
          rootExecutionId,
          rootMessageId,
        },
        { allowCreate: false },
      );
    });

    api.on("session_start", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const identity = resolveCanonicalSessionIdentity(
        {
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          conversationId: ctx.conversationId,
        },
        { sessionId: event.sessionId },
      );
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "start",
          severity: "debug",
          openclaw: {
            agentId: ctx.agentId,
            sessionId: identity.sessionId,
            sessionKey: identity.sessionKey,
          },
          payload: { ...event },
        },
        { sessionKey: identity.sessionKey, sessionId: identity.sessionId, conversationId: ctx.conversationId },
        { allowCreate: true },
      );
    });

    api.on("session_end", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      const identity = resolveCanonicalSessionIdentity(
        {
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          conversationId: ctx.conversationId,
        },
        { sessionId: event.sessionId },
      );
      emitWithTrace(
        rt,
        {
          category: "session",
          action: "end",
          severity: "debug",
          openclaw: {
            agentId: ctx.agentId,
            sessionId: identity.sessionId,
            sessionKey: identity.sessionKey,
          },
          payload: { ...event },
        },
        { sessionKey: identity.sessionKey, sessionId: identity.sessionId, conversationId: ctx.conversationId },
        { allowCreate: false },
      );
      closeTrace(identity.sessionKey, undefined);
    });

    api.on("gateway_start", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "gateway",
          action: "start",
          severity: "info",
          openclaw: { gatewayPort: event.port },
          payload: { ...event, ...ctx },
        },
        { sessionKey: undefined, sessionId: undefined },
        { allowCreate: false, allowOrphan: true },
      );
    });

    api.on("gateway_stop", async (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      emitWithTrace(
        rt,
        {
          category: "gateway",
          action: "stop",
          severity: "info",
          openclaw: {},
          payload: { ...event, ...ctx },
        },
        { sessionKey: undefined, sessionId: undefined },
        { allowCreate: false, allowOrphan: true },
      );
    });

    api.on("tool_result_persist", (event, ctx) => {
      const rt = getRuntime();
      if (!rt) {
        return;
      }
      // This hook runs on the persistence path; keep it cheap and never throw.
      const persistTrace = emitWithTrace(
        rt,
        {
          category: "tool",
          action: "tool_result_persist",
          openclaw: {
            agentId: ctx.agentId,
            sessionKey: ctx.sessionKey,
            toolName: ctx.toolName,
            toolCallId: event.toolCallId,
          },
          payload: {
            toolName: event.toolName,
            toolCallId: event.toolCallId,
            isSynthetic: event.isSynthetic,
          },
        },
        {
          sessionKey: ctx.sessionKey,
          sessionId: undefined,
          toolCallId: event.toolCallId,
          toolName: event.toolName ?? ctx.toolName,
        },
        { allowCreate: true },
      );
    });

    // --- Chat commands (processed by messaging platform dispatch) ---
    api.registerCommand({
      name: "cs",
      description: "Manage ClawSight security rules",
      acceptsArgs: true,
      requireAuth: true,
      handler: async (ctx) => {
        const store = localRuleStoreRef.current;
        const rt = getRuntime();
        const args = (ctx.args ?? "").trim();
        const parts = args.split(/\s+/);
        const sub = parts[0]?.toLowerCase() ?? "";

        if (sub === "status") {
          const mode = rt?.config.mode ?? "unknown";
          const ruleCount = store?.ruleCount ?? 0;
          const directiveCount = store?.getPromptDirectives().length ?? 0;
          const outputRules = store?.getOutputRules() ?? [];
          const blockRules = store?.listRules().filter((r) => r.action === "block" && r.scope !== "output").length ?? 0;
          const lines = [
            `ClawSight status:`,
            `  Mode: ${mode}`,
            `  Rules loaded: ${ruleCount}`,
            ``,
            `  Advisory (prompt directives): ${directiveCount}`,
            `  Enforced (tool/domain/ip/msg blocks): ${blockRules}`,
            `  Enforced (output rules): ${outputRules.length}`,
          ];
          if (outputRules.length > 0) {
            for (const r of outputRules) {
              lines.push(`    [${r.id}] ${r.enforce} "${r.enforceValue}" — ${r.reason ?? "no reason"}`);
            }
          }
          return { text: lines.join("\n") };
        }

        if (sub === "rules") {
          if (!store) return { text: "ClawSight is not in local mode. No local rules available." };
          const rules = store.listRules();
          if (rules.length === 0) return { text: "No rules configured." };
          const lines = rules.map(
            (r) => `  [${r.id}] ${r.action} ${r.scope}${r.pattern ? ` "${r.pattern}"` : ""}${r.toolName ? ` tool=${r.toolName}` : ""}${r.commandContains ? ` cmd~"${r.commandContains}"` : ""}${r.reason ? ` — ${r.reason}` : ""}`,
          );
          return { text: `Active rules (${rules.length}):\n${lines.join("\n")}` };
        }

        if (sub === "block" || sub === "allow") {
          if (!store) return { text: "ClawSight is not in local mode." };
          const action = sub as "block" | "allow";
          const scope = parts[1]?.toLowerCase();

          if (scope === "domain" && parts[2]) {
            const pattern = parts[2];
            const rule = await store.addRule({ scope: "domain", action, pattern, match: "subdomain", priority: 50 });
            return { text: `Added rule #${rule.id}: ${action} domain "${pattern}"` };
          }
          if (scope === "ip" && parts[2]) {
            const pattern = parts.slice(2).join(",");
            const rule = await store.addRule({ scope: "ip", action, pattern, priority: 50 });
            return { text: `Added rule #${rule.id}: ${action} ip "${pattern}"` };
          }
          if (scope === "command" || scope === "cmd") {
            const commandContains = parts.slice(2).join(" ");
            if (!commandContains) return { text: `Usage: /cs ${action} command <pattern>` };
            const rule = await store.addRule({ scope: "tool", action, toolName: "exec", commandContains, priority: 50 });
            return { text: `Added rule #${rule.id}: ${action} command "${commandContains}"` };
          }
          if (scope === "tool" && parts[2]) {
            const toolName = parts[2];
            const commandContains = parts.slice(3).join(" ") || undefined;
            const rule = await store.addRule({ scope: "tool", action, toolName, commandContains, priority: 50 });
            return { text: `Added rule #${rule.id}: ${action} tool "${toolName}"${commandContains ? ` cmd~"${commandContains}"` : ""}` };
          }
          if (scope === "message" && parts.slice(2).join(" ")) {
            const contentContains = parts.slice(2).join(" ");
            const rule = await store.addRule({ scope: "message", action, contentContains, priority: 50 });
            return { text: `Added rule #${rule.id}: ${action} message containing "${contentContains}"` };
          }
          return { text: [
            `Usage: /cs ${action} <type> <pattern>`,
            `  /cs ${action} command <text> — match shell commands containing text`,
            `  /cs ${action} domain <domain> — match domain (incl. subdomains)`,
            `  /cs ${action} ip <addr> — match IP address`,
            `  /cs ${action} tool <name> [cmd-pattern] — match a specific tool`,
            `  /cs ${action} message <text> — match outbound messages containing text`,
          ].join("\n") };
        }

        if (sub === "enforce") {
          if (!store) return { text: "ClawSight is not in local mode." };
          const enforceSub = parts[1]?.toLowerCase();

          if (enforceSub === "require" && parts.slice(2).join(" ").trim()) {
            const required = parts.slice(2).join(" ");
            const rule = await store.addRule({
              scope: "output", action: "block", enforce: "require_contains",
              enforceValue: required, priority: 1, reason: `Block messages missing "${required}"`,
            });
            return { text: `Added enforced rule #${rule.id}: block outbound messages not containing "${required}"` };
          }
          if (enforceSub === "reject" && parts.slice(2).join(" ").trim()) {
            const forbidden = parts.slice(2).join(" ");
            const rule = await store.addRule({
              scope: "output", action: "block", enforce: "reject_if_contains",
              enforceValue: forbidden, priority: 1, reason: `Block messages containing "${forbidden}"`,
            });
            return { text: `Added enforced rule #${rule.id}: block outbound messages containing "${forbidden}"` };
          }
          return { text: [
            "Output enforcement (deterministic, guaranteed):",
            "  /cs enforce require <text> — block messages that don't contain text",
            "  /cs enforce reject <text> — block messages that contain text",
            "",
            "These are NOT prompt directives — they run at the message_sending hook",
            "and cannot be bypassed by the LLM. Use /cs remove <id> to delete.",
          ].join("\n") };
        }

        if (sub === "remove" && parts[1]) {
          if (!store) return { text: "ClawSight is not in local mode." };
          const ids = parts.slice(1).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
          if (ids.length === 0) return { text: "Invalid rule ID(s)." };
          const results: string[] = [];
          for (const id of ids) {
            const removed = await store.removeRule(id);
            results.push(removed ? `Rule #${id} removed.` : `Rule #${id} not found.`);
          }
          return { text: results.join("\n") };
        }

        if (sub === "confirm") {
          if (!store) return { text: "ClawSight is not in local mode." };
          const scope = parts[1]?.toLowerCase();

          if (scope === "command" || scope === "cmd") {
            const commandContains = parts.slice(2).join(" ");
            if (!commandContains) return { text: "Usage: /cs confirm command <pattern>" };
            const rule = await store.addRule({ scope: "tool", action: "confirm", toolName: "exec", commandContains, priority: 50 });
            return { text: `Added rule #${rule.id}: confirm command "${commandContains}"` };
          }
          if (scope === "domain" && parts[2]) {
            const pattern = parts[2];
            const rule = await store.addRule({ scope: "domain", action: "confirm", pattern, match: "subdomain", priority: 50 });
            return { text: `Added rule #${rule.id}: confirm domain "${pattern}"` };
          }
          if (scope === "ip" && parts[2]) {
            const pattern = parts.slice(2).join(",");
            const rule = await store.addRule({ scope: "ip", action: "confirm", pattern, priority: 50 });
            return { text: `Added rule #${rule.id}: confirm ip "${pattern}"` };
          }
          if (scope === "tool" && parts[2]) {
            const toolName = parts[2];
            const commandContains = parts.slice(3).join(" ") || undefined;
            const rule = await store.addRule({ scope: "tool", action: "confirm", toolName, commandContains, priority: 50 });
            return { text: `Added rule #${rule.id}: confirm tool "${toolName}"${commandContains ? ` cmd~"${commandContains}"` : ""}` };
          }
          if (scope === "message" && parts.slice(2).join(" ")) {
            const contentContains = parts.slice(2).join(" ");
            const rule = await store.addRule({ scope: "message", action: "confirm", contentContains, priority: 50 });
            return { text: `Added rule #${rule.id}: confirm message containing "${contentContains}"` };
          }
          return { text: [
            "Usage: /cs confirm <type> <pattern>",
            "  /cs confirm command <text> — require approval for shell commands containing text",
            "  /cs confirm domain <domain> — require approval for domain access",
            "  /cs confirm ip <addr> — require approval for IP access",
            "  /cs confirm tool <name> [cmd-pattern] — require approval for a specific tool",
            "  /cs confirm message <text> — require approval for outbound messages containing text",
          ].join("\n") };
        }

        if (sub === "pending") {
          const pending = approvalManager.listPending();
          if (pending.length === 0) return { text: "No pending approvals." };
          const lines = pending.map((p) => {
            const remainMs = p.expiresAt - Date.now();
            const remainSec = Math.max(0, Math.round(remainMs / 1000));
            return `  [${p.id}] ${p.toolName} — ${p.paramsSummary} (expires in ${remainSec}s)`;
          });
          return { text: `Pending approvals (${pending.length}):\n${lines.join("\n")}` };
        }

        if (sub === "approve") {
          const id = parts[1];
          if (!id) return { text: "Usage: /cs approve <id>" };
          const entry = approvalManager.resolve(id, "approved");
          if (!entry) return { text: `Approval ID "${id}" not found or expired.` };
          return { text: `Approved ${id} (${entry.toolName}: ${entry.paramsSummary}). The agent can now retry.` };
        }

        if (sub === "approve-always") {
          if (!store) return { text: "ClawSight is not in local mode." };
          const id = parts[1];
          if (!id) return { text: "Usage: /cs approve-always <id>" };
          const entry = approvalManager.resolve(id, "approved");
          if (!entry) return { text: `Approval ID "${id}" not found or expired.` };
          // Add a permanent allow rule so future matching calls pass without approval
          const rule = await store.addRule({
            scope: "tool",
            action: "allow",
            toolName: entry.toolName,
            commandContains: entry.paramsSummary.length <= 120 ? entry.paramsSummary : undefined,
            priority: 40,
            reason: `Permanently approved from pending ${id}`,
          });
          return { text: `Approved ${id} and added permanent allow rule #${rule.id} for ${entry.toolName}. Future matching calls will pass without approval.` };
        }

        if (sub === "deny") {
          const id = parts[1];
          if (!id) return { text: "Usage: /cs deny <id>" };
          const entry = approvalManager.resolve(id, "denied");
          if (!entry) return { text: `Approval ID "${id}" not found or expired.` };
          return { text: `Denied ${id} (${entry.toolName}: ${entry.paramsSummary}).` };
        }

        if (sub === "reset") {
          if (!store) return { text: "ClawSight is not in local mode." };
          const confirmFlag = parts[1]?.toLowerCase();
          if (confirmFlag !== "confirm") {
            return { text: "This will replace ALL rules and directives with defaults (46 rules, 11 directives).\nTo confirm, run: /cs reset confirm" };
          }
          await store.resetToDefaults();
          return { text: `Reset complete. Loaded ${store.ruleCount} default rules and ${store.getPromptDirectives().length} default directives.` };
        }

        if (sub === "directives" || sub === "directive") {
          if (!store) return { text: "ClawSight is not in local mode. No directives available." };
          const directiveSub = parts[1]?.toLowerCase();

          if (directiveSub === "add" && parts.slice(2).join(" ").trim()) {
            const text = parts.slice(2).join(" ").trim();
            const count = await store.addDirective(text);
            return { text: `Added directive #${count - 1}: "${text}"` };
          }

          if (directiveSub === "remove" && parts[2]) {
            const indices = parts.slice(2).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
            if (indices.length === 0) return { text: "Invalid directive index(es)." };
            const directives = store.getPromptDirectives();
            const outOfRange = indices.filter((i) => i < 0 || i >= directives.length);
            if (outOfRange.length > 0) return { text: `Index out of range (0–${directives.length - 1}): ${outOfRange.join(", ")}` };
            // Remove highest indices first so earlier indices stay valid
            const sorted = [...new Set(indices)].sort((a, b) => b - a);
            for (const idx of sorted) {
              await store.removeDirective(idx);
            }
            return { text: `Removed ${sorted.length} directive(s): #${sorted.sort((a, b) => a - b).join(", #")}` };
          }

          // Show full injection preview
          if (directiveSub === "preview") {
            const text = buildSystemDirectives(store);
            if (!text) return { text: "No directives or rules to inject." };
            return { text: `=== INJECTED POLICY (system prompt + prepend context) ===\n${text}` };
          }

          // List user-editable directives with indices
          const directives = store.getPromptDirectives();
          if (directives.length === 0) return { text: "No custom directives configured.\nUse /cs directive add <text> to add one.\nUse /cs directive preview to see the full injected prompt." };
          const lines = directives.map((d, i) => `  [${i}] ${d}`);
          return { text: `Custom directives (${directives.length}):\n${lines.join("\n")}\n\nUse /cs directive add <text> or /cs directive remove <index>\nUse /cs directive preview to see the full injected prompt.` };
        }

        return { text: [
          "ClawSight commands:",
          "",
          "Status & inspection:",
          "  /cs status — show mode and rule count",
          "  /cs rules — list all active rules",
          "  /cs directives — list prompt directives",
          "",
          "Block / allow rules:",
          "  /cs block command <text> — block shell commands containing text",
          "  /cs block domain <pattern> — block a domain (incl. subdomains)",
          "  /cs block ip <addr> — block an IP address",
          "  /cs block tool <name> [pattern] — block a specific tool",
          "  /cs block message <text> — block outbound messages containing text",
          "  /cs allow command <text> — allow (same types as block)",
          "  /cs remove <id> — remove a rule by ID",
          "  /cs reset confirm — reset all rules and directives to defaults",
          "",
          "Approval rules (human-in-the-loop):",
          "  /cs confirm command <text> — require approval for matching commands",
          "  /cs confirm domain <pattern> — require approval for domain access",
          "  /cs confirm tool <name> [pattern] — require approval for a tool",
          "  /cs pending — list pending approvals",
          "  /cs approve <id> — approve a pending action (one-time)",
          "  /cs approve-always <id> — approve and add permanent allow rule",
          "  /cs deny <id> — deny a pending action",
          "",
          "Prompt directives (advisory — LLM guidance, best-effort):",
          "  /cs directive add <text> — add a security directive",
          "  /cs directive remove <index> — remove a directive by index",
          "  /cs directive preview — show full injected system + context prompt",
          "",
          "Output enforcement (deterministic — guaranteed, cannot be bypassed):",
          "  /cs enforce require <text> — block messages not containing text",
          "  /cs enforce reject <text> — block messages containing text",
          "",
          "Examples:",
          "  /cs block command rm -rf — block recursive force-delete",
          "  /cs block domain evil.com — block evil.com + all subdomains",
          "  /cs block tool web_search — block the web_search tool entirely",
          "  /cs confirm command npm install — require approval for npm install",
          "  /cs approve a3f8 — approve pending action a3f8",
          "  /cs enforce require [verified] — block messages without [verified]",
          "  /cs enforce reject <script> — block messages containing <script>",
          "  /cs directive add Never share API keys in responses",
          "  /cs remove 6 — remove any rule by ID",
        ].join("\n") };
      },
    });
  },
};

export default plugin;

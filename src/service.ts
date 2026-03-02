/**
 * @module service
 * @description ClawSight service factory — creates the {@link ClawsightRuntime} for the active mode.
 *
 * The service implements OpenClaw's `OpenClawPluginService` interface (start/stop lifecycle).
 * On `start()`, it resolves the plugin config, determines the operating mode, and builds
 * the appropriate runtime:
 *
 * - **local** — creates a {@link LocalRuleStore}, wires `decideToolCall` to the local policy
 *   engine, optionally starts a telemetry pipeline to the SIEM.
 * - **audit/enforce** — creates a {@link PlatformClient} for remote policy decisions,
 *   a {@link TelemetryQueue} for event streaming, inventory snapshots, and diagnostic/log
 *   transports.
 *
 * Exposes `localRuleStoreRef` so the plugin entry (index.ts) can access the rule store
 * for chat commands and prompt directive injection.
 */
import crypto from "node:crypto";
import os from "node:os";
import type { RuntimeEnv, OpenClawPluginService } from "openclaw/plugin-sdk";
import { onDiagnosticEvent, registerLogTransport } from "openclaw/plugin-sdk";
import { resolvePluginConfig } from "./config.js";
import { resolveRuntimeAgentIdentity } from "./identity.js";
import { collectAgentInventorySnapshot } from "./inventory.js";
import { PlatformClient } from "./platform-client.js";
import { LocalRuleStore } from "./local/rule-store.js";
import { evaluateToolDecision as localEvalTool, evaluateMessageDecision as localEvalMessage } from "./local/policy-engine.js";
import type {
  ClawsightRuntime,
  IntentActionDecisionRequest,
  IntentBaselineDecisionRequest,
  IntentDecision,
  IntentOutputDecisionRequest,
  InboundMessageDecision,
  InboundMessageDecisionRequest,
  MessageDecision,
  MessageDecisionRequest,
  PaymentsSendRequest,
  PaymentsSendResponse,
  ToolDecision,
  ToolDecisionRequest,
} from "./service-types.js";
import { setRuntime } from "./runtime.js";
import { TelemetryQueue } from "./telemetry/queue.js";

/** Shared ref so index.ts hooks can access the local rule store. */
export const localRuleStoreRef: { current: LocalRuleStore | null } = { current: null };

function isInsecurePlatformUrl(url: string): boolean {
  if (!url) return false;
  const lower = url.toLowerCase();
  if (!lower.startsWith("http://")) return false;
  const host = lower.slice(7).split(/[:/]/)[0];
  return host !== "localhost" && host !== "127.0.0.1" && host !== "::1";
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function shortText(value: unknown, max = 240): string {
  const raw = typeof value === "string" ? value : safeStringify(value);
  if (raw.length <= max) {
    return raw;
  }
  return `${raw.slice(0, max - 12)}…(${raw.length} chars)`;
}

function clampAddress(address: string): string {
  const trimmed = address.trim();
  if (trimmed.length <= 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}

function isHighRiskTool(toolName?: string): boolean {
  const name = String(toolName || "").toLowerCase();
  return name.includes("payment") || name.includes("send") || name.includes("transfer");
}

function canFailOpenOnError(mode: "off" | "audit" | "enforce", toolName?: string): boolean {
  if (mode !== "enforce") {
    return true;
  }
  return !isHighRiskTool(toolName);
}

function sanitizeForTelemetry(req: { toolName: string; params: Record<string, unknown> }) {
  const params = { ...req.params };
  if (typeof params.toAddress === "string") {
    params.toAddress = clampAddress(params.toAddress);
  }
  if (typeof params.command === "string" && params.command.length > 160) {
    params.command = `${params.command.slice(0, 160)}…`;
  }
  if (typeof params.password === "string") {
    params.password = "[redacted]";
  }
  return params;
}

function diagnosticSeverity(type: string): "debug" | "info" | "warn" | "error" {
  const normalized = String(type || "").toLowerCase();
  if (normalized.includes("error")) return "warn";
  if (normalized === "model.usage") return "info";
  if (normalized === "session.stuck" || normalized === "tool.loop") return "warn";
  return "debug";
}

function asString(value: unknown): string | undefined {
  const raw = String(value || "").trim();
  return raw.length > 0 ? raw : undefined;
}

function resolveSessionKind(sessionKey?: string): string | undefined {
  const normalized = asString(sessionKey)?.toLowerCase();
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

function resolveDiagnosticTriggerType(params: {
  type: string;
  sessionKey?: string;
  channel?: string;
  reason?: string;
}): string {
  const type = params.type.trim().toLowerCase();
  const sessionKind = resolveSessionKind(params.sessionKey);
  const channel = asString(params.channel)?.toLowerCase();
  const reason = asString(params.reason)?.toLowerCase();

  if (type.startsWith("webhook.")) return "hook";
  if (type === "diagnostic.heartbeat") return "heartbeat";
  if (channel === "heartbeat") return "heartbeat";
  if (channel === "cron-event") return "cron";
  if (channel?.startsWith("hook")) return "hook";
  if (sessionKind === "cron") return "cron";
  if (sessionKind === "hook") return "hook";
  if (reason?.startsWith("cron:")) return "cron";
  if (reason?.startsWith("hook:") || reason === "wake") return "hook";
  return "system";
}

export function createClawsightService(params: {
  pluginConfig: Record<string, unknown>;
  runtime?: RuntimeEnv;
}): OpenClawPluginService {
  let stopLogTransport: (() => void) | null = null;
  let unsubscribeDiagnostics: (() => void) | null = null;
  let queue: TelemetryQueue | null = null;
  let runtime: ClawsightRuntime | null = null;
  let inventoryTimer: ReturnType<typeof setInterval> | null = null;
  let inventorySnapshotInFlight = false;

  return {
    id: "clawsight",
    async start(ctx) {
      inventorySnapshotInFlight = false;
      if (inventoryTimer) {
        clearInterval(inventoryTimer);
        inventoryTimer = null;
      }

      const cfg = resolvePluginConfig(params.pluginConfig ?? {});
      if (!cfg.enabled || cfg.mode === "off") {
        setRuntime(null);
        return;
      }

      // --- Local mode: standalone enforcement from local rules file ---
      if (cfg.mode === "local") {
        const rulesPath = cfg.localRulesPath;
        if (!rulesPath) {
          ctx.logger.warn("clawsight: localRulesPath is not configured for local mode. Plugin disabled.");
          setRuntime(null);
          return;
        }
        const localStore = new LocalRuleStore(rulesPath);
        await localStore.loadRules();

        // Expose the store on the service for index.ts hooks to access
        (localRuleStoreRef as { current: LocalRuleStore | null }).current = localStore;

        // If platformUrl is configured, stand up telemetry pipeline to SIEM
        let localQueue: TelemetryQueue | null = null;
        let runtimeIdentity:
          | Awaited<ReturnType<typeof resolveRuntimeAgentIdentity>>
          | null = null;
        const hasPlatform = Boolean(cfg.platformUrl);
        if (hasPlatform) {
          if (isInsecurePlatformUrl(cfg.platformUrl)) {
            ctx.logger.warn(
              "clawsight: platformUrl is HTTP on a non-localhost host. Telemetry and API token will be sent unencrypted. Use HTTPS in production.",
            );
          }
          try {
            runtimeIdentity = await resolveRuntimeAgentIdentity(cfg);
            cfg.agentInstanceId = runtimeIdentity.agentInstanceId;
            cfg.agentName = runtimeIdentity.agentName;
            cfg.identityPath = runtimeIdentity.identityPath;
          } catch (err) {
            ctx.logger.warn(`clawsight: failed to resolve persistent identity: ${String(err)}`);
            if (!cfg.agentInstanceId) {
              cfg.agentInstanceId = crypto.randomUUID();
            }
          }
          const client = new PlatformClient(cfg);
          localQueue = new TelemetryQueue({ cfg, client });
          await localQueue.start();

          const bootstrapTraceId = cfg.agentInstanceId ? `agent:${cfg.agentInstanceId}:bootstrap` : undefined;
          localQueue.emit({
            category: "agent",
            action: "bootstrap",
            severity: "info",
            outcome: "allow",
            traceId: bootstrapTraceId,
            rootExecutionId: bootstrapTraceId,
            payload: {
              type: "agent.bootstrap",
              agentProfile: {
                agentInstanceId: cfg.agentInstanceId,
                agentName: cfg.agentName,
                identityPath: cfg.identityPath,
                hostName: runtimeIdentity?.hostName || os.hostname(),
                osPlatform: runtimeIdentity?.osPlatform || process.platform,
                osRelease: runtimeIdentity?.osRelease || os.release(),
                osArch: runtimeIdentity?.osArch || process.arch,
                nodeVersion: runtimeIdentity?.nodeVersion || process.version,
                mode: cfg.mode,
                projectId: cfg.projectId,
              },
            },
          } as any);

          const emitInventorySnapshot = async (reason: "startup" | "periodic") => {
            if (!localQueue || inventorySnapshotInFlight) return;
            inventorySnapshotInFlight = true;
            const startedAt = Date.now();
            try {
              const { snapshot } = await collectAgentInventorySnapshot({
                cfg,
                reason,
                runtimeIdentity: runtimeIdentity || undefined,
              });
              localQueue.emit({
                category: "agent",
                action: "inventory_snapshot",
                severity: "info",
                outcome: "allow",
                durationMs: Date.now() - startedAt,
                traceId: bootstrapTraceId,
                rootExecutionId: bootstrapTraceId,
                payload: {
                  type: "agent.inventory_snapshot",
                  inventory: snapshot,
                },
              } as any);
            } catch (err) {
              localQueue.emit({
                category: "agent",
                action: "inventory_snapshot_error",
                severity: "warn",
                traceId: bootstrapTraceId,
                rootExecutionId: bootstrapTraceId,
                durationMs: Date.now() - startedAt,
                outcome: "error",
                outcomeReason: "inventory snapshot collection failed",
                errorClass: "inventory_collection_error",
                errorCode: "inventory_snapshot_failed",
                payload: { reason, error: String(err) },
              } as any);
            } finally {
              inventorySnapshotInFlight = false;
            }
          };

          await emitInventorySnapshot("startup");
          inventoryTimer = setInterval(() => {
            void emitInventorySnapshot("periodic");
          }, 10 * 60 * 1000);
        }

        const localRt: ClawsightRuntime = {
          config: cfg,
          emit: (evt) => {
            if (!localQueue) return;
            localQueue.emit(evt as any);
          },
          decideToolCall: async (req: ToolDecisionRequest): Promise<ToolDecision | null> => {
            const rules = localStore.getSortedRules();
            return localEvalTool(rules, req);
          },
          decideOutboundMessage: async (req: MessageDecisionRequest): Promise<MessageDecision | null> => {
            const rules = localStore.getSortedRules();
            return localEvalMessage(rules, req);
          },
          decideInboundMessage: async (): Promise<InboundMessageDecision | null> => {
            return null; // no inbound check in local mode
          },
          decideIntentBaseline: async (): Promise<IntentDecision | null> => {
            return null; // no LLM intent analysis in local mode
          },
          decideIntentAction: async (): Promise<IntentDecision | null> => {
            return null; // no LLM intent analysis in local mode
          },
          decideIntentOutput: async (): Promise<IntentDecision | null> => {
            return null; // no LLM intent analysis in local mode
          },
          paymentsSend: async (): Promise<PaymentsSendResponse> => {
            return { status: "blocked", reason: "payments disabled in local mode" };
          },
          stop: async () => {
            if (inventoryTimer) {
              clearInterval(inventoryTimer);
              inventoryTimer = null;
            }
            if (localQueue) {
              await localQueue.stop();
              localQueue = null;
            }
            setRuntime(null);
          },
        };

        runtime = localRt;
        setRuntime(localRt);
        const telemetryStatus = hasPlatform ? `telemetry → ${cfg.platformUrl}` : "telemetry off";
        ctx.logger.info(
          `clawsight: local mode active — ${localStore.ruleCount} rules loaded from ${rulesPath} (${telemetryStatus})`,
        );
        return;
      }

      if (!cfg.platformUrl) {
        ctx.logger.warn("clawsight: platformUrl is not configured. Plugin disabled until configured.");
        setRuntime(null);
        return;
      }

      if (isInsecurePlatformUrl(cfg.platformUrl)) {
        ctx.logger.warn(
          "clawsight: platformUrl is HTTP on a non-localhost host. Telemetry and API token will be sent unencrypted. Use HTTPS in production.",
        );
      }

      let runtimeIdentity:
        | Awaited<ReturnType<typeof resolveRuntimeAgentIdentity>>
        | null = null;
      try {
        runtimeIdentity = await resolveRuntimeAgentIdentity(cfg);
        cfg.agentInstanceId = runtimeIdentity.agentInstanceId;
        cfg.agentName = runtimeIdentity.agentName;
        cfg.identityPath = runtimeIdentity.identityPath;
      } catch (err) {
        ctx.logger.warn(`clawsight: failed to resolve persistent identity: ${String(err)}`);
        if (!cfg.agentInstanceId) {
          cfg.agentInstanceId = crypto.randomUUID();
        }
      }

      const client = new PlatformClient(cfg);
      queue = new TelemetryQueue({ cfg, client });
      await queue.start();

      const bootstrapTraceId = cfg.agentInstanceId ? `agent:${cfg.agentInstanceId}:bootstrap` : undefined;

      queue.emit({
        category: "agent",
        action: "bootstrap",
        severity: "info",
        outcome: "allow",
        traceId: bootstrapTraceId,
        rootExecutionId: bootstrapTraceId,
        payload: {
          type: "agent.bootstrap",
          agentProfile: {
            agentInstanceId: cfg.agentInstanceId,
            agentName: cfg.agentName,
            identityPath: cfg.identityPath,
            hostName: runtimeIdentity?.hostName || os.hostname(),
            osPlatform: runtimeIdentity?.osPlatform || process.platform,
            osRelease: runtimeIdentity?.osRelease || os.release(),
            osArch: runtimeIdentity?.osArch || process.arch,
            nodeVersion: runtimeIdentity?.nodeVersion || process.version,
            openclawVersion:
              runtimeIdentity?.openclawVersion ||
              asString(process.env.OPENCLAW_VERSION) ||
              asString(process.env.OPENCLAW_BUILD_VERSION) ||
              undefined,
            pluginVersion:
              runtimeIdentity?.pluginVersion ||
              asString(process.env.CLAWSIGHT_PLUGIN_VERSION) ||
              asString(process.env.npm_package_version) ||
              undefined,
            mode: cfg.mode,
            projectId: cfg.projectId,
          },
        },
      } as any);

      const emitInventorySnapshot = async (reason: "startup" | "periodic") => {
        if (!queue || inventorySnapshotInFlight) return;
        inventorySnapshotInFlight = true;
        const startedAt = Date.now();
        try {
          const { snapshot } = await collectAgentInventorySnapshot({
            cfg,
            reason,
            runtimeIdentity: runtimeIdentity || undefined,
          });
          queue.emit({
            category: "agent",
            action: "inventory_snapshot",
            severity: "info",
            outcome: "allow",
            durationMs: Date.now() - startedAt,
            traceId: bootstrapTraceId,
            rootExecutionId: bootstrapTraceId,
            payload: {
              type: "agent.inventory_snapshot",
              inventory: snapshot,
            },
          } as any);
        } catch (err) {
          queue.emit({
            category: "agent",
            action: "inventory_snapshot_error",
            severity: "warn",
            traceId: bootstrapTraceId,
            rootExecutionId: bootstrapTraceId,
            durationMs: Date.now() - startedAt,
            outcome: "error",
            outcomeReason: "inventory snapshot collection failed",
            errorClass: "inventory_collection_error",
            errorCode: "inventory_snapshot_failed",
            payload: { reason, error: String(err) },
          } as any);
        } finally {
          inventorySnapshotInFlight = false;
        }
      };

      await emitInventorySnapshot("startup");
      inventoryTimer = setInterval(() => {
        void emitInventorySnapshot("periodic");
      }, 10 * 60 * 1000);

      const rt: ClawsightRuntime = {
        config: cfg,
        emit: (evt) => {
          if (!queue) {
            return;
          }
          queue.emit(evt as any);
        },
        decideToolCall: async (req: ToolDecisionRequest): Promise<ToolDecision | null> => {
          if (!cfg.enabled || cfg.mode !== "enforce") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: ToolDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideToolCall(decisionReq);
            const durationMs = Date.now() - startedAt;
            const shouldEmitPolicyDecision =
              decision.action !== "allow" || Boolean(decision.decisionId || decision.ruleId);
            if (shouldEmitPolicyDecision) {
              queue?.emit({
                category: "policy",
                action: "tool_decision",
                severity: decision.action === "block" || decision.action === "warn" ? "warn" : "info",
                requestId,
                traceId: req.traceId,
                correlationId: req.traceId,
                rootExecutionId: req.rootExecutionId,
                rootMessageId: req.rootMessageId,
                parentSpanId: req.parentSpanId,
                durationMs,
                latencyMs: durationMs,
                outcome: decision.action,
                outcomeReason:
                  decision.action === "block" ||
                  decision.action === "warn" ||
                  decision.action === "modify"
                    ? (decision as { reason?: string }).reason
                    : undefined,
                policyRuleId: decision.ruleId,
                policyDecisionId: decision.decisionId,
                openclaw: { agentId: req.agentId, sessionKey: req.sessionKey, toolName: req.toolName },
                policyDecision: {
                  requestId,
                  decisionId: decision.decisionId,
                  action: decision.action,
                  reason:
                    decision.action === "block" ||
                    decision.action === "warn" ||
                    decision.action === "modify"
                      ? (decision as { reason?: string }).reason
                      : undefined,
                  latencyMs: durationMs,
                  ruleId: decision.ruleId,
                },
                payload: { toolName: req.toolName, params: sanitizeForTelemetry(req) },
              } as any);
            }
            return decision;
          } catch (err) {
            const fallback = canFailOpenOnError(cfg.mode, req.toolName);
            const durationMs = Date.now() - startedAt;
            queue?.emit({
              category: "policy",
              action: "decide_error",
              severity: "warn",
              requestId,
              traceId: req.traceId,
              correlationId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              parentSpanId: req.parentSpanId,
              durationMs,
              latencyMs: durationMs,
              outcome: fallback ? "allow" : "block",
              outcomeReason: String(err),
              errorClass: "policy_service_error",
              errorCode: "tool_decide_failed",
              openclaw: { agentId: req.agentId, sessionKey: req.sessionKey, toolName: req.toolName },
              payload: {
                toolName: req.toolName,
                kind: "tool",
                error: String(err),
                fallbackToAllow: fallback,
              },
            } as any);
            if (fallback) {
              return null;
            }
            return { action: "block", reason: "policy service unavailable for high-risk action" };
          }
        },
        decideOutboundMessage: async (
          req: MessageDecisionRequest,
        ): Promise<MessageDecision | null> => {
          if (!cfg.enabled || cfg.mode !== "enforce") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: MessageDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideOutboundMessage(decisionReq);
            const durationMs = Date.now() - startedAt;
            const shouldEmitPolicyDecision =
              decision.action !== "allow" || Boolean(decision.decisionId || decision.ruleId);
            if (shouldEmitPolicyDecision) {
              queue?.emit({
                category: "policy",
                action: "message_decision",
                severity: decision.action === "block" || decision.action === "warn" ? "warn" : "info",
                requestId,
                durationMs,
                latencyMs: durationMs,
                outcome: decision.action,
                outcomeReason:
                  decision.action === "block" ||
                  decision.action === "warn" ||
                  decision.action === "modify"
                    ? decision.reason
                    : undefined,
                policyRuleId: decision.ruleId,
                policyDecisionId: decision.decisionId,
                policyDecision: {
                  requestId,
                  decisionId: decision.decisionId,
                  action: decision.action,
                  reason:
                    decision.action === "block" ||
                    decision.action === "warn" ||
                    decision.action === "modify"
                      ? decision.reason
                      : undefined,
                  latencyMs: durationMs,
                  ruleId: decision.ruleId,
                },
                payload: {
                  channelId: req.channelId,
                  to: clampAddress(req.to),
                  actionLen: req.content.length,
                  preview: shortText(req.content, 120),
                },
              } as any);
            }
            return decision;
          } catch (err) {
            queue?.emit({
              category: "policy",
              action: "decide_error",
              severity: "warn",
              requestId,
              durationMs: Date.now() - startedAt,
              outcome: "allow",
              outcomeReason: "policy service unavailable; fail-open applied",
              errorClass: "policy_service_error",
              errorCode: "message_decide_failed",
              payload: { kind: "message", error: String(err), channelId: req.channelId },
            } as any);
            return null;
          }
        },
        decideInboundMessage: async (
          req: InboundMessageDecisionRequest,
        ): Promise<InboundMessageDecision | null> => {
          if (!cfg.enabled || cfg.mode === "off") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: InboundMessageDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideInboundMessage(decisionReq);
            const durationMs = Date.now() - startedAt;
            const shouldEmit = decision.action !== "allow" || Boolean(decision.decisionId || decision.ruleId);
            if (shouldEmit) {
              queue?.emit({
                category: "policy",
                action: "inbound_message_decision",
                severity: decision.action === "block" ? "warn" : "info",
                requestId,
                durationMs,
                latencyMs: durationMs,
                outcome: decision.action,
                outcomeReason: decision.reason,
                policyRuleId: decision.ruleId,
                policyDecisionId: decision.decisionId,
                openclaw: { sessionKey: req.sessionKey },
                payload: {
                  channelId: req.channelId,
                  from: clampAddress(req.from),
                  enforcement: decision.enforcement,
                  signals: (decision.signals ?? []).slice(0, 20),
                },
              } as any);
            }
            return decision;
          } catch (err) {
            queue?.emit({
              category: "policy",
              action: "decide_error",
              severity: "warn",
              requestId,
              durationMs: Date.now() - startedAt,
              outcome: "allow",
              outcomeReason: "inbound policy check unavailable; fail-open applied",
              errorClass: "policy_service_error",
              errorCode: "inbound_decide_failed",
              payload: { kind: "inbound_message", error: String(err), channelId: req.channelId },
            } as any);
            return null;
          }
        },
        decideIntentBaseline: async (
          req: IntentBaselineDecisionRequest,
        ): Promise<IntentDecision | null> => {
          if (!cfg.enabled || cfg.mode === "off") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: IntentBaselineDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideIntentBaseline(decisionReq);
            const durationMs = Date.now() - startedAt;
            queue?.emit({
              category: "policy",
              action: "intent_baseline_decision",
              severity:
                decision.action === "block"
                  ? "warn"
                  : decision.action === "warn" || decision.action === "modify"
                    ? "info"
                    : "debug",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs,
              latencyMs: durationMs,
              outcome: decision.action as any,
              outcomeReason: decision.reason,
              policyDecisionId: decision.decisionId,
              payload: {
                mode: decision.mode,
                confidence: decision.confidence,
                scoreDelta: decision.scoreDelta,
                driftScore: decision.driftScore,
                signals: decision.signals,
                expectedScopes: decision.expectedScopes,
                expectedDomains: decision.expectedDomains,
              },
            } as any);
            return decision;
          } catch (err) {
            queue?.emit({
              category: "policy",
              action: "intent_baseline_error",
              severity: "warn",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs: Date.now() - startedAt,
              outcome: "allow",
              outcomeReason: "intent baseline unavailable; fail-open applied",
              errorClass: "policy_service_error",
              errorCode: "intent_baseline_failed",
              payload: { kind: "intent_baseline", error: String(err) },
            } as any);
            return null;
          }
        },
        decideIntentAction: async (
          req: IntentActionDecisionRequest,
        ): Promise<IntentDecision | null> => {
          if (!cfg.enabled || cfg.mode === "off") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: IntentActionDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideIntentAction(decisionReq);
            const durationMs = Date.now() - startedAt;
            queue?.emit({
              category: "policy",
              action: "intent_action_decision",
              severity:
                decision.action === "block"
                  ? "warn"
                  : decision.action === "warn" || decision.action === "modify"
                    ? "info"
                    : "debug",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs,
              latencyMs: durationMs,
              outcome: decision.action as any,
              outcomeReason: decision.reason,
              policyDecisionId: decision.decisionId,
              openclaw: { toolName: req.toolName },
              payload: {
                mode: decision.mode,
                confidence: decision.confidence,
                scoreDelta: decision.scoreDelta,
                driftScore: decision.driftScore,
                signals: decision.signals,
                targetDomains: decision.targetDomains,
                expectedScopes: decision.expectedScopes,
                expectedDomains: decision.expectedDomains,
              },
            } as any);
            return decision;
          } catch (err) {
            const fallback = canFailOpenOnError(cfg.mode, req.toolName);
            queue?.emit({
              category: "policy",
              action: "intent_action_error",
              severity: "warn",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs: Date.now() - startedAt,
              outcome: fallback ? "allow" : "block",
              outcomeReason: "intent action check unavailable",
              errorClass: "policy_service_error",
              errorCode: "intent_action_failed",
              openclaw: { toolName: req.toolName },
              payload: { kind: "intent_action", error: String(err), fallbackToAllow: fallback },
            } as any);
            if (fallback) return null;
            return { action: "block", reason: "intent policy unavailable for high-risk action" };
          }
        },
        decideIntentOutput: async (
          req: IntentOutputDecisionRequest,
        ): Promise<IntentDecision | null> => {
          if (!cfg.enabled || cfg.mode === "off") {
            return null;
          }
          const requestId = req.requestId ?? crypto.randomUUID();
          const startedAt = Date.now();
          const decisionReq: IntentOutputDecisionRequest = {
            ...req,
            requestId,
            projectId: req.projectId ?? cfg.projectId,
            agentInstanceId: req.agentInstanceId ?? cfg.agentInstanceId,
            agentName: req.agentName ?? cfg.agentName,
          };
          try {
            const decision = await client.decideIntentOutput(decisionReq);
            const durationMs = Date.now() - startedAt;
            queue?.emit({
              category: "policy",
              action: "intent_output_decision",
              severity:
                decision.action === "block"
                  ? "warn"
                  : decision.action === "warn" || decision.action === "modify"
                    ? "info"
                    : "debug",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs,
              latencyMs: durationMs,
              outcome: decision.action as any,
              outcomeReason: decision.reason,
              policyDecisionId: decision.decisionId,
              openclaw: { toolName: req.toolName, toolCallId: req.toolCallId },
              payload: {
                mode: decision.mode,
                confidence: decision.confidence,
                scoreDelta: decision.scoreDelta,
                driftScore: decision.driftScore,
                signals: decision.signals,
                sanitized: typeof decision.sanitizedContent === "string" && decision.sanitizedContent.length > 0,
              },
            } as any);
            return decision;
          } catch (err) {
            queue?.emit({
              category: "policy",
              action: "intent_output_error",
              severity: "warn",
              requestId,
              traceId: req.traceId,
              rootExecutionId: req.rootExecutionId,
              rootMessageId: req.rootMessageId,
              durationMs: Date.now() - startedAt,
              outcome: "allow",
              outcomeReason: "intent output check unavailable; fail-open applied",
              errorClass: "policy_service_error",
              errorCode: "intent_output_failed",
              openclaw: { toolName: req.toolName, toolCallId: req.toolCallId },
              payload: { kind: "intent_output", error: String(err) },
            } as any);
            return null;
          }
        },
        paymentsSend: async (req: PaymentsSendRequest): Promise<PaymentsSendResponse> => {
          const requestId = crypto.randomUUID();
          const startedAt = Date.now();
          queue?.emit({
            category: "payment",
            action: "send_request",
            severity: "debug",
            requestId,
            payload: {
              toAddress: clampAddress(req.toAddress),
              amount: req.amount,
              chain: req.chain,
              asset: req.asset,
              hasMemo: Boolean(req.memo),
            },
          } as any);
          try {
            const response = await client.paymentsSend(req);
            queue?.emit({
              category: "payment",
              action: "send_result",
              severity: response.status === "blocked" ? "warn" : response.status === "submitted" ? "info" : "error",
              requestId,
              durationMs: Date.now() - startedAt,
              result: response.status === "submitted" ? "ok" : response.status === "blocked" ? "blocked" : "error",
              payload: {
                status: response.status,
                decisionId: response.decisionId,
                txId: response.txId,
                reason: response.reason,
                toAddress: clampAddress(req.toAddress),
                amount: req.amount,
              },
            } as any);
            return response;
          } catch (err) {
            queue?.emit({
              category: "payment",
              action: "send_error",
              severity: "error",
              requestId,
              durationMs: Date.now() - startedAt,
              result: "error",
              payload: { toAddress: req.toAddress, amount: req.amount, error: String(err) },
            } as any);
            throw err;
          }
        },
        stop: async () => {
          if (inventoryTimer) {
            clearInterval(inventoryTimer);
            inventoryTimer = null;
          }
          if (unsubscribeDiagnostics) {
            unsubscribeDiagnostics();
            unsubscribeDiagnostics = null;
          }
          if (stopLogTransport) {
            stopLogTransport();
            stopLogTransport = null;
          }
          if (queue) {
            await queue.stop();
            queue = null;
          }
          setRuntime(null);
        },
      };

      runtime = rt;
      setRuntime(rt);

      // =============================================================================
      // Global event sources (best-effort)
      // =============================================================================

      if (cfg.capture.diagnostics) {
        unsubscribeDiagnostics = onDiagnosticEvent((evt) => {
          const diagnostic = evt as Record<string, unknown>;
          const type = asString(diagnostic.type) || "diagnostic";
          const runId = asString(diagnostic.runId);
          const sessionKey = asString(diagnostic.sessionKey);
          const sessionId = asString(diagnostic.sessionId);
          const channel = asString(diagnostic.channel);
          const reason = asString(diagnostic.reason);
          const sessionKind = resolveSessionKind(sessionKey);
          const trigger = resolveDiagnosticTriggerType({
            type,
            sessionKey,
            channel,
            reason,
          });
          const traceId = runId || (sessionKey ? `session:${sessionKey}` : undefined);

          const payloadRecord =
            evt && typeof evt === "object" && !Array.isArray(evt)
              ? ({ ...(evt as Record<string, unknown>) } as Record<string, unknown>)
              : ({ value: evt } as Record<string, unknown>);
          const execution = {
            trigger,
            sessionKind,
            messageProvider: channel,
            reason,
            rootExecutionId: traceId,
          };
          payloadRecord.execution =
            payloadRecord.execution && typeof payloadRecord.execution === "object" && !Array.isArray(payloadRecord.execution)
              ? { ...(payloadRecord.execution as Record<string, unknown>), ...execution }
              : execution;

          queue?.emit({
            category: "diagnostic",
            action: type,
            severity: diagnosticSeverity(type),
            traceId,
            correlationId: traceId,
            spanId: crypto.randomUUID(),
            openclaw: {
              sessionKey,
              sessionId,
              runId,
              messageProvider: channel,
            },
            payload: payloadRecord,
          } as any);
        });
      }

      if (cfg.capture.logs) {
        stopLogTransport = registerLogTransport((logObj) => {
          // Avoid exploding payload sizes. Keep logs shallow and capped.
          const record =
            logObj && typeof logObj === "object" && !Array.isArray(logObj)
              ? (logObj as Record<string, unknown>)
              : { message: String(logObj) };
          queue?.emit({
            category: "log",
            action: "log",
            severity: "debug",
            payload: {
              time: record.time,
              // tslog transports include numeric args ("0","1",...) - keep only a bounded preview.
              preview: safeStringify(record).slice(0, 20_000),
            },
          } as any);
        });
      }

      ctx.logger.info(
        `clawsight: enabled mode=${cfg.mode} platform=${cfg.platformUrl} capture=${safeStringify(cfg.capture)}`,
      );
    },

    async stop(ctx) {
      try {
        await runtime?.stop();
      } catch (err) {
        ctx.logger.warn(`clawsight: stop failed: ${String(err)}`);
      } finally {
        runtime = null;
        setRuntime(null);
      }
    },
  };
}

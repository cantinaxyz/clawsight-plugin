/**
 * @module platform-client
 * @description HTTP client for the Clawsight platform API. Provides typed
 * methods for telemetry ingestion, policy decision endpoints (tool calls,
 * outbound/inbound messages, intent baseline/action/output), and payment
 * submission. All network calls are POST requests with JSON bodies, protected
 * by a configurable timeout and optional Bearer-token authentication.
 */

import type {
  ClawsightPluginConfig,
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
  TelemetryEnvelope,
  ToolDecision,
  ToolDecisionRequest,
} from "./service-types.js";

/**
 * @description Joins a base URL and a path segment, normalising trailing and
 * leading slashes so that exactly one slash separates them.
 * @param base - The base URL (trailing slashes are stripped).
 * @param path - The path segment to append (a leading slash is added if absent).
 * @returns The concatenated URL string.
 */
function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

/**
 * @description Safely narrows an unknown value to a plain record (object) type.
 * Returns null for primitives, arrays, and nullish values.
 * @param value - The value to check.
 * @returns The value cast to a record, or null if it is not a plain object.
 */
function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * @description HTTP client for the Clawsight platform. Encapsulates all
 * outbound API calls including telemetry ingestion, policy decision requests
 * (tool, message, inbound message, intent), and payment submission. Each method
 * constructs the appropriate URL from the plugin configuration, serialises the
 * request as JSON, and parses the typed response.
 */
export class PlatformClient {
  /** The plugin configuration containing URLs, paths, tokens, and network settings. */
  readonly cfg: ClawsightPluginConfig;

  /**
   * @description Creates a new PlatformClient instance.
   * @param cfg - The full Clawsight plugin configuration.
   */
  constructor(cfg: ClawsightPluginConfig) {
    this.cfg = cfg;
  }

  /**
   * @description Convenience wrapper around {@link postJsonWithMetadata} that
   * omits the optional request ID header.
   * @param url - The fully-qualified endpoint URL.
   * @param body - The request payload (will be JSON-serialised).
   * @returns The parsed JSON response cast to type T.
   */
  private async postJson<T>(url: string, body: unknown): Promise<T> {
    return this.postJsonWithMetadata<T>(url, body);
  }

  /**
   * @description Sends a POST request with a JSON body to the given URL. Attaches
   * the Bearer authentication token (if configured) and an optional
   * `x-clawsight-request-id` header. The request is aborted if it exceeds the
   * configured timeout. Non-2xx responses throw an error containing the HTTP
   * status and the first 500 characters of the response body.
   * @param url - The fully-qualified endpoint URL.
   * @param body - The request payload (will be JSON-serialised).
   * @param requestId - Optional correlation ID sent as a request header.
   * @returns The parsed JSON response cast to type T, or undefined for empty responses.
   */
  private async postJsonWithMetadata<T>(url: string, body: unknown, requestId?: string): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.cfg.apiToken) {
      headers.authorization = `Bearer ${this.cfg.apiToken}`;
    }
    if (requestId) {
      headers["x-clawsight-request-id"] = requestId;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.cfg.network.timeoutMs);
    try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
      const text = await res.text();
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 500)}`);
      }
      if (!text.trim()) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-return
        return undefined as T;
      }
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * @description Sends a batch of telemetry events to the platform ingestion
   * endpoint.
   * @param events - The array of telemetry envelopes to ingest.
   */
  async ingest(events: TelemetryEnvelope[]): Promise<void> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.ingestPath);
    await this.postJson(url, { events });
  }

  /**
   * @description Requests a policy decision for a tool call. The platform may
   * respond with "allow", "warn", "block", or "modify" (with replacement params).
   * @param req - The tool decision request containing tool name, parameters, and metadata.
   * @returns A typed decision indicating the allowed action and optional reason,
   * decision ID, rule ID, or modified parameters.
   */
  async decideToolCall(req: ToolDecisionRequest): Promise<ToolDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "tool", ...req }, req.requestId);
    const record = asRecord(res);
    const action = String(record?.action ?? "allow");
    const decisionId = typeof record?.decisionId === "string" ? record.decisionId : undefined;
    const ruleId = typeof record?.ruleId === "string" ? record.ruleId : undefined;
    if (action === "warn") {
      return {
        action: "warn",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "block") {
      return {
        action: "block",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "modify") {
      const params = asRecord(record?.params) ?? {};
      return {
        action: "modify",
        params,
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    return { action: "allow", decisionId, ruleId };
  }

  /**
   * @description Requests a policy decision for an outbound message. The platform
   * may respond with "allow", "warn", "block", or "modify" (with replacement content).
   * @param req - The message decision request containing content, recipient, and metadata.
   * @returns A typed decision indicating the allowed action and optional reason,
   * decision ID, rule ID, or modified content.
   */
  async decideOutboundMessage(req: MessageDecisionRequest): Promise<MessageDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "message", ...req }, req.requestId);
    const record = asRecord(res);
    const action = String(record?.action ?? "allow");
    const decisionId = typeof record?.decisionId === "string" ? record.decisionId : undefined;
    const ruleId = typeof record?.ruleId === "string" ? record.ruleId : undefined;
    if (action === "warn") {
      return {
        action: "warn",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "block") {
      return {
        action: "block",
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    if (action === "modify") {
      return {
        action: "modify",
        content: typeof record?.content === "string" ? record.content : req.content,
        reason: typeof record?.reason === "string" ? record.reason : undefined,
        decisionId,
        ruleId,
      };
    }
    return { action: "allow", decisionId, ruleId };
  }

  /**
   * @description Requests a policy decision for an inbound message. The platform
   * may respond with "allow" or "block", along with an enforcement level
   * ("advisory" or "hard") and optional threat signals.
   * @param req - The inbound message decision request containing message content and metadata.
   * @returns A typed decision with action, enforcement level, optional signals,
   * reason, decision ID, and rule ID.
   */
  async decideInboundMessage(req: InboundMessageDecisionRequest): Promise<InboundMessageDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "inbound_message", ...req }, req.requestId);
    const record = asRecord(res);
    const actionRaw = String(record?.action ?? "allow");
    const action: InboundMessageDecision["action"] = actionRaw === "block" ? "block" : "allow";
    const enforcementRaw = String(record?.enforcement ?? "advisory");
    const enforcement: InboundMessageDecision["enforcement"] =
      enforcementRaw === "hard" ? "hard" : "advisory";
    const signalsRaw = Array.isArray(record?.signals) ? record?.signals : [];
    const signals = signalsRaw
      .map((item) => (typeof item === "string" ? item : String(item)))
      .slice(0, 20);
    return {
      action,
      enforcement,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      ruleId: typeof record?.ruleId === "string" ? record.ruleId : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      signals,
    };
  }

  /**
   * @description Requests an intent-baseline policy decision. This is used to
   * establish a baseline drift score and expected domains/scopes at the start of
   * an interaction.
   * @param req - The intent baseline decision request with session and content details.
   * @returns A typed intent decision including action, mode, drift score,
   * confidence, signals, and domain/scope lists.
   */
  async decideIntentBaseline(req: IntentBaselineDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_baseline", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  /**
   * @description Requests an intent-action policy decision. Evaluates whether a
   * proposed action (e.g. tool invocation) is consistent with the established
   * intent baseline.
   * @param req - The intent action decision request with the proposed action details.
   * @returns A typed intent decision including action, mode, drift score,
   * confidence, signals, and domain/scope lists.
   */
  async decideIntentAction(req: IntentActionDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_action", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  /**
   * @description Requests an intent-output policy decision. Evaluates whether the
   * output of an action is consistent with the established intent baseline.
   * @param req - The intent output decision request with the action output details.
   * @returns A typed intent decision including action, mode, drift score,
   * confidence, signals, and domain/scope lists.
   */
  async decideIntentOutput(req: IntentOutputDecisionRequest): Promise<IntentDecision> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.decidePath);
    const res = await this.postJsonWithMetadata(url, { kind: "intent_output", ...req }, req.requestId);
    const record = asRecord(res);
    return {
      action: String(record?.action ?? "allow") as IntentDecision["action"],
      mode:
        String(record?.mode) === "off" || String(record?.mode) === "enforce" || String(record?.mode) === "audit"
          ? (String(record?.mode) as IntentDecision["mode"])
          : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      scoreDelta: typeof record?.scoreDelta === "number" ? record.scoreDelta : undefined,
      driftScore: typeof record?.driftScore === "number" ? record.driftScore : undefined,
      confidence: typeof record?.confidence === "number" ? record.confidence : undefined,
      signals: Array.isArray(record?.signals) ? record.signals.map((v) => String(v)).slice(0, 20) : undefined,
      targetDomains: Array.isArray(record?.targetDomains) ? record.targetDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedDomains: Array.isArray(record?.expectedDomains) ? record.expectedDomains.map((v) => String(v)).slice(0, 20) : undefined,
      expectedScopes: Array.isArray(record?.expectedScopes) ? record.expectedScopes.map((v) => String(v)).slice(0, 20) : undefined,
      sanitizedContent: typeof record?.sanitizedContent === "string" ? record.sanitizedContent : undefined,
    };
  }

  /**
   * @description Submits a payment send request to the platform. The response
   * indicates whether the payment was submitted, blocked, or encountered an error.
   * @param req - The payment request payload.
   * @returns A typed response with status ("submitted", "blocked", or "error"),
   * optional transaction ID, decision ID, and reason.
   */
  async paymentsSend(req: PaymentsSendRequest): Promise<PaymentsSendResponse> {
    const url = joinUrl(this.cfg.platformUrl, this.cfg.paymentsSendPath);
    const res = await this.postJson(url, req);
    const record = asRecord(res);
    const statusRaw = typeof record?.status === "string" ? record.status : "error";
    const status: PaymentsSendResponse["status"] =
      statusRaw === "submitted" || statusRaw === "blocked" || statusRaw === "error"
        ? statusRaw
        : "error";
    return {
      status,
      txId: typeof record?.txId === "string" ? record.txId : undefined,
      decisionId: typeof record?.decisionId === "string" ? record.decisionId : undefined,
      reason: typeof record?.reason === "string" ? record.reason : undefined,
    };
  }
}

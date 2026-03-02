/**
 * @module config
 * @description Configuration resolution for the ClawSight plugin. Accepts a
 * raw key-value object (typically sourced from the OpenClaw plugin manifest or
 * environment) and produces a fully-validated {@link ClawsightPluginConfig}
 * with sensible defaults for every field.
 */

import path from "node:path";
import os from "node:os";
import type { ClawsightPluginConfig, ClawsightMode } from "./service-types.js";

/**
 * @description Coerces an unknown value to a boolean, returning the supplied
 * default when the value is not already a boolean.
 * @param value - The raw value to inspect.
 * @param defaultValue - Fallback if `value` is not a boolean.
 * @returns The boolean value or the default.
 */
function asBoolean(value: unknown, defaultValue: boolean): boolean {
  return typeof value === "boolean" ? value : defaultValue;
}

/**
 * @description Coerces an unknown value to a finite number, returning the
 * supplied default when the value is not a finite number.
 * @param value - The raw value to inspect.
 * @param defaultValue - Fallback if `value` is not a finite number.
 * @returns The numeric value or the default.
 */
function asNumber(value: unknown, defaultValue: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : defaultValue;
}

/**
 * @description Coerces an unknown value to a trimmed, non-empty string.
 * Returns `undefined` if the value is not a string or is blank after trimming.
 * @param value - The raw value to inspect.
 * @returns The trimmed string or `undefined`.
 */
function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

/**
 * @description Coerces an unknown value to one of the recognised
 * {@link ClawsightMode} literals (`"off"`, `"audit"`, `"enforce"`, `"local"`).
 * Returns the default if the value does not match any valid mode.
 * @param value - The raw value to inspect.
 * @param defaultValue - Fallback mode.
 * @returns A valid {@link ClawsightMode}.
 */
function asMode(value: unknown, defaultValue: ClawsightMode): ClawsightMode {
  const raw = asString(value)?.toLowerCase();
  if (raw === "off" || raw === "audit" || raw === "enforce" || raw === "local") {
    return raw;
  }
  return defaultValue;
}

/**
 * @description Concatenates a base URL and a path segment, ensuring exactly one
 * slash separates them and stripping trailing slashes from the base.
 * @param base - The base URL (e.g. `"https://api.example.com"`).
 * @param path - The path to append (e.g. `"/v1/ingest"`).
 * @returns The joined URL string.
 */
function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

/**
 * @description Transforms a raw configuration object into a fully-resolved
 * {@link ClawsightPluginConfig}. Missing or invalid values are replaced with
 * sensible defaults. Numeric values are clamped to their minimum thresholds
 * (e.g. `flushIntervalMs >= 250`, `batchMaxEvents >= 1`).
 * @param raw - Untyped key-value configuration object.
 * @returns A complete, validated plugin configuration.
 */
export function resolvePluginConfig(raw: Record<string, unknown>): ClawsightPluginConfig {
  const enabled = asBoolean(raw.enabled, true);
  const mode = asMode(raw.mode, "audit");
  const platformUrl = asString(raw.platformUrl) ?? "";

  const apiToken = asString(raw.apiToken);
  const projectId = asString(raw.projectId);
  const agentInstanceId = asString(raw.agentInstanceId);
  const agentName = asString(raw.agentName);
  const identityPath = asString(raw.identityPath);
  const localRulesPath =
    asString(raw.localRulesPath) ??
    (mode === "local"
      ? path.join(os.homedir(), ".openclaw", "plugins", "clawsight", "rules.json")
      : undefined);

  const ingestPath = asString(raw.ingestPath) ?? "/v1/telemetry/ingest";
  const decidePath = asString(raw.decidePath) ?? "/v1/guardrails/decide";
  const paymentsSendPath = asString(raw.paymentsSendPath) ?? "/v1/payments/send";

  const flushIntervalMs = Math.max(250, asNumber(raw.flushIntervalMs, 1000));
  const batchMaxEvents = Math.max(1, Math.floor(asNumber(raw.batchMaxEvents, 200)));

  const captureRaw = raw.capture && typeof raw.capture === "object" ? (raw.capture as any) : {};
  const capture = {
    messages: asBoolean(captureRaw.messages, true),
    messageBody: asBoolean(captureRaw.messageBody, false),
    tools: asBoolean(captureRaw.tools, true),
    toolParams: asBoolean(captureRaw.toolParams, true),
    toolResult: asBoolean(captureRaw.toolResult, false),
    diagnostics: asBoolean(captureRaw.diagnostics, true),
    logs: asBoolean(captureRaw.logs, false),
  };

  const networkRaw = raw.network && typeof raw.network === "object" ? (raw.network as any) : {};
  const network = {
    timeoutMs: Math.max(1000, asNumber(networkRaw.timeoutMs, 30_000)),
  };

  return {
    enabled,
    mode,
    platformUrl,
    localRulesPath,
    apiToken,
    projectId,
    agentInstanceId,
    agentName,
    identityPath,
    ingestPath,
    decidePath,
    paymentsSendPath,
    flushIntervalMs,
    batchMaxEvents,
    capture,
    network,
  };
}

export const __internal = { joinUrl };

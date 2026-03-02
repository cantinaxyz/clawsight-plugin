/**
 * @module redact
 * @description Redacts and sanitizes hook event payloads before they are sent as
 * telemetry. Message bodies are replaced with their SHA-256 hashes and length,
 * large or deeply nested values are truncated, and file/URL/media artifact
 * metadata is extracted into a normalised list. The single exported function,
 * {@link redactHookEventForTelemetry}, is the entry point used by the
 * telemetry pipeline.
 */

import crypto from "node:crypto";
import type { ClawsightCaptureConfig } from "../service-types.js";

type RedactInput = {
  hook: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  event: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  context?: any;
  capture: ClawsightCaptureConfig;
};

type Artifact = {
  kind: "file" | "url" | "media";
  label?: string;
  mimeType?: string;
  fileName?: string;
  filePath?: string;
  url?: string;
  source: string;
};

/**
 * @description Computes the Base64-encoded SHA-256 hash of the given text.
 * @param text - The plaintext string to hash.
 * @returns The Base64-encoded SHA-256 digest.
 */
function sha256Base64(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64");
}

/**
 * @description Truncates a string to the specified maximum length, appending an
 * ellipsis character if truncation occurs.
 * @param value - The string to truncate.
 * @param max - The maximum allowed character length.
 * @returns The original string if within the limit, or a truncated copy with a trailing ellipsis.
 */
function truncateString(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}…`;
}

/**
 * @description Recursively truncates an unknown value. Strings are capped at
 * {@link maxStr} characters, arrays are limited to the first 50 elements, and
 * objects are limited to the first 50 entries. Nested structures are processed
 * recursively.
 * @param value - The value to truncate.
 * @param maxStr - Maximum character length for individual strings (default 4000).
 * @returns A structurally similar copy of the input with all leaf strings and
 * collection sizes bounded.
 */
function truncateUnknown(value: unknown, maxStr = 4_000): unknown {
  if (typeof value === "string") {
    return truncateString(value, maxStr);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((v) => truncateUnknown(v, maxStr));
  }
  if (value && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const entries = Object.entries(rec).slice(0, 50);
    for (const [k, v] of entries) {
      out[k] = truncateUnknown(v, maxStr);
    }
    return out;
  }
  return value;
}

/**
 * @description Replaces a message body with its SHA-256 hash and character length,
 * effectively stripping the raw content while preserving a fingerprint.
 * @param body - The raw message body string.
 * @returns An object containing the (potentially empty) body, its SHA-256 hash,
 * and its character length.
 */
function redactMessageBody(body: string) {
  const trimmed = body ?? "";
  return { body: trimmed, bodySha256: sha256Base64(trimmed), len: trimmed.length };
}

/**
 * @description Safely narrows an unknown value to a plain record (object) type.
 * Returns null for primitives, arrays, and nullish values.
 * @param value - The value to check.
 * @returns The value cast to a record, or null if it is not a plain object.
 */
function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

/**
 * @description Extracts a non-empty trimmed string from an unknown value.
 * Returns undefined if the value is not a string or is blank after trimming.
 * @param value - The value to coerce.
 * @returns The trimmed string, or undefined.
 */
function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * @description Attempts to interpret a record as an {@link Artifact} by probing
 * common property names for file paths, URLs, file names, MIME types, and labels.
 * Returns null when none of the expected keys are present.
 * @param rec - The record to inspect.
 * @param source - A dot-delimited path describing where in the event tree this
 * record was found (e.g. "event.attachments").
 * @returns A normalised Artifact, or null if no artifact-like properties exist.
 */
function maybeArtifact(
  rec: Record<string, unknown>,
  source: string,
): Artifact | null {
  const filePath =
    asString(rec.file_path) ??
    asString(rec.filePath) ??
    asString(rec.path) ??
    asString(rec.mediaPath);
  const url =
    asString(rec.url) ??
    asString(rec.mediaUrl) ??
    asString(rec.href);
  const fileName =
    asString(rec.file_name) ??
    asString(rec.fileName) ??
    asString(rec.filename) ??
    asString(rec.name);
  const mimeType =
    asString(rec.mime_type) ??
    asString(rec.mimeType) ??
    asString(rec.mimetype) ??
    asString(rec.contentType) ??
    asString(rec.type);
  const label =
    asString(rec.label) ??
    asString(rec.kind) ??
    asString(rec.mediaType) ??
    asString(rec.type);

  if (!filePath && !url && !fileName && !mimeType) {
    return null;
  }

  const kind: Artifact["kind"] = filePath ? "file" : (url ? "url" : "media");
  return {
    kind,
    label,
    mimeType,
    fileName,
    filePath,
    url,
    source,
  };
}

/**
 * @description Adds an artifact to the output list if it is non-null and has not
 * already been recorded. Deduplication is based on a composite key of the
 * artifact's kind, file path, URL, file name, MIME type, and source.
 * @param out - The accumulator array of collected artifacts.
 * @param seen - A set of composite keys used for deduplication.
 * @param artifact - The artifact to conditionally add.
 */
function pushArtifact(out: Artifact[], seen: Set<string>, artifact: Artifact | null) {
  if (!artifact) return;
  const key = [
    artifact.kind,
    artifact.filePath ?? "",
    artifact.url ?? "",
    artifact.fileName ?? "",
    artifact.mimeType ?? "",
    artifact.source,
  ].join("|");
  if (seen.has(key)) return;
  seen.add(key);
  out.push(artifact);
}

/**
 * @description Recursively walks an unknown value tree (up to depth 4) looking for
 * artifact-like records. Arrays are scanned up to the first 32 elements, and
 * objects are probed on a set of well-known child keys such as "attachments",
 * "media", "files", etc.
 * @param value - The value to traverse.
 * @param source - Dot-delimited path describing the current position in the tree.
 * @param out - Accumulator array for discovered artifacts.
 * @param seen - Deduplication set of composite artifact keys.
 * @param depth - Current recursion depth (capped at 4).
 */
function collectArtifactsFromUnknown(
  value: unknown,
  source: string,
  out: Artifact[],
  seen: Set<string>,
  depth = 0,
) {
  if (depth > 4) return;
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 32)) {
      collectArtifactsFromUnknown(item, source, out, seen, depth + 1);
    }
    return;
  }

  const rec = asRecord(value);
  if (!rec) return;

  pushArtifact(out, seen, maybeArtifact(rec, source));

  const candidateKeys = [
    "attachments",
    "media",
    "files",
    "file",
    "documents",
    "document",
    "photos",
    "photo",
    "items",
    "mediaItems",
    "payload",
    "params",
    "metadata",
    "context",
  ];
  for (const key of candidateKeys) {
    if (!(key in rec)) continue;
    collectArtifactsFromUnknown(rec[key], `${source}.${key}`, out, seen, depth + 1);
  }
}

/**
 * @description Extracts a deduplicated list of artifacts from the event and
 * optional context objects. Returns at most 24 artifacts.
 * @param event - The hook event payload.
 * @param context - Optional additional context associated with the event.
 * @returns An array of normalised {@link Artifact} objects (max 24).
 */
function extractArtifacts(event: unknown, context?: unknown): Artifact[] {
  const out: Artifact[] = [];
  const seen = new Set<string>();
  collectArtifactsFromUnknown(event, "event", out, seen);
  collectArtifactsFromUnknown(context, "context", out, seen);
  return out.slice(0, 24);
}

/**
 * @description Transforms a raw hook event into a redacted, telemetry-safe
 * representation. The transformation is hook-specific:
 *
 * - **message_received** / **message_sending** / **message_sent** -- message
 *   bodies are replaced with their SHA-256 hash and length; metadata, context,
 *   and artifacts are preserved in truncated form.
 * - **before_tool_call** / **after_tool_call** -- tool parameters and results
 *   are optionally included based on the capture configuration, and artifacts
 *   are extracted.
 * - All other hooks fall through to a generic truncated representation of the
 *   entire event.
 *
 * @param input - The redaction input containing the hook name, event payload,
 * optional context, and capture configuration flags.
 * @returns A redacted plain object suitable for telemetry ingestion.
 */
export function redactHookEventForTelemetry(input: RedactInput): unknown {
  const { hook, event, context, capture } = input;

  if (hook === "message_received") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      from: event?.from,
      timestamp: event?.timestamp,
      ...redactMessageBody(content),
      metadata: truncateUnknown(event?.metadata),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "message_sending") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      to: event?.to,
      ...redactMessageBody(content),
      metadata: truncateUnknown(event?.metadata),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "message_sent") {
    const content = typeof event?.content === "string" ? event.content : "";
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      to: event?.to,
      success: Boolean(event?.success),
      error: event?.error,
      ...redactMessageBody(content),
      context: truncateUnknown(context),
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "before_tool_call") {
    const artifacts = extractArtifacts(event?.params ?? event, context);
    return {
      hook,
      toolName: event?.toolName,
      params: capture.toolParams ? truncateUnknown(event?.params) : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  if (hook === "after_tool_call") {
    const artifacts = extractArtifacts(event, context);
    return {
      hook,
      toolName: event?.toolName,
      params: capture.toolParams ? truncateUnknown(event?.params) : undefined,
      error: event?.error,
      durationMs: event?.durationMs,
      result: capture.toolResult ? truncateUnknown(event?.result) : undefined,
      artifacts: artifacts.length > 0 ? artifacts : undefined,
    };
  }

  return truncateUnknown({ hook, event, context });
}

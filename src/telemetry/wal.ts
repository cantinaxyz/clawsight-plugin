/**
 * @module telemetry/wal
 * @description Write-ahead log (WAL) for telemetry events. Provides durable,
 * newline-delimited JSON storage so that events are not lost if the process
 * crashes before the in-memory queue can be flushed to the platform. The WAL
 * supports append, full reload, and atomic rewrite operations.
 */

import fs from "node:fs/promises";
import path from "node:path";
import type { TelemetryEnvelope } from "../service-types.js";

/**
 * @description Type guard that checks whether a value is a non-empty string
 * (after trimming whitespace).
 * @param value - The value to check.
 * @returns `true` if `value` is a string with non-whitespace content.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * @description Attempts to parse a single JSON line. Returns `undefined`
 * instead of throwing when the input is not valid JSON.
 * @param line - A single line of text to parse.
 * @returns The parsed value, or `undefined` on failure.
 */
function safeParseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * @description Type guard that validates whether a parsed JSON value has the
 * minimum required shape of a {@link TelemetryEnvelope} (non-empty `eventId`,
 * numeric `ts`, and non-empty `category`).
 * @param value - The value to validate.
 * @returns `true` if the value satisfies the minimum envelope contract.
 */
function isTelemetryEnvelope(value: unknown): value is TelemetryEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  return isNonEmptyString(rec.eventId) && typeof rec.ts === "number" && isNonEmptyString(rec.category);
}

/**
 * @description Reads the WAL file and returns all valid telemetry envelopes
 * it contains. Lines that cannot be parsed or do not satisfy the envelope
 * schema are silently skipped. Returns an empty array if the file does not
 * exist or cannot be read.
 * @param filePath - Absolute path to the WAL file.
 * @returns An array of recovered {@link TelemetryEnvelope} records.
 */
export async function loadWal(filePath: string): Promise<TelemetryEnvelope[]> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, "utf8");
  } catch {
    return [];
  }
  const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  const out: TelemetryEnvelope[] = [];
  for (const line of lines) {
    const parsed = safeParseJsonLine(line);
    if (isTelemetryEnvelope(parsed)) {
      out.push(parsed);
    }
  }
  return out;
}

/**
 * @description Appends a single telemetry event to the WAL as a newline-
 * delimited JSON line. Creates parent directories if they do not exist.
 * @param filePath - Absolute path to the WAL file.
 * @param evt - The telemetry envelope to append.
 */
export async function appendWal(filePath: string, evt: TelemetryEnvelope): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const line = `${JSON.stringify(evt)}\n`;
  await fs.appendFile(filePath, line, { encoding: "utf8" });
}

/**
 * @description Atomically rewrites the WAL with the provided set of events.
 * Writes to a temporary file first and then renames it over the original to
 * avoid partial-write corruption. An empty `events` array results in an
 * empty file.
 * @param filePath - Absolute path to the WAL file.
 * @param events - The complete set of events that should remain in the WAL.
 */
export async function rewriteWal(filePath: string, events: TelemetryEnvelope[]): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp`;
  const payload =
    events.length === 0 ? "" : `${events.map((evt) => JSON.stringify(evt)).join("\n")}\n`;
  await fs.writeFile(tmpPath, payload, { encoding: "utf8" });
  await fs.rename(tmpPath, filePath);
}


/**
 * @module telemetry/queue
 * @description In-memory telemetry event queue that batches
 * {@link TelemetryEnvelope} events and periodically flushes them to the
 * ClawSight platform via a {@link PlatformClient}. The queue normalises
 * incoming events (assigning IDs, timestamps, and config-level defaults)
 * and respects the plugin's enabled/mode flags.
 */

import crypto from "node:crypto";
import type { PlatformClient } from "../platform-client.js";
import type { ClawsightPluginConfig, TelemetryEnvelope } from "../service-types.js";

/**
 * @description Returns the current wall-clock time in milliseconds.
 * @returns Milliseconds since the Unix epoch.
 */
function nowMs(): number {
  return Date.now();
}

/**
 * @description Fills in missing fields on a telemetry event using the
 * plugin configuration as a source of defaults. Generates a UUID for
 * `eventId` and stamps the current time for `ts` when they are absent.
 * @param cfg - The resolved plugin configuration supplying default identifiers.
 * @param evt - The raw telemetry envelope, potentially missing auto-filled fields.
 * @returns A fully-populated {@link TelemetryEnvelope}.
 */
function normalizeEvent(cfg: ClawsightPluginConfig, evt: TelemetryEnvelope): TelemetryEnvelope {
  return {
    ...evt,
    eventId: evt.eventId || crypto.randomUUID(),
    ts: typeof evt.ts === "number" ? evt.ts : nowMs(),
    severity: evt.severity ?? "info",
    projectId: evt.projectId ?? cfg.projectId,
    agentInstanceId: evt.agentInstanceId ?? cfg.agentInstanceId,
    agentName: evt.agentName ?? cfg.agentName,
  };
}

/**
 * @description Batching telemetry queue. Events are collected via {@link emit},
 * normalised, and held in memory until the periodic flush timer fires or
 * {@link flush} is called explicitly. Each flush sends at most
 * `cfg.batchMaxEvents` events to the platform and removes them from the
 * queue on success.
 */
export class TelemetryQueue {
  /** Resolved plugin configuration. */
  readonly cfg: ClawsightPluginConfig;
  /** Platform HTTP client used to ship event batches. */
  readonly client: PlatformClient;

  private queue: TelemetryEnvelope[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;

  /**
   * @description Creates a new TelemetryQueue.
   * @param params - Construction parameters.
   * @param params.cfg - Resolved plugin configuration.
   * @param params.client - Platform client for ingesting events.
   */
  constructor(params: {
    cfg: ClawsightPluginConfig;
    client: PlatformClient;
  }) {
    this.cfg = params.cfg;
    this.client = params.client;
  }

  /**
   * @description Starts the periodic flush timer. Events will be sent to the
   * platform at the interval defined by `cfg.flushIntervalMs`.
   */
  async start(): Promise<void> {
    this.flushTimer = setInterval(() => {
      void this.flush().catch(() => {});
    }, this.cfg.flushIntervalMs);
  }

  /**
   * @description Stops the periodic flush timer and performs a final flush to
   * drain any remaining events in the queue.
   */
  async stop(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  /**
   * @description Enqueues a telemetry event. The event is normalised (missing
   * `eventId`, `ts`, and identity fields are filled in) and appended to the
   * in-memory queue. No-ops when the plugin is disabled or the mode is `"off"`.
   * @param partial - A partial telemetry envelope; `eventId` and `ts` are optional.
   */
  emit(partial: Omit<TelemetryEnvelope, "eventId" | "ts"> & { eventId?: string; ts?: number }) {
    if (!this.cfg.enabled || this.cfg.mode === "off") {
      return;
    }
    const normalized = normalizeEvent(this.cfg, partial as TelemetryEnvelope);
    this.queue.push(normalized);
  }

  /**
   * @description Removes up to `cfg.batchMaxEvents` events from the front of
   * the queue and returns them as an array. Does not mutate the queue itself.
   * @returns A shallow copy of the next batch of events.
   */
  private dequeueBatch(): TelemetryEnvelope[] {
    const max = this.cfg.batchMaxEvents;
    if (this.queue.length <= max) {
      return [...this.queue];
    }
    return this.queue.slice(0, max);
  }

  /**
   * @description Sends the next batch of queued events to the platform.
   * Guards against concurrent flushes and no-ops when the queue is empty or
   * the plugin is disabled. Successfully ingested events are removed from
   * the queue.
   */
  async flush(): Promise<void> {
    if (!this.cfg.enabled || this.cfg.mode === "off") {
      return;
    }
    if (this.flushing) {
      return;
    }
    if (this.queue.length === 0) {
      return;
    }
    this.flushing = true;
    try {
      const batch = this.dequeueBatch();
      await this.client.ingest(batch);
      // Drop acknowledged events.
      this.queue.splice(0, batch.length);
    } finally {
      this.flushing = false;
    }
  }
}

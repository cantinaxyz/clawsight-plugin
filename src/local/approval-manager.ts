/**
 * @module approval-manager
 * @description In-memory pending approval system for "confirm" rules.
 *
 * When a confirm rule matches a tool call, the approval manager creates a
 * pending entry with a short hex ID (4 chars). The tool call is blocked and
 * the user is prompted to approve or deny via chat commands:
 *   /cs approve <id>   — one-time approval
 *   /cs deny <id>      — deny (blocks retries for the session)
 *   /cs approve-always  — approve + create permanent allow rule
 *
 * On retry, matching uses toolName + SHA256(params) — not the toolCallId,
 * which changes per attempt. Entries expire after 5 minutes (DEFAULT_TTL_MS).
 *
 * This is entirely in-memory (not persisted). Gateway restart clears all pending approvals.
 */
import crypto from "node:crypto";

/** Represents a tool call awaiting user approval, denial, or expiry. */
export type PendingApproval = {
  id: string;
  toolName: string;
  paramsHash: string;
  paramsSummary: string;
  reason: string;
  ruleId: string;
  status: "pending" | "approved" | "denied";
  createdAt: number;
  expiresAt: number;
};

function hashParams(toolName: string, params: Record<string, unknown>): string {
  const payload = JSON.stringify({ toolName, params });
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

function shortId(): string {
  return crypto.randomBytes(2).toString("hex");
}

function summarizeParams(params: Record<string, unknown>, max = 120): string {
  const command = params.command;
  if (typeof command === "string") {
    return command.length <= max ? command : `${command.slice(0, max - 3)}...`;
  }
  const raw = JSON.stringify(params);
  return raw.length <= max ? raw : `${raw.slice(0, max - 3)}...`;
}

/**
 * Manages pending tool call approvals. Keyed by short hex ID for easy typing in chat.
 * Matching on LLM retry uses toolName + SHA256(params) since toolCallId changes per attempt.
 */
export class ApprovalManager {
  private pending = new Map<string, PendingApproval>();
  private DEFAULT_TTL_MS = 5 * 60 * 1000;

  /**
   * Create a new pending approval entry for a blocked tool call.
   * @param toolName - The tool being invoked (e.g. "exec")
   * @param params - The full tool call parameters (hashed for matching)
   * @param reason - Human-readable reason from the matching rule
   * @param ruleId - ID of the confirm rule that triggered this
   * @returns The created PendingApproval with a unique short ID
   */
  createPending(
    toolName: string,
    params: Record<string, unknown>,
    reason: string,
    ruleId: string,
  ): PendingApproval {
    this.cleanup();
    const id = shortId();
    const now = Date.now();
    const entry: PendingApproval = {
      id,
      toolName,
      paramsHash: hashParams(toolName, params),
      paramsSummary: summarizeParams(params),
      reason,
      ruleId,
      status: "pending",
      createdAt: now,
      expiresAt: now + this.DEFAULT_TTL_MS,
    };
    this.pending.set(id, entry);
    return entry;
  }

  /**
   * Check if a tool call has a prior approval/denial decision.
   * Matches by toolName + SHA256(params), not by pending ID.
   * @returns "approved", "denied", or null if no prior decision exists
   */
  checkApproval(toolName: string, params: Record<string, unknown>): "approved" | "denied" | null {
    this.cleanup();
    const hash = hashParams(toolName, params);
    for (const entry of this.pending.values()) {
      if (entry.paramsHash === hash && entry.toolName === toolName) {
        if (entry.status === "approved") return "approved";
        if (entry.status === "denied") return "denied";
      }
    }
    return null;
  }

  /**
   * Resolve a pending approval by its short hex ID.
   * @param id - The 4-char hex ID (e.g. "a3f8")
   * @param decision - "approved" or "denied"
   * @returns The updated entry, or null if ID not found / expired
   */
  resolve(id: string, decision: "approved" | "denied"): PendingApproval | null {
    const entry = this.pending.get(id);
    if (!entry) return null;
    entry.status = decision;
    return entry;
  }

  get(id: string): PendingApproval | undefined {
    return this.pending.get(id);
  }

  listPending(): PendingApproval[] {
    this.cleanup();
    return [...this.pending.values()].filter((e) => e.status === "pending");
  }

  listAll(): PendingApproval[] {
    this.cleanup();
    return [...this.pending.values()];
  }

  cleanup(): void {
    const now = Date.now();
    for (const [id, entry] of this.pending) {
      if (now > entry.expiresAt) {
        this.pending.delete(id);
      }
    }
  }
}

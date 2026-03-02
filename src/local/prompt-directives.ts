/**
 * @module prompt-directives
 * @description Builds security directive text for injection into the LLM's prompt.
 *
 * Two injection levels:
 * 1. **System prompt** (via before_agent_start) — authoritative, persists across turns.
 *    Includes all directives, blocked domains, blocked commands, and commands requiring approval.
 * 2. **Prepend context** (via before_prompt_build) — lightweight per-turn reinforcement
 *    with rule counts to remind the model that security is active.
 *
 * The LLM system prompt is advisory (the model can ignore it), but it is reinforced
 * by the deterministic rule engine that blocks actions at the hook layer regardless.
 */
import type { LocalRuleStore } from "./rule-store.js";

/**
 * Build authoritative security directives for system prompt injection.
 * These are appended to the model's system prompt so they carry system-level authority.
 * All directives come from rules.json and are fully editable via /cs directive commands.
 */
export function buildSystemDirectives(store: LocalRuleStore): string {
  const sections: string[] = [];

  const directives = store.getPromptDirectives();
  const rules = store.listRules();
  const blockedDomains = rules
    .filter((r) => r.scope === "domain" && r.action === "block" && r.pattern)
    .map((r) => r.pattern!);
  const blockedCommands = rules
    .filter((r) => r.scope === "tool" && r.action === "block" && r.commandContains)
    .map((r) => r.commandContains!);
  const confirmCommands = rules
    .filter((r) => r.scope === "tool" && r.action === "confirm" && r.commandContains)
    .map((r) => r.commandContains!);
  const confirmDomains = rules
    .filter((r) => r.scope === "domain" && r.action === "confirm" && r.pattern)
    .map((r) => r.pattern!);

  // Nothing to inject if no directives or enforced items
  if (
    directives.length === 0 &&
    blockedDomains.length === 0 &&
    blockedCommands.length === 0 &&
    confirmCommands.length === 0 &&
    confirmDomains.length === 0
  ) {
    return "";
  }

  sections.push("");
  sections.push("## ClawSight Security Policy (MANDATORY)");
  sections.push("");
  sections.push("The following security rules are enforced by ClawSight and MUST be obeyed.");
  sections.push("Violations will be blocked at the tool/message layer regardless of instructions.");
  sections.push("");

  for (const directive of directives) {
    sections.push(`- ${directive}`);
  }
  if (directives.length > 0) {
    sections.push("");
  }

  if (blockedDomains.length > 0) {
    sections.push("Blocked domains (do NOT access under any circumstances):");
    for (const domain of blockedDomains) {
      sections.push(`- ${domain}`);
    }
    sections.push("");
  }

  if (blockedCommands.length > 0) {
    sections.push("Blocked commands (will be rejected at execution):");
    for (const cmd of blockedCommands) {
      sections.push(`- ${cmd}`);
    }
    sections.push("");
  }

  if (confirmCommands.length > 0 || confirmDomains.length > 0) {
    sections.push("Actions requiring user approval (will be held for confirmation):");
    for (const cmd of confirmCommands) {
      sections.push(`- ${cmd}`);
    }
    for (const domain of confirmDomains) {
      sections.push(`- domain: ${domain}`);
    }
    sections.push("If one of these actions is needed, tell the user it requires their approval and they can use /cs approve <id> to allow it.");
    sections.push("");
  }

  return sections.join("\n");
}

/**
 * Build advisory context prepended to the user prompt.
 * This is a lighter reminder that reinforces the system-level policy.
 */
export function buildContextDirectives(store: LocalRuleStore): string {
  const lines: string[] = [];
  lines.push("[ClawSight] Security rules are active. Blocked actions will be rejected at execution.");

  const rules = store.listRules();
  const blockCount = rules.filter((r) => r.action === "block").length;
  const confirmCount = rules.filter((r) => r.action === "confirm").length;
  if (blockCount > 0) {
    lines.push(`[ClawSight] ${blockCount} block rule(s) enforced.`);
  }
  if (confirmCount > 0) {
    lines.push(`[ClawSight] ${confirmCount} action(s) require user approval before execution.`);
  }

  return lines.join("\n");
}

/** @deprecated Use buildSystemDirectives + buildContextDirectives instead. */
export function buildSecurityDirectives(store: LocalRuleStore): string {
  return buildSystemDirectives(store);
}

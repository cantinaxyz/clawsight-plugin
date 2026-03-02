/**
 * @module rule-store
 * @description Persistent storage for local security rules and prompt directives.
 *
 * Manages a JSON file on disk (`rules.json`) containing:
 * - An array of {@link LocalRule} entries (block, allow, warn, confirm, modify)
 * - An array of free-text prompt directives injected into the LLM system prompt
 *
 * All mutations (add/remove rule or directive) persist to disk immediately.
 * On first run (file missing), initializes with defaults from {@link default-rules}.
 * On corrupted file, re-initializes with defaults.
 *
 * Rules are evaluated by the policy engine ({@link policy-engine}) in priority order
 * (lower number = higher priority). IDs are stable and auto-incremented.
 */
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_RULES, DEFAULT_PROMPT_DIRECTIVES } from "./default-rules.js";

/**
 * A single security rule. Rules are matched against tool calls or messages
 * by the policy engine based on scope (domain/ip/tool/message/output).
 */
export type LocalRule = {
  id: number;
  scope: "domain" | "ip" | "tool" | "message" | "output";
  action: "allow" | "warn" | "block" | "modify" | "confirm";
  pattern?: string;
  match?: "exact" | "subdomain";
  toolName?: string;
  commandContains?: string;
  contentContains?: string;
  channelId?: string;
  priority?: number;
  reason?: string;
  /** For output scope with modify action: strategy to apply */
  enforce?: "append_suffix" | "require_contains" | "reject_if_contains";
  /** The value used by the enforcement strategy (suffix text, required text, etc.) */
  enforceValue?: string;
};

export type LocalRulesFile = {
  rules: LocalRule[];
  promptDirectives?: string[];
};

const VALID_SCOPES = new Set(["domain", "ip", "tool", "message", "output"]);
const VALID_ACTIONS = new Set(["allow", "warn", "block", "modify", "confirm"]);

function isValidRule(rule: unknown): rule is LocalRule {
  if (!rule || typeof rule !== "object" || Array.isArray(rule)) return false;
  const r = rule as Record<string, unknown>;
  if (typeof r.id !== "number" || !Number.isFinite(r.id)) return false;
  if (typeof r.scope !== "string" || !VALID_SCOPES.has(r.scope)) return false;
  if (typeof r.action !== "string" || !VALID_ACTIONS.has(r.action)) return false;
  return true;
}

/**
 * CRUD store for local rules and prompt directives.
 * Reads from and writes to a JSON file. Thread-safe for single-process use.
 * Exposed to the /cs command handler and the policy engine.
 */
export class LocalRuleStore {
  private filePath: string;
  private rules: LocalRule[] = [];
  private promptDirectives: string[] = [];
  private nextId = 1;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async loadRules(): Promise<void> {
    if (!fs.existsSync(this.filePath)) {
      await this.initializeDefaults();
      return;
    }
    try {
      const raw = fs.readFileSync(this.filePath, "utf-8");
      const parsed = JSON.parse(raw) as LocalRulesFile;
      const rules: LocalRule[] = [];
      if (Array.isArray(parsed.rules)) {
        for (const entry of parsed.rules) {
          if (isValidRule(entry)) {
            rules.push(entry);
          }
        }
      }
      this.rules = rules;
      this.promptDirectives = Array.isArray(parsed.promptDirectives)
        ? parsed.promptDirectives.filter((d): d is string => typeof d === "string")
        : [];
      this.nextId = this.rules.length > 0
        ? Math.max(...this.rules.map((r) => r.id)) + 1
        : 1;
    } catch {
      // Corrupted file — re-initialize with defaults
      await this.initializeDefaults();
    }
  }

  async resetToDefaults(): Promise<void> {
    await this.initializeDefaults();
  }

  private async initializeDefaults(): Promise<void> {
    this.rules = [...DEFAULT_RULES];
    this.promptDirectives = [...DEFAULT_PROMPT_DIRECTIVES];
    this.nextId = this.rules.length > 0
      ? Math.max(...this.rules.map((r) => r.id)) + 1
      : 1;
    await this.persist();
  }

  private async persist(): Promise<void> {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data: LocalRulesFile = {
      rules: this.rules,
      promptDirectives: this.promptDirectives,
    };
    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
  }

  listRules(): LocalRule[] {
    return [...this.rules];
  }

  getRule(id: number): LocalRule | undefined {
    return this.rules.find((r) => r.id === id);
  }

  async addRule(rule: Omit<LocalRule, "id">): Promise<LocalRule> {
    const newRule: LocalRule = { ...rule, id: this.nextId++ };
    this.rules.push(newRule);
    await this.persist();
    return newRule;
  }

  async removeRule(id: number): Promise<boolean> {
    const idx = this.rules.findIndex((r) => r.id === id);
    if (idx === -1) return false;
    this.rules.splice(idx, 1);
    await this.persist();
    return true;
  }

  getPromptDirectives(): string[] {
    return [...this.promptDirectives];
  }

  async addDirective(text: string): Promise<number> {
    this.promptDirectives.push(text);
    await this.persist();
    return this.promptDirectives.length;
  }

  async removeDirective(index: number): Promise<boolean> {
    if (index < 0 || index >= this.promptDirectives.length) return false;
    this.promptDirectives.splice(index, 1);
    await this.persist();
    return true;
  }

  getSortedRules(): LocalRule[] {
    return [...this.rules].sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100) || a.id - b.id);
  }

  getOutputRules(): LocalRule[] {
    return this.rules
      .filter((r) => r.scope === "output")
      .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100) || a.id - b.id);
  }

  get ruleCount(): number {
    return this.rules.length;
  }
}

/**
 * @module policy-engine
 * @description Local rule evaluation engine for tool calls and outbound messages.
 *
 * Pure functions with no side effects — takes a sorted rules array and a request,
 * returns the first matching decision or null (allow-by-default).
 *
 * Evaluation order per rule:
 * 1. Extract targets (domains, IPs) from request params via recursive traversal
 * 2. Match rules in priority order: domain → IP → tool (or message) scope
 * 3. First match wins — returns allow/warn/block/confirm decision
 *
 * Target extraction scans nested objects up to 5 levels deep, finding URLs,
 * domain patterns, IPv4/IPv6 addresses, and keys matching common naming
 * conventions (host, url, ip, endpoint, etc.).
 */
import crypto from "node:crypto";
import { isIP } from "node:net";
import type { LocalRule } from "./rule-store.js";
import type {
  ToolDecision,
  ToolDecisionRequest,
  MessageDecision,
  MessageDecisionRequest,
} from "../service-types.js";

// --- Target extraction (ported from platform/src/lib/policy.ts) ---

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6_RE = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi;

function normalize(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function normalizeIp(value: string): string {
  return value.trim().replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
}

function addIpCandidate(value: string, store: Set<string>) {
  const ip = normalizeIp(value);
  if (!ip || isIP(ip) === 0) return;
  store.add(ip);
}

function collectTargetsFromString(input: string, domainStore: Set<string>, ipStore: Set<string>) {
  for (const url of input.match(URL_RE) ?? []) {
    try {
      const parsed = new URL(url);
      if (parsed.hostname) {
        const hostname = normalizeDomain(parsed.hostname);
        if (!hostname) continue;
        if (isIP(hostname) === 0) {
          domainStore.add(hostname);
        } else {
          addIpCandidate(hostname, ipStore);
        }
      }
    } catch {
      // Ignore malformed URL.
    }
  }
  for (const domain of input.match(DOMAIN_RE) ?? []) {
    domainStore.add(normalizeDomain(domain));
  }
  for (const ip of input.match(IPV4_RE) ?? []) {
    addIpCandidate(ip, ipStore);
  }
  for (const ip of input.match(IPV6_RE) ?? []) {
    addIpCandidate(ip, ipStore);
  }
}

function collectTargetsFromUnknown(
  value: unknown,
  domainStore: Set<string>,
  ipStore: Set<string>,
  depth = 0,
) {
  if (depth > 5 || value == null) return;
  if (typeof value === "string") {
    collectTargetsFromString(value, domainStore, ipStore);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    for (const entry of value.slice(0, 80)) {
      collectTargetsFromUnknown(entry, domainStore, ipStore, depth + 1);
    }
    return;
  }
  if (typeof value === "object") {
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
      collectTargetsFromUnknown(entry, domainStore, ipStore, depth + 1);
      if (
        /domain|host|url|uri|endpoint|href|link|target|destination/i.test(key) &&
        typeof entry === "string"
      ) {
        collectTargetsFromString(entry, domainStore, ipStore);
      }
      if (/ip|sourceip|destip|destinationip|remoteip/i.test(key) && typeof entry === "string") {
        addIpCandidate(entry, ipStore);
      }
    }
  }
}

function extractTargets(req: Record<string, unknown>): { domains: string[]; ips: string[] } {
  const domains = new Set<string>();
  const ips = new Set<string>();
  collectTargetsFromUnknown(req, domains, ips);
  return {
    domains: [...domains.values()].filter(Boolean),
    ips: [...ips.values()].filter(Boolean),
  };
}

// --- Rule matching ---

function includesNormalized(haystack: string, needle: string | undefined): boolean {
  if (!needle) return true;
  const normalizedNeedle = needle.trim().toLowerCase();
  if (!normalizedNeedle) return true;
  return haystack.includes(normalizedNeedle);
}

function domainMatchesRule(domain: string, rule: LocalRule): boolean {
  const pattern = normalize(rule.pattern);
  if (!pattern) return true; // Empty pattern matches all domains
  const normalizedDomain = normalizeDomain(domain);
  if (rule.match === "exact") {
    return normalizedDomain === pattern;
  }
  // Default: subdomain match
  return normalizedDomain === pattern || normalizedDomain.endsWith(`.${pattern}`);
}

function matchesDomainRule(rule: LocalRule, domains: string[]): boolean {
  if (rule.scope !== "domain") return false;
  if (domains.length === 0) return false;
  return domains.some((domain) => domainMatchesRule(domain, rule));
}

function matchesIpRule(rule: LocalRule, ips: string[]): boolean {
  if (rule.scope !== "ip") return false;
  if (ips.length === 0) return false;
  const needleRaw = normalize(rule.pattern);
  if (!needleRaw) return ips.length > 0;
  const needles = new Set(
    needleRaw
      .split(/[,\s]+/)
      .map((c) => normalizeIp(c))
      .filter((c) => Boolean(c) && isIP(c) !== 0),
  );
  if (needles.size === 0) return false;
  return ips.some((ip) => needles.has(normalizeIp(ip)));
}

function matchesToolRule(rule: LocalRule, req: Record<string, unknown>): boolean {
  if (rule.scope !== "tool") return false;
  const toolName = normalize(req.toolName);
  const params = req.params && typeof req.params === "object" ? (req.params as Record<string, unknown>) : {};
  const command = normalize(params.command);
  const commandFull = command || normalize(JSON.stringify(params));

  if (rule.toolName && normalize(rule.toolName) !== toolName) return false;
  if (rule.commandContains && !includesNormalized(commandFull, rule.commandContains)) return false;
  return true;
}

function matchesMessageRule(rule: LocalRule, req: Record<string, unknown>): boolean {
  if (rule.scope !== "message") return false;
  const channelId = normalize(req.channelId);
  const content = normalize(req.content);

  if (rule.channelId && normalize(rule.channelId) !== channelId) return false;
  if (rule.contentContains && !includesNormalized(content, rule.contentContains)) return false;
  return true;
}

// --- Decision functions ---

function getDecisionId(prefix: string): string {
  return `local-${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

/**
 * Evaluate a tool call request against the sorted rules array.
 * Extracts domains/IPs from params, then checks domain → IP → tool rules in order.
 * @param rules - Pre-sorted rules array (by priority ascending, then ID ascending)
 * @param req - The tool call request containing toolName and params
 * @returns First matching decision, or null if no rule matches (implicit allow)
 */
export function evaluateToolDecision(
  rules: LocalRule[],
  req: ToolDecisionRequest,
): ToolDecision | null {
  const reqRecord = req as unknown as Record<string, unknown>;
  const targets = extractTargets(reqRecord);

  for (const rule of rules) {
    let matched = false;
    if (rule.scope === "domain") {
      matched = matchesDomainRule(rule, targets.domains);
    } else if (rule.scope === "ip") {
      matched = matchesIpRule(rule, targets.ips);
    } else if (rule.scope === "tool") {
      matched = matchesToolRule(rule, reqRecord);
    }
    if (!matched) continue;

    const ruleId = String(rule.id);
    const decisionId = getDecisionId("tool");
    if (rule.action === "block") {
      return { action: "block", reason: rule.reason || `blocked by local rule ${ruleId}`, decisionId, ruleId };
    }
    if (rule.action === "warn") {
      return { action: "warn", reason: rule.reason || `warned by local rule ${ruleId}`, decisionId, ruleId };
    }
    if (rule.action === "confirm") {
      return { action: "confirm", reason: rule.reason || `requires approval per local rule ${ruleId}`, decisionId, ruleId };
    }
    return { action: "allow", decisionId, ruleId };
  }
  return null;
}

/**
 * Evaluate an outbound message against the sorted rules array.
 * Extracts domains/IPs from message content, then checks domain → IP → message rules.
 * @param rules - Pre-sorted rules array (by priority ascending, then ID ascending)
 * @param req - The message request containing channelId, to, and content
 * @returns First matching decision, or null if no rule matches (implicit allow)
 */
export function evaluateMessageDecision(
  rules: LocalRule[],
  req: MessageDecisionRequest,
): MessageDecision | null {
  const reqRecord = req as unknown as Record<string, unknown>;
  const targets = extractTargets(reqRecord);

  for (const rule of rules) {
    let matched = false;
    if (rule.scope === "domain") {
      matched = matchesDomainRule(rule, targets.domains);
    } else if (rule.scope === "ip") {
      matched = matchesIpRule(rule, targets.ips);
    } else if (rule.scope === "message") {
      matched = matchesMessageRule(rule, reqRecord);
    }
    if (!matched) continue;

    const ruleId = String(rule.id);
    const decisionId = getDecisionId("msg");
    if (rule.action === "block") {
      return { action: "block", reason: rule.reason || `blocked by local rule ${ruleId}`, decisionId, ruleId };
    }
    if (rule.action === "warn") {
      return { action: "warn", reason: rule.reason || `warned by local rule ${ruleId}`, decisionId, ruleId };
    }
    return { action: "allow", decisionId, ruleId };
  }
  return null;
}

# SIEM Rules

## Overview

In platform modes (`audit` and `enforce`), policy rules are managed on the ClawSight SIEM platform and enforced remotely. The plugin sends decision requests to the platform, which evaluates rules from its database and returns allow/warn/block/modify decisions.

```
+-------------------+          +------------------------+
|  ClawSight      |   HTTP   |  ClawSight SIEM      |
|  Plugin           +--------->|  Platform              |
|                   |          |                        |
|  before_tool_call |  decide  |  PolicyRule table      |
|  message_sending  +--------->|  Agent scoping         |
|  llm_input        |          |  Intent analysis       |
|  after_tool_call  |          |  Drift detection       |
|                   |<---------+                        |
|  enforce decision |  result  |  allow/block/warn/     |
+-------------------+          |  modify                |
                               +------------------------+
```

## How Platform Rules Differ from Local Rules

| Aspect | Local Rules | SIEM Rules |
|--------|-------------|------------|
| Storage | JSON file on disk | Database (PostgreSQL via Prisma) |
| Management | `/cs` chat commands | Platform UI / API |
| Scope | Same rules for all agents | Per-agent + global rules |
| Decision speed | Microseconds (in-process) | Milliseconds (HTTP roundtrip) |
| Intent analysis | Not available | LLM-powered drift detection |
| Modify action | Not supported | Supported (alter tool params or message content) |
| Audit trail | No | Full decision history in SIEM |

## Platform Rule Schema

Rules in the platform database (`PolicyRule` table):

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Auto-incremented primary key |
| `scope` | enum | `"domain"`, `"ip"`, `"tool"`, `"message"` |
| `action` | string | `"allow"`, `"warn"`, `"block"`, `"modify"` |
| `enabled` | boolean | Whether the rule is active |
| `scopeLevel` | enum | `"global"` or `"agent"` |
| `managedAgentKey` | string? | Agent scope key (null for global rules) |
| `priority` | int | Lower = higher priority |
| `toolName` | string? | Tool name match (tool scope) |
| `commandContains` | string? | Command substring match (tool scope) |
| `contentContains` | string? | Content/domain pattern (domain/ip/message scope) |
| `channelId` | string? | Channel match (message scope) |
| `toContains` | string? | Recipient match (message scope) |
| `reason` | string? | Human-readable explanation |
| `modifyParams` | json? | Parameter overrides (modify action, tool scope) |
| `modifyContent` | string? | Content replacement (modify action, message scope) |

## Agent Scoping

The platform supports per-agent rules that take precedence over global rules:

```
1. Derive managedAgentKey from request:
   - projectId + agentInstanceId + agentId + sessionKey + sessionId

2. Fetch agent-scoped rules (scopeLevel = "agent", matching key)
3. Fetch global rules (scopeLevel = "global")
4. Evaluate agent rules first, then global rules
5. First match wins
```

This allows different agents to have different policies. For example:
- A production agent might block all `exec` calls
- A development agent might allow `exec` but block network access
- Global rules provide a baseline (e.g., block known malicious domains)

## Decision Flow

### Tool Decision

```
Plugin                              Platform
  |                                    |
  |  POST /v1/guardrails/decide        |
  |  { kind: "tool",                   |
  |    toolName: "exec",               |
  |    params: { command: "..." },     |
  |    projectId, agentInstanceId,     |
  |    agentId, sessionKey }           |
  |                                    |
  |----------------------------------->|
  |                                    |
  |    1. Derive managedAgentKey       |
  |    2. Fetch scoped rules           |
  |    3. Extract targets (domains,    |
  |       IPs from params)             |
  |    4. Evaluate rules:              |
  |       - domain rules vs targets    |
  |       - IP rules vs targets        |
  |       - tool rules vs name/cmd     |
  |    5. First match -> decision      |
  |                                    |
  |  { action: "block",               |
  |    reason: "blocked by rule 42",   |
  |    decisionId: "tool-a1b2c3d4",   |
  |    ruleId: "42" }                  |
  |<-----------------------------------|
  |                                    |
  |  -> Block tool, return reason      |
  |     to LLM                         |
```

### Message Decision

Same flow with `kind: "message"`. Evaluates domain/IP/message rules against the outbound message content, recipient, and channel.

### Modify Action

The platform can return `action: "modify"` with altered parameters:

**Tool modify**: Platform returns new `params` object. The plugin merges it with original params and executes the tool with modified parameters.

```json
{
  "action": "modify",
  "params": { "command": "ls -la" },
  "reason": "Removed dangerous flags from command"
}
```

**Message modify**: Platform returns new `content` string. The plugin sends the modified message instead of the original.

```json
{
  "action": "modify",
  "content": "Message content with sensitive data redacted",
  "reason": "PII detected and removed"
}
```

## Intent Policy

The platform provides LLM-powered intent analysis not available in local mode.

### Baseline Establishment

On `llm_input`, the plugin sends the prompt, system prompt, and conversation history. The platform:

1. Derives expected scopes (what the agent should be doing)
2. Establishes expected domains (what resources the agent should access)
3. Creates a baseline for the execution key
4. Reuses existing baselines for the same execution key

### Action Drift Detection

On `before_tool_call`, the plugin sends tool name and params. The platform:

1. Compares the action against the established baseline
2. Computes a drift score (how far the action deviates)
3. Evaluates confidence level
4. Returns signals (e.g., "unexpected_domain", "scope_violation")
5. Can block if drift exceeds threshold

### Output Analysis

On `after_tool_call`, the plugin sends tool output content. The platform:

1. Scans for instruction injection patterns
2. Analyzes content for policy violations
3. Can return sanitized content to replace the original
4. Flags suspicious signals for SIEM alerting

## Telemetry for SIEM Analysis

Every decision (local or platform) generates telemetry:

```json
{
  "category": "policy",
  "action": "tool_decision",
  "severity": "warn",
  "outcome": "block",
  "outcomeReason": "blocked by rule 42",
  "policyRuleId": "42",
  "policyDecisionId": "tool-a1b2c3d4",
  "durationMs": 45,
  "latencyMs": 45,
  "openclaw": {
    "toolName": "exec",
    "sessionKey": "telegram:dm:123"
  },
  "policyDecision": {
    "requestId": "uuid",
    "decisionId": "tool-a1b2c3d4",
    "action": "block",
    "reason": "blocked by rule 42",
    "latencyMs": 45,
    "ruleId": "42"
  }
}
```

Decision errors are also captured:

```json
{
  "category": "policy",
  "action": "decide_error",
  "outcome": "allow",
  "outcomeReason": "policy service unavailable; fail-open applied",
  "errorClass": "policy_service_error",
  "errorCode": "tool_decide_failed"
}
```

## Fail-Safe Behavior

When the platform is unreachable in `enforce` mode:

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Low-risk tool + platform down | **Fail-open** (allow) | Don't break agent functionality for transient outages |
| High-risk tool + platform down | **Fail-closed** (block) | Payment/transfer/send tools are too dangerous to allow without policy check |
| Message + platform down | **Fail-open** (allow) | Messages are lower risk than financial actions |
| Any tool in `audit` mode | **Fail-open** (allow) | Audit mode never blocks, even on error |

High-risk tools are identified by name containing: `payment`, `send`, `transfer`.

## Audit vs Enforce

### Audit Mode

- All telemetry is emitted (full observability)
- Tool/message guardrails are **not enforced** (decisions logged but not acted on)
- Inbound message checks are advisory (logged only)
- Intent baseline/action/output checks are evaluated and logged
- Use this mode to monitor agent behavior before enabling enforcement

### Enforce Mode

- All telemetry is emitted
- Tool/message guardrails are **enforced** (block/modify actions take effect)
- Inbound message checks remain advisory (OpenClaw hook limitation)
- Intent action checks can block drifted tool calls
- Fail-safe behavior applies on platform errors

### Recommended Rollout

1. Start with `audit` mode to establish baseline behavior
2. Review SIEM dashboards for policy violations
3. Create rules to address observed issues
4. Switch to `enforce` mode once rules are validated
5. Monitor fail-open/fail-closed events for platform reliability

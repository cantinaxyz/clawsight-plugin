# Capabilities

## Overview

ClawSight provides five security layers that work together:

```
Layer 1: System Prompt Directives (advisory, high-authority)
  |  Injected into the LLM's system prompt via before_agent_start hook.
  |  Persists across turns and compaction. Highest model authority for
  |  prompt-level instructions, but still advisory — model can ignore.
  |
Layer 2: Per-Turn Reinforcement (advisory, medium-authority)
  |  Prepended to user message via before_prompt_build hook each turn.
  |  Secondary reinforcement of system-level directives.
  |
Layer 3: Tool/Message Guardrails (deterministic, guaranteed)
  |  before_tool_call and message_sending hooks evaluate rules and block
  |  actions before they execute. The model cannot bypass this.
  |  Includes the approval system for "confirm" rules.
  |
Layer 4: Output Enforcement (deterministic, guaranteed)
  |  message_sending hook applies output rules (append/require/reject)
  |  to every outbound message before send. Cannot be bypassed.
  |
Layer 5: Telemetry & Observability (passive)
     All events are logged with distributed tracing for SIEM analysis,
     alerting, and forensic investigation.
```

## Layer 1: System Prompt Directive Injection

**Hook**: `before_agent_start` (session-level, persists across turns)
**Reinforcement**: `before_prompt_build` (per-turn, prepended to user message)
**Mode**: Local only

Security directives are injected at two levels:

### System Prompt (`before_agent_start`)

Set once at session creation via `before_agent_start` hook. OpenClaw calls `applySystemPromptOverrideToSession()` which stores the directives as the session's **actual system prompt**. This persists across turns and compaction. Includes:
- User-defined directives from `rules.json` `promptDirectives` array
- Blocked domain list
- Blocked command list
- Commands requiring approval (confirm rules)

The framing uses authoritative language ("MANDATORY", "MUST be obeyed") and reminds the model that violations will be blocked at the tool layer regardless.

**Important**: Directives are advisory — the model should follow them but they are not guaranteed. For guaranteed behavior, use enforced rules (Layer 3/4).

### Per-Turn Reinforcement (`before_prompt_build`)

The same directive text is also prepended to the user message each turn via `prependContext`. This provides secondary reinforcement in case the system prompt is deprioritized by the model.

### Managing Directives

```
/cs directives                    List custom directives
/cs directive add <text>          Add a directive
/cs directive remove <idx...>     Remove by index
/cs directive preview             See full injected text
```

## Layer 3: Tool and Message Guardrails

**Hooks**: `before_tool_call`, `message_sending`
**Mode**: Local and Platform (enforce)

### Tool Call Blocking

When the agent attempts a tool call, the plugin:

1. Extracts targets from the request (domains, IPs from URLs and params)
2. Evaluates rules in priority order (lower number = higher priority)
3. Returns a decision:
   - `allow` — tool executes normally
   - `warn` — logged, tool executes (audit behavior)
   - `block` — tool is prevented, reason shown to LLM
   - `confirm` — checked against approval manager (see below)
   - `modify` — tool params are altered (platform mode only)

**Rule matching** checks four scopes in order:
1. **Domain rules** — extracted domains from tool params matched against patterns
2. **IP rules** — extracted IPs matched against addresses
3. **Tool rules** — tool name and command content matching
4. **Message rules** — channel and content matching

First match wins.

### Tool Approval System (confirm rules)

When a rule with `action: "confirm"` matches:

1. The approval manager checks if this exact tool call (matched by `toolName + SHA256(params)`) has been previously approved or denied
2. If **approved** → tool executes normally
3. If **denied** → tool is blocked
4. If **no prior decision** → a pending approval is created with a short ID (4 hex chars), and the tool call is blocked with a message telling the LLM to inform the user

The user then approves or denies via chat:
- `/cs approve <id>` — one-time approval; the agent can retry
- `/cs approve-always <id>` — approves and creates a permanent allow rule in `rules.json`
- `/cs deny <id>` — denies; subsequent retries are blocked

Pending approvals expire after 5 minutes.

### Message Blocking

When the agent sends a message to a chat channel:

1. Same target extraction and rule evaluation
2. Decisions:
   - `allow` — message sends
   - `block` — message cancelled (never reaches the channel)
   - `modify` — message content replaced (platform mode only)

### Fail-Safe Behavior (Platform Mode)

When the platform is unreachable:

| Tool Risk | Behavior |
|-----------|----------|
| Low-risk (most tools) | Fail-open (allow) |
| High-risk (payment/send/transfer) | Fail-closed (block) |

All fail-open/fail-closed outcomes are recorded in telemetry.

## Layer 4: Output Enforcement (Deterministic)

**Hook**: `message_sending`
**Mode**: Local only

Output rules run on every outbound message **after** the LLM generates a response but **before** it reaches the messaging channel. These are deterministic — the LLM cannot bypass them.

### Enforcement Strategies

| Strategy | Action | What it does |
|----------|--------|-------------|
| `append_suffix` | modify | Auto-appends text to message if not already present |
| `require_contains` | block | Cancels message if required text is missing |
| `reject_if_contains` | block | Cancels message if forbidden text is present |

### Managing Output Rules

```
/cs enforce append LOLOLOL          Guarantee every message ends with LOLOLOL
/cs enforce require [verified]      Block messages missing [verified]
/cs enforce reject <script>         Block messages containing <script>
/cs remove <id>                     Remove output rule by ID
```

Output rules use the `output` scope in `rules.json`:

```json
{
  "id": 100,
  "scope": "output",
  "action": "modify",
  "enforce": "append_suffix",
  "enforceValue": " LOLOLOL",
  "priority": 1,
  "reason": "Anti-tamper signature"
}
```

## Layer 5: Telemetry and Observability

**Mode**: Platform modes, or local mode with `platformUrl`

### Event Categories

| Category | Events |
|----------|--------|
| `agent` | `bootstrap`, `inventory_snapshot` |
| `session` | `start`, `end`, `before_reset`, `before_model_resolve`, `before_prompt_build`, `before_agent_start`, `agent_end`, `llm_input`, `llm_output`, `before_compaction`, `after_compaction`, `before_message_write` |
| `tool` | `before_tool_call`, `after_tool_call`, `tool_result_persist` |
| `message` | `received`, `sending`, `sent` |
| `policy` | `tool_decision`, `message_decision`, `intent_*_decision`, `decide_error` |
| `gateway` | `start`, `stop` |
| `diagnostic` | Heartbeats, webhooks, cron events |
| `log` | Application logs (when `capture.logs` enabled) |
| `payment` | `send_request`, `send_result`, `send_error` |

### Privacy

Telemetry events are redacted before transmission:
- Message bodies are SHA256-hashed (not sent in cleartext)
- Tool params are truncated (addresses clamped, commands shortened)
- Passwords are replaced with `[redacted]`
- Strings capped at 4,000 chars, arrays at 50 items
- Artifacts (files, URLs, media) are extracted as metadata only

### Batching

Events are queued and flushed in configurable batches:
- Default interval: 1,000ms
- Default batch size: 200 events
- Flush on gateway shutdown

## Intent Policy (Platform Mode)

Three-phase intent analysis performed by the remote platform:

### 1. Baseline (`llm_input`)

Captures the initial prompt and conversation context. The platform derives expected scopes and domains for the execution.

### 2. Action (`before_tool_call`)

Each tool call is checked against the established baseline. The platform tracks drift score and can block actions that deviate from expected behavior.

### 3. Output (`after_tool_call`)

Tool output is analyzed for suspicious content. The platform can flag, sanitize, or block based on content analysis.

## Chat Command System

**Hook**: `api.registerCommand()`
**Mode**: All modes (local mode has full CRUD)

The `/cs` command is processed by OpenClaw's message dispatch pipeline before the LLM sees the message. The handler runs directly and returns a text reply.

Sub-commands parse from `ctx.args` and delegate to the `LocalRuleStore` for mutations. Changes take effect immediately (no restart needed) because the policy engine reads fresh rules on every evaluation.

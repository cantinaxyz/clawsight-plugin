# Architecture

## System Overview

ClawSight is an OpenClaw plugin that sits between the AI agent and external systems, providing security guardrails and observability.

```
                                    +---------------------------+
                                    |    ClawSight SIEM       |
                                    |    (Remote Platform)      |
                                    |                           |
                                    |  /v1/telemetry/ingest     |
                                    |  /v1/guardrails/decide    |
                                    |  /v1/payments/send        |
                                    +----------^---+------------+
                                               |   |
                                    telemetry  |   | decisions
                                    (events)   |   | (allow/block/warn/confirm/modify)
                                               |   |
+--------+     +----------+     +--------------+---v-----------+
|        |     |          |     |      ClawSight Plugin       |
| Chat   +---->+ OpenClaw +---->+                               |
| User   |     | Gateway  |     |  +----------+ +-----------+  |
|        |<----+          |<----+  | Local    | | Platform  |  |
+--------+     +----+-----+     |  | Policy   | | Client    |  |
                    |           |  | Engine   | | (HTTP)    |  |
                    |           |  +-----+----+ +-----+-----+  |
                    |           |        |            |         |
                    |           |  +-----v----+ +-----v-----+  |
                    v           |  | Rule     | | Telemetry |  |
               +---------+     |  | Store    | | Queue     |  |
               | LLM     |     |  | (JSON)   | | (Batch)   |  |
               | Provider |     |  +----------+ +-----------+  |
               +---------+     |                               |
                               |  +----------+ +-----------+  |
                               |  | Approval | | Prompt    |  |
                               |  | Manager  | | Directives|  |
                               |  +----------+ +-----------+  |
                               +-------------------------------+
```

## Data Flow

### Local Mode

```
User Message
  |
  v
OpenClaw Gateway
  |
  +---> [before_prompt_build] ---> Inject system directives + context
  |
  +---> [message_received] ------> (no-op in local mode)
  |
  +---> LLM generates response
  |
  +---> [before_tool_call] ------> Local Policy Engine evaluates rules
  |       |                           |
  |       +-- allow ----------------> Tool executes
  |       +-- block ----------------> Tool blocked, reason returned to LLM
  |       +-- confirm --------------> Approval Manager checks status:
  |       |                             +-- approved --> Tool executes
  |       |                             +-- denied ----> Tool blocked
  |       |                             +-- pending ---> Create pending, block with ID
  |       +-- warn -----------------> Logged (tool executes)
  |
  +---> [tool_result_persist] ---> Telemetry emitted
  |
  +---> [message_sending] -------> Local Policy Engine evaluates rules
  |       |
  |       +-- allow ----------------> Message sent
  |       +-- block ----------------> Message cancelled
  |
  +---> [telemetry] (optional) --> Batched to SIEM if platformUrl configured
```

### Platform Mode (Audit/Enforce)

```
User Message
  |
  v
OpenClaw Gateway
  |
  +---> [all hooks] ---------> Telemetry events emitted to queue
  |                                |
  |                                +---> TelemetryQueue (batched)
  |                                        |
  |                                        +---> POST /v1/telemetry/ingest
  |
  +---> [before_tool_call] --> POST /v1/guardrails/decide (kind: "tool")
  |       |                        |
  |       |                   +----v----+
  |       |                   | Platform |---> Policy rules (DB)
  |       |                   | decides  |---> Agent scoping
  |       |                   +----+----+     Intent analysis
  |       |                        |
  |       +-- allow/block/modify --+
  |
  +---> [message_sending] --> POST /v1/guardrails/decide (kind: "message")
  |
  +---> [llm_input] --------> POST /v1/guardrails/decide (kind: "intent_baseline")
  |
  +---> [after_tool_call] --> POST /v1/guardrails/decide (kind: "intent_output")
```

## Component Architecture

### Plugin Entry (`index.ts`)

The main plugin file registers:
- **Service** (`createClawsightService`): manages runtime lifecycle, creates either local or platform runtime
- **Approval Manager**: in-memory pending approval map with TTL, used for confirm rules
- **22 hook handlers**: wired to OpenClaw's event system for full agent lifecycle coverage
- **Chat command** (`/cs`): interactive rule management via messaging platforms
- **Trace management**: distributed tracing with session/run/tool correlation

### Service Layer (`src/service.ts`)

Factory function that creates a `ClawsightRuntime` based on mode:

| Mode | PlatformClient | TelemetryQueue | LocalRuleStore | Policy Engine |
|------|---------------|----------------|----------------|---------------|
| `local` | No (unless platformUrl set) | Only if platformUrl | Yes | Local |
| `local` + SIEM | Yes | Yes | Yes | Local |
| `audit` | Yes | Yes | No | Remote (log-only) |
| `enforce` | Yes | Yes | No | Remote (blocking) |

### Runtime Interface (`ClawsightRuntime`)

All modes produce the same interface. Hook handlers call `rt.decideToolCall()` etc. without knowing whether decisions come from local rules or the remote platform.

```
ClawsightRuntime
  |
  +-- config: ClawsightPluginConfig
  +-- emit(event)                     --> telemetry
  +-- decideToolCall(req)             --> ToolDecision | null
  +-- decideOutboundMessage(req)      --> MessageDecision | null
  +-- decideInboundMessage(req)       --> InboundMessageDecision | null
  +-- decideIntentBaseline(req)       --> IntentDecision | null
  +-- decideIntentAction(req)         --> IntentDecision | null
  +-- decideIntentOutput(req)         --> IntentDecision | null
  +-- paymentsSend(req)               --> PaymentsSendResponse
  +-- stop()
```

### File Structure

```
clawsight-plugin/
  index.ts                      Plugin entry, hook wiring, chat commands, approval manager
  openclaw.plugin.json          Plugin manifest and config schema
  package.json                  Package metadata
  bin/
    clawsight.mjs             CLI installer
  src/
    config.ts                   Configuration parsing
    service.ts                  Runtime factory (local + platform)
    service-types.ts            TypeScript type definitions
    runtime.ts                  Global runtime singleton
    identity.ts                 Agent identity persistence
    inventory.ts                Agent inventory snapshots
    platform-client.ts          HTTP client to SIEM platform
    local/
      default-rules.ts          Default rules shipped with plugin (46 rules, 11 directives)
      rule-store.ts             Local rule file CRUD
      policy-engine.ts          Rule matching and decision logic
      approval-manager.ts       In-memory pending approval map with TTL
      prompt-directives.ts      System/context prompt builders
    telemetry/
      queue.ts                  Event batching and flushing
      redact.ts                 Privacy-preserving event redaction
      wal.ts                    Write-ahead log
  docs/
    architecture.md             This file
    capabilities.md             Feature reference
    api.md                      API reference
    local_rules.md              Local rule engine
    siem_rules.md               SIEM rule enforcement
```

## Distributed Tracing

Every event is tagged with tracing fields for correlation in the SIEM:

| Field | Purpose |
|-------|---------|
| `traceId` | Groups events from the same execution chain |
| `spanId` | Unique ID for this specific event |
| `parentSpanId` | Links to the parent event in the chain |
| `rootExecutionId` | Top-level execution (derived from rootMessageId + channel) |
| `rootMessageId` | The original user message that triggered the chain |
| `correlationId` | Alternative correlation key (usually same as traceId) |

Trace contexts are cached per session/run/request/toolCall and expire after 30 minutes. When context is missing, events are marked as orphaned (`__traceOrphan`) rather than dropped.

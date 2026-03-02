# Configuration

ClawSight is configured through OpenClaw's config system. All keys live under `plugins.entries.clawsight.config.*`.

## Setting values

```bash
openclaw config set plugins.entries.clawsight.config.<key> <value>
openclaw gateway restart
```

Changes require a gateway restart to take effect.

## Plugin-level keys

| Key | Description |
|-----|-------------|
| `plugins.entries.clawsight.enabled` | Enable or disable the plugin (`true` / `false`) |

## Config keys

### Core

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `"audit"` | Operating mode: `off`, `audit`, `enforce`, or `local` |
| `platformUrl` | string | — | SIEM platform URL. Required for audit/enforce, optional for local |
| `apiToken` | string | — | Platform API token. Supports `${ENV_VAR}` syntax |
| `localRulesPath` | string | `~/.openclaw/plugins/clawsight/rules.json` | Path to local rules file (local mode) |
| `projectId` | string | — | Project identifier for SIEM scoping |

### Agent identity

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `agentName` | string | — | Human-readable agent label shown in SIEM |
| `agentInstanceId` | string | auto-generated | Stable instance ID. If omitted, auto-generated and persisted |
| `identityPath` | string | `~/.openclaw/plugins/clawsight/identity.json` | Path for persisted identity file |

### API paths

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ingestPath` | string | `/v1/telemetry/ingest` | Telemetry ingestion endpoint path |
| `decidePath` | string | `/v1/guardrails/decide` | Policy decision endpoint path |
| `paymentsSendPath` | string | `/v1/payments/send` | Payments endpoint path |

### Telemetry batching

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `flushIntervalMs` | number | `1000` | How often to flush telemetry batches (ms, min 250) |
| `batchMaxEvents` | number | `200` | Max events per batch (min 1) |

### Network

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network.timeoutMs` | number | `30000` | HTTP request timeout for platform calls (ms, min 1000) |

### Capture flags

Control what data is included in telemetry events:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `capture.messages` | boolean | `true` | Capture message lifecycle events |
| `capture.messageBody` | boolean | `false` | Include message body content (hashed by default) |
| `capture.tools` | boolean | `true` | Capture tool call events |
| `capture.toolParams` | boolean | `true` | Include tool parameters in telemetry |
| `capture.toolResult` | boolean | `false` | Include tool result content in telemetry |
| `capture.diagnostics` | boolean | `true` | Capture diagnostic events (heartbeats, webhooks, cron) |
| `capture.logs` | boolean | `false` | Capture application logs |

## Presets

### Local mode (no SIEM)

```bash
openclaw config set plugins.entries.clawsight.enabled true
openclaw config set plugins.entries.clawsight.config.mode local
openclaw gateway restart
```

### Local mode + SIEM telemetry

```bash
openclaw config set plugins.entries.clawsight.enabled true
openclaw config set plugins.entries.clawsight.config.mode local
openclaw config set plugins.entries.clawsight.config.platformUrl http://127.0.0.1:3000
openclaw config set plugins.entries.clawsight.config.apiToken YOUR_TOKEN
openclaw gateway restart
```

### Audit mode (observe only)

```bash
openclaw config set plugins.entries.clawsight.enabled true
openclaw config set plugins.entries.clawsight.config.mode audit
openclaw config set plugins.entries.clawsight.config.platformUrl http://127.0.0.1:3000
openclaw config set plugins.entries.clawsight.config.apiToken YOUR_TOKEN
openclaw config set plugins.entries.clawsight.config.agentName my-agent
openclaw gateway restart
```

### Enforce mode (block on policy violations)

```bash
openclaw config set plugins.entries.clawsight.enabled true
openclaw config set plugins.entries.clawsight.config.mode enforce
openclaw config set plugins.entries.clawsight.config.platformUrl http://127.0.0.1:3000
openclaw config set plugins.entries.clawsight.config.apiToken YOUR_TOKEN
openclaw config set plugins.entries.clawsight.config.agentName my-agent
openclaw gateway restart
```

### Enable verbose telemetry

```bash
openclaw config set plugins.entries.clawsight.config.capture.messageBody true
openclaw config set plugins.entries.clawsight.config.capture.toolResult true
openclaw config set plugins.entries.clawsight.config.capture.logs true
openclaw gateway restart
```

### Disable the plugin

```bash
openclaw config set plugins.entries.clawsight.enabled false
openclaw gateway restart
```

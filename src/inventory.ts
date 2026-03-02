/**
 * @module inventory
 * @description Collects a comprehensive snapshot of the agent's environment for SIEM telemetry.
 *
 * The inventory snapshot captures:
 * - OpenClaw configuration (channels, plugins, skills, gateway settings)
 * - Runtime state via CLI commands (`openclaw skills list`, `openclaw plugins list`, `openclaw gateway call channels.status`)
 * - File system discovery of workspace and managed skills
 * - Agent identity metadata (hostname, OS, node version)
 *
 * Snapshots are emitted on startup and periodically (every 10 minutes).
 * Periodic snapshots are deduplicated by a SHA256 signature — only changes are sent.
 *
 * Sensitive fields (API tokens, passwords) are detected but NOT included in the snapshot;
 * only a boolean `credentialsPresent` flag is set.
 */
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { promisify } from "node:util";
import type { ClawsightPluginConfig } from "./service-types.js";

type InventoryChannel = {
  id: string;
  enabled: boolean;
  configured: boolean;
  accounts: number;
  allowFromCount: number;
  dmPolicy?: string;
  groupPolicy?: string;
  streamMode?: string;
  credentialsPresent: boolean;
};

type InventoryPluginEntry = {
  id: string;
  enabled: boolean;
  hasConfig: boolean;
};

type InventoryPluginInstall = {
  id: string;
  source?: string;
  version?: string;
  installPath?: string;
  sourcePath?: string;
  installedAt?: string;
};

type InventorySkillEntry = {
  id: string;
  enabled: boolean;
  hasApiKey: boolean;
  hasEnv: boolean;
};

type RuntimeCommandStatus = {
  ok: boolean;
  durationMs: number;
  error?: string;
};

type RuntimeSkillItem = {
  name: string;
  status: "ready" | "disabled" | "blocked" | "missing";
  source?: string;
  bundled: boolean;
};

type RuntimePluginItem = {
  id: string;
  name?: string;
  status: "loaded" | "disabled" | "error" | "unknown";
  version?: string;
  origin?: string;
};

type RuntimeChannelAccountItem = {
  channelId: string;
  accountId: string;
  enabled?: boolean;
  configured?: boolean;
  running?: boolean;
  connected?: boolean;
  lastError?: string;
  probeOk?: boolean;
};

type SnapshotRuntimeIdentity = {
  identityPath?: string;
  hostName?: string;
  osPlatform?: string;
  osRelease?: string;
  osArch?: string;
  nodeVersion?: string;
  pluginVersion?: string;
  openclawVersion?: string;
};

type AgentInventorySnapshot = {
  version: number;
  collectedAt: string;
  reason: "startup" | "periodic";
  source: {
    configPath: string;
    configExists: boolean;
    configParseOk: boolean;
    configHash?: string;
    configMtimeMs?: number;
    identityPath?: string;
    hostName?: string;
    osPlatform?: string;
    osRelease?: string;
    osArch?: string;
    nodeVersion?: string;
    pluginVersion?: string;
    openclawVersion?: string;
  };
  access: {
    channels: InventoryChannel[];
    automations: {
      cronConfigured: boolean;
      hooksConfigured: boolean;
      discoveryConfigured: boolean;
    };
    gateway: {
      mode?: string;
      bind?: string;
      authMode?: string;
    };
    tools: {
      policyProfile?: string;
      allowCount: number;
      denyCount: number;
      execHost?: string;
      execSecurity?: string;
      elevatedEnabled?: boolean;
    };
    capabilities: string[];
  };
  plugins: {
    globalEnabled: boolean;
    allow: string[];
    deny: string[];
    loadPaths: string[];
    entries: InventoryPluginEntry[];
    installs: InventoryPluginInstall[];
  };
  skills: {
    workspaceDir: string;
    managedSkillsDir: string;
    allowBundled: string[];
    extraDirs: string[];
    configuredEntries: InventorySkillEntry[];
    discoveredWorkspaceSkills: string[];
    discoveredManagedSkills: string[];
  };
  runtime: {
    source: "openclaw-cli";
    commands: {
      skillsList: RuntimeCommandStatus;
      pluginsList: RuntimeCommandStatus;
      channelsStatus: RuntimeCommandStatus;
    };
    skills: {
      total: number;
      ready: number;
      disabled: number;
      blocked: number;
      missing: number;
      items: RuntimeSkillItem[];
    };
    plugins: {
      total: number;
      loaded: number;
      disabled: number;
      errors: number;
      items: RuntimePluginItem[];
    };
    channels: {
      totalAccounts: number;
      configuredAccounts: number;
      runningAccounts: number;
      connectedAccounts: number;
      items: RuntimeChannelAccountItem[];
    };
  };
};

const execFileAsync = promisify(execFile);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => asString(item))
    .filter((item): item is string => Boolean(item));
}

function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function countObjectKeys(value: unknown): number {
  const rec = asRecord(value);
  if (!rec) return 0;
  return Object.keys(rec).length;
}

function countAllowFrom(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (typeof value === "string" && value.trim()) return 1;
  return 0;
}

function hasCredentialLikeKeys(value: unknown, depth = 0): boolean {
  if (depth > 2 || !value) return false;
  const rec = asRecord(value);
  if (!rec) return false;
  const sensitiveKey = /token|secret|apikey|api_key|password|cookie|authorization|auth/i;
  for (const [key, child] of Object.entries(rec)) {
    if (sensitiveKey.test(key) && typeof child === "string" && child.trim().length > 0) {
      return true;
    }
    if (typeof child === "object" && child && hasCredentialLikeKeys(child, depth + 1)) {
      return true;
    }
  }
  return false;
}

function defaultConfigPath(): string {
  return path.join(os.homedir(), ".openclaw", "openclaw.json");
}

function resolveConfigPath(): string {
  return (
    asString(process.env.OPENCLAW_CONFIG_PATH) ||
    asString(process.env.OPENCLAW_CONFIG) ||
    defaultConfigPath()
  );
}

function stableHash(value: unknown): string {
  const raw = JSON.stringify(value);
  return crypto.createHash("sha256").update(raw, "utf8").digest("hex");
}

function trimText(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (value instanceof Buffer) return value.toString("utf8").trim();
  return "";
}

function parseJsonFromCommandOutput(raw: string): unknown | null {
  const text = raw.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    // Keep fallback parsing conservative: try first/last object or array block.
  }

  const objectStart = text.indexOf("{");
  const objectEnd = text.lastIndexOf("}");
  if (objectStart >= 0 && objectEnd > objectStart) {
    try {
      return JSON.parse(text.slice(objectStart, objectEnd + 1));
    } catch {
      // continue
    }
  }

  const arrayStart = text.indexOf("[");
  const arrayEnd = text.lastIndexOf("]");
  if (arrayStart >= 0 && arrayEnd > arrayStart) {
    try {
      return JSON.parse(text.slice(arrayStart, arrayEnd + 1));
    } catch {
      // continue
    }
  }

  return null;
}

async function runOpenclawJsonCommand(args: string[]): Promise<{
  ok: boolean;
  durationMs: number;
  data?: unknown;
  error?: string;
}> {
  const startedAt = Date.now();
  const fullArgs = [...args, "--json"];
  try {
    const { stdout } = await execFileAsync("openclaw", fullArgs, {
      encoding: "utf8",
      timeout: 8_000,
      maxBuffer: 4 * 1024 * 1024,
      env: process.env,
    });
    const parsed = parseJsonFromCommandOutput(typeof stdout === "string" ? stdout : String(stdout));
    if (parsed == null) {
      return {
        ok: false,
        durationMs: Date.now() - startedAt,
        error: `invalid_json_output for: openclaw ${fullArgs.join(" ")}`,
      };
    }
    return { ok: true, durationMs: Date.now() - startedAt, data: parsed };
  } catch (error: unknown) {
    const rec = asRecord(error);
    const code = asString(rec?.code);
    const signal = asString(rec?.signal);
    const stderr = trimText(rec?.stderr);
    const message = trimText(rec?.message);
    const reason = [code, signal, stderr || message].filter(Boolean).join(" | ");
    return {
      ok: false,
      durationMs: Date.now() - startedAt,
      error: reason || `failed: openclaw ${fullArgs.join(" ")}`,
    };
  }
}

function parseRuntimeSkills(commandData: unknown): AgentInventorySnapshot["runtime"]["skills"] {
  const dataRec = asRecord(commandData);
  const rows = Array.isArray(dataRec?.skills) ? dataRec.skills : [];
  const items: RuntimeSkillItem[] = rows
    .map((row) => {
      const rec = asRecord(row);
      if (!rec) return null;
      const name = asString(rec.name);
      if (!name) return null;
      const eligible = asBoolean(rec.eligible) === true;
      const disabled = asBoolean(rec.disabled) === true;
      const blocked = asBoolean(rec.blockedByAllowlist) === true;
      const status: RuntimeSkillItem["status"] = eligible
        ? "ready"
        : disabled
          ? "disabled"
          : blocked
            ? "blocked"
            : "missing";
      return {
        name,
        status,
        source: asString(rec.source),
        bundled: asBoolean(rec.bundled) === true,
      };
    })
    .filter((item): item is RuntimeSkillItem => Boolean(item))
    .sort((a, b) => a.name.localeCompare(b.name));

  const ready = items.filter((item) => item.status === "ready").length;
  const disabled = items.filter((item) => item.status === "disabled").length;
  const blocked = items.filter((item) => item.status === "blocked").length;
  const missing = items.filter((item) => item.status === "missing").length;
  return {
    total: items.length,
    ready,
    disabled,
    blocked,
    missing,
    items,
  };
}

function parseRuntimePlugins(commandData: unknown): AgentInventorySnapshot["runtime"]["plugins"] {
  const dataRec = asRecord(commandData);
  const rows = Array.isArray(dataRec?.plugins) ? dataRec.plugins : [];
  const items: RuntimePluginItem[] = rows
    .map((row) => {
      const rec = asRecord(row);
      if (!rec) return null;
      const id = asString(rec.id);
      if (!id) return null;
      const statusRaw = asString(rec.status);
      const status: RuntimePluginItem["status"] =
        statusRaw === "loaded" || statusRaw === "disabled" || statusRaw === "error"
          ? statusRaw
          : "unknown";
      return {
        id,
        name: asString(rec.name),
        status,
        version: asString(rec.version),
        origin: asString(rec.origin),
      };
    })
    .filter((item): item is RuntimePluginItem => Boolean(item))
    .sort((a, b) => a.id.localeCompare(b.id));

  const loaded = items.filter((item) => item.status === "loaded").length;
  const disabled = items.filter((item) => item.status === "disabled").length;
  const errors = items.filter((item) => item.status === "error").length;
  return {
    total: items.length,
    loaded,
    disabled,
    errors,
    items,
  };
}

function parseRuntimeChannels(commandData: unknown): AgentInventorySnapshot["runtime"]["channels"] {
  const dataRec = asRecord(commandData);
  const channelAccountsRec = asRecord(dataRec?.channelAccounts);
  const items: RuntimeChannelAccountItem[] = [];
  if (channelAccountsRec) {
    for (const [channelId, accountsRaw] of Object.entries(channelAccountsRec)) {
      if (!Array.isArray(accountsRaw)) continue;
      for (const accountRaw of accountsRaw) {
        const account = asRecord(accountRaw);
        if (!account) continue;
        const accountId = asString(account.accountId) || "default";
        const probe = asRecord(account.probe);
        items.push({
          channelId,
          accountId,
          enabled: asBoolean(account.enabled),
          configured: asBoolean(account.configured),
          running: asBoolean(account.running),
          connected: asBoolean(account.connected),
          lastError: asString(account.lastError),
          probeOk: asBoolean(probe?.ok),
        });
      }
    }
  }
  items.sort((a, b) =>
    a.channelId === b.channelId
      ? a.accountId.localeCompare(b.accountId)
      : a.channelId.localeCompare(b.channelId),
  );

  return {
    totalAccounts: items.length,
    configuredAccounts: items.filter((item) => item.configured === true).length,
    runningAccounts: items.filter((item) => item.running === true).length,
    connectedAccounts: items.filter((item) => item.connected === true).length,
    items,
  };
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function parseOpenclawConfig(filePath: string): Promise<{
  exists: boolean;
  parsed: Record<string, unknown> | null;
  parseOk: boolean;
  hash?: string;
  mtimeMs?: number;
}> {
  try {
    const metadata = await stat(filePath);
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    const rec = asRecord(parsed);
    if (!rec) {
      return { exists: true, parsed: null, parseOk: false, mtimeMs: metadata.mtimeMs };
    }
    return {
      exists: true,
      parsed: rec,
      parseOk: true,
      hash: crypto.createHash("sha256").update(raw, "utf8").digest("hex"),
      mtimeMs: metadata.mtimeMs,
    };
  } catch {
    const exists = await fileExists(filePath);
    return { exists, parsed: null, parseOk: false };
  }
}

async function scanSkillFolders(rootDir: string): Promise<string[]> {
  const MAX_DEPTH = 4;
  const MAX_DIRS = 1500;
  const names = new Set<string>();
  const visitedRealPaths = new Set<string>();
  const queue: Array<{ dir: string; depth: number }> = [{ dir: rootDir, depth: 0 }];
  let visited = 0;

  while (queue.length > 0 && visited < MAX_DIRS) {
    const current = queue.shift();
    if (!current) break;
    let entries: Awaited<ReturnType<typeof readdir>>;
    let currentRealPath: string | null = null;
    try {
      currentRealPath = await realpath(current.dir);
      if (visitedRealPaths.has(currentRealPath)) continue;
      visitedRealPaths.add(currentRealPath);
      entries = await readdir(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }

    const hasSkillDoc = entries.some((entry) => entry.isFile() && entry.name === "SKILL.md");
    if (hasSkillDoc) {
      const rel = path.relative(rootDir, current.dir).replaceAll("\\", "/");
      if (rel && rel !== ".") names.add(rel);
      continue;
    }

    if (current.depth >= MAX_DEPTH) continue;
    for (const entry of entries.slice(0, 400)) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      const nextDir = path.join(current.dir, entry.name);
      if (entry.isSymbolicLink()) {
        try {
          const symlinkTarget = await stat(nextDir);
          if (!symlinkTarget.isDirectory()) continue;
        } catch {
          continue;
        }
      }
      queue.push({ dir: nextDir, depth: current.depth + 1 });
      visited += 1;
      if (visited >= MAX_DIRS) break;
    }
  }

  return [...names].sort((a, b) => a.localeCompare(b));
}

function buildCapabilities(snapshot: AgentInventorySnapshot): string[] {
  const capabilities = new Set<string>();

  for (const channel of snapshot.access.channels) {
    if (channel.enabled || channel.configured) {
      capabilities.add(`channel:${channel.id}`);
    }
  }

  if (snapshot.access.automations.cronConfigured) capabilities.add("automation:cron");
  if (snapshot.access.automations.hooksConfigured) capabilities.add("automation:hooks");
  if (snapshot.access.automations.discoveryConfigured) capabilities.add("automation:discovery");
  if (snapshot.access.tools.execHost || snapshot.access.tools.execSecurity) capabilities.add("tool:exec");
  if (snapshot.access.tools.elevatedEnabled) capabilities.add("tool:elevated");
  if (snapshot.skills.discoveredWorkspaceSkills.length > 0 || snapshot.skills.discoveredManagedSkills.length > 0) {
    capabilities.add("skills:loaded");
  }
  if (snapshot.plugins.entries.some((entry) => entry.enabled)) capabilities.add("plugins:enabled");
  if (snapshot.runtime.skills.ready > 0) capabilities.add("skills:ready-runtime");
  if (snapshot.runtime.plugins.loaded > 0) capabilities.add("plugins:loaded-runtime");
  if (snapshot.runtime.channels.connectedAccounts > 0) capabilities.add("channels:connected-runtime");

  return [...capabilities].sort((a, b) => a.localeCompare(b));
}

/**
 * Collect a full agent environment snapshot for SIEM telemetry.
 * Reads the OpenClaw config file, discovers skills on disk, and queries
 * the running gateway for runtime state. Returns a snapshot + SHA256 signature
 * for deduplication.
 * @param params.cfg - Plugin configuration (for project/agent metadata)
 * @param params.reason - "startup" for initial snapshot, "periodic" for recurring
 * @param params.runtimeIdentity - Agent identity metadata (hostname, versions)
 * @returns Snapshot object and its SHA256 signature for change detection
 */
export async function collectAgentInventorySnapshot(params: {
  cfg: ClawsightPluginConfig;
  reason: "startup" | "periodic";
  runtimeIdentity?: SnapshotRuntimeIdentity;
}): Promise<{
  signature: string;
  snapshot: AgentInventorySnapshot;
}> {
  const configPath = resolveConfigPath();
  const configState = await parseOpenclawConfig(configPath);
  const cfg = configState.parsed;

  const channelsRec = asRecord(cfg?.channels);
  const channelEntries: InventoryChannel[] = [];
  if (channelsRec) {
    for (const [channelId, rawChannel] of Object.entries(channelsRec)) {
      if (channelId === "defaults") continue;
      const channel = asRecord(rawChannel);
      if (!channel) continue;
      const enabled = asBoolean(channel.enabled);
      channelEntries.push({
        id: channelId,
        enabled: enabled !== undefined ? enabled : true,
        configured: true,
        accounts: countObjectKeys(channel.accounts),
        allowFromCount: countAllowFrom(channel.allowFrom),
        dmPolicy: asString(channel.dmPolicy),
        groupPolicy: asString(channel.groupPolicy),
        streamMode: asString(channel.streamMode),
        credentialsPresent: hasCredentialLikeKeys(channel),
      });
    }
  }
  channelEntries.sort((a, b) => a.id.localeCompare(b.id));

  const pluginsRec = asRecord(cfg?.plugins);
  const pluginEntriesRec = asRecord(pluginsRec?.entries);
  const pluginInstallsRec = asRecord(pluginsRec?.installs);
  const pluginEntries: InventoryPluginEntry[] = pluginEntriesRec
    ? Object.entries(pluginEntriesRec).map(([pluginId, raw]) => {
        const rec = asRecord(raw);
        const enabled = asBoolean(rec?.enabled);
        return {
          id: pluginId,
          enabled: enabled !== undefined ? enabled : true,
          hasConfig: Boolean(asRecord(rec?.config)),
        };
      })
    : [];
  pluginEntries.sort((a, b) => a.id.localeCompare(b.id));

  const pluginInstalls: InventoryPluginInstall[] = pluginInstallsRec
    ? Object.entries(pluginInstallsRec).map(([pluginId, raw]) => {
        const rec = asRecord(raw);
        return {
          id: pluginId,
          source: asString(rec?.source),
          version: asString(rec?.version),
          installPath: asString(rec?.installPath),
          sourcePath: asString(rec?.sourcePath),
          installedAt: asString(rec?.installedAt),
        };
      })
    : [];
  pluginInstalls.sort((a, b) => a.id.localeCompare(b.id));

  const skillsRec = asRecord(cfg?.skills);
  const skillEntriesRec = asRecord(skillsRec?.entries);
  const configuredSkillEntries: InventorySkillEntry[] = skillEntriesRec
    ? Object.entries(skillEntriesRec).map(([skillId, raw]) => {
        const rec = asRecord(raw);
        const enabled = asBoolean(rec?.enabled);
        return {
          id: skillId,
          enabled: enabled !== undefined ? enabled : true,
          hasApiKey: Boolean(asString(rec?.apiKey)),
          hasEnv: countObjectKeys(rec?.env) > 0,
        };
      })
    : [];
  configuredSkillEntries.sort((a, b) => a.id.localeCompare(b.id));

  const workspaceDir =
    asString(asRecord(asRecord(cfg?.agents)?.defaults)?.workspace) ||
    path.join(os.homedir(), ".openclaw", "workspace");
  const managedSkillsDir = path.join(os.homedir(), ".openclaw", "skills");
  const workspaceSkillsDir = path.join(workspaceDir, "skills");
  const extraSkillDirs = asStringArray(asRecord(skillsRec?.load)?.extraDirs);
  const codexHomeDir = asString(process.env.CODEX_HOME) || path.join(os.homedir(), ".codex");
  const codexSkillsDir = path.join(codexHomeDir, "skills");
  const managedSkillRoots = [...new Set([managedSkillsDir, codexSkillsDir, ...extraSkillDirs])].map(
    (dir) => path.resolve(dir),
  );
  const pluginSkillRoots = [
    ...new Set(
      [
        ...pluginInstalls.map((plugin) => plugin.installPath).filter((v): v is string => Boolean(v)),
        ...pluginInstalls.map((plugin) => plugin.sourcePath).filter((v): v is string => Boolean(v)),
        ...asStringArray(asRecord(pluginsRec?.load)?.paths),
      ]
        .map((dir) => path.resolve(dir, "skills"))
        .filter((dir) => dir.length > 0),
    ),
  ];

  const [discoveredWorkspaceSkills, ...discoveredManagedSkillLists] = await Promise.all([
    scanSkillFolders(workspaceSkillsDir),
    ...managedSkillRoots.map((root) => scanSkillFolders(root)),
    ...pluginSkillRoots.map((root) => scanSkillFolders(root)),
  ]);
  const discoveredManagedSkills = [...new Set(discoveredManagedSkillLists.flat())].sort((a, b) =>
    a.localeCompare(b),
  );
  const [skillsListCmd, pluginsListCmd, channelsStatusCmd] = await Promise.all([
    runOpenclawJsonCommand(["skills", "list"]),
    runOpenclawJsonCommand(["plugins", "list"]),
    runOpenclawJsonCommand(["gateway", "call", "channels.status"]),
  ]);

  const runtimeSkills = skillsListCmd.ok
    ? parseRuntimeSkills(skillsListCmd.data)
    : {
        total: 0,
        ready: 0,
        disabled: 0,
        blocked: 0,
        missing: 0,
        items: [],
      };
  const runtimePlugins = pluginsListCmd.ok
    ? parseRuntimePlugins(pluginsListCmd.data)
    : {
        total: 0,
        loaded: 0,
        disabled: 0,
        errors: 0,
        items: [],
      };
  const runtimeChannels = channelsStatusCmd.ok
    ? parseRuntimeChannels(channelsStatusCmd.data)
    : {
        totalAccounts: 0,
        configuredAccounts: 0,
        runningAccounts: 0,
        connectedAccounts: 0,
        items: [],
      };

  const snapshot: AgentInventorySnapshot = {
    version: 2,
    collectedAt: new Date().toISOString(),
    reason: params.reason,
    source: {
      configPath,
      configExists: configState.exists,
      configParseOk: configState.parseOk,
      configHash: configState.hash,
      configMtimeMs: configState.mtimeMs,
      identityPath: params.runtimeIdentity?.identityPath,
      hostName: params.runtimeIdentity?.hostName || os.hostname(),
      osPlatform: params.runtimeIdentity?.osPlatform || process.platform,
      osRelease: params.runtimeIdentity?.osRelease || os.release(),
      osArch: params.runtimeIdentity?.osArch || process.arch,
      nodeVersion: params.runtimeIdentity?.nodeVersion || process.version,
      pluginVersion: params.runtimeIdentity?.pluginVersion,
      openclawVersion: params.runtimeIdentity?.openclawVersion,
    },
    access: {
      channels: channelEntries,
      automations: {
        cronConfigured: Boolean(asRecord(cfg?.cron)),
        hooksConfigured: Boolean(asRecord(cfg?.hooks)),
        discoveryConfigured: Boolean(asRecord(cfg?.discovery)),
      },
      gateway: {
        mode: asString(asRecord(cfg?.gateway)?.mode),
        bind: asString(asRecord(cfg?.gateway)?.bind),
        authMode: asString(asRecord(asRecord(cfg?.gateway)?.auth)?.mode),
      },
      tools: {
        policyProfile: asString(asRecord(cfg?.tools)?.profile),
        allowCount: asStringArray(asRecord(cfg?.tools)?.allow).length,
        denyCount: asStringArray(asRecord(cfg?.tools)?.deny).length,
        execHost: asString(asRecord(asRecord(cfg?.tools)?.exec)?.host),
        execSecurity: asString(asRecord(asRecord(cfg?.tools)?.exec)?.security),
        elevatedEnabled: asBoolean(asRecord(asRecord(cfg?.tools)?.elevated)?.enabled),
      },
      capabilities: [],
    },
    plugins: {
      globalEnabled: asBoolean(pluginsRec?.enabled) !== false,
      allow: asStringArray(pluginsRec?.allow),
      deny: asStringArray(pluginsRec?.deny),
      loadPaths: asStringArray(asRecord(pluginsRec?.load)?.paths),
      entries: pluginEntries,
      installs: pluginInstalls,
    },
    skills: {
      workspaceDir,
      managedSkillsDir,
      allowBundled: asStringArray(skillsRec?.allowBundled),
      extraDirs: extraSkillDirs,
      configuredEntries: configuredSkillEntries,
      discoveredWorkspaceSkills,
      discoveredManagedSkills,
    },
    runtime: {
      source: "openclaw-cli",
      commands: {
        skillsList: {
          ok: skillsListCmd.ok,
          durationMs: skillsListCmd.durationMs,
          ...(skillsListCmd.ok ? {} : { error: skillsListCmd.error }),
        },
        pluginsList: {
          ok: pluginsListCmd.ok,
          durationMs: pluginsListCmd.durationMs,
          ...(pluginsListCmd.ok ? {} : { error: pluginsListCmd.error }),
        },
        channelsStatus: {
          ok: channelsStatusCmd.ok,
          durationMs: channelsStatusCmd.durationMs,
          ...(channelsStatusCmd.ok ? {} : { error: channelsStatusCmd.error }),
        },
      },
      skills: runtimeSkills,
      plugins: runtimePlugins,
      channels: runtimeChannels,
    },
  };

  snapshot.access.capabilities = buildCapabilities(snapshot);

  const signature = stableHash({
    source: snapshot.source,
    access: snapshot.access,
    plugins: snapshot.plugins,
    skills: snapshot.skills,
    runtime: snapshot.runtime,
  });

  return { signature, snapshot };
}

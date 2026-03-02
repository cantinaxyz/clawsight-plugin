/**
 * @module identity
 * @description Manages the persistent agent identity for a ClawSight plugin
 * instance. On first run a unique agent instance ID is generated and written
 * to disk; subsequent runs re-use the persisted identity so that the platform
 * can correlate telemetry across restarts. The module also gathers host-level
 * metadata (hostname, OS, Node version, etc.) into a single
 * {@link RuntimeAgentIdentity} object.
 */

import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import type { ClawsightPluginConfig } from "./service-types.js";

/**
 * Shape of the identity JSON file stored on disk.
 */
type PersistedIdentity = {
  agentInstanceId?: string;
  agentName?: string;
  createdAt?: string;
  updatedAt?: string;
};

/**
 * Full runtime identity of the agent, combining persisted fields with
 * live host metadata and version information.
 */
export type RuntimeAgentIdentity = {
  agentInstanceId: string;
  agentName?: string;
  identityPath: string;
  hostName: string;
  osPlatform: string;
  osRelease: string;
  osArch: string;
  nodeVersion: string;
  pluginVersion?: string;
  openclawVersion?: string;
};

/**
 * @description Coerces an unknown value to a trimmed, non-empty string.
 * Returns `undefined` when the value is not a string or is blank.
 * @param value - The value to inspect.
 * @returns The trimmed string or `undefined`.
 */
function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * @description Returns the default filesystem path where the identity file is
 * persisted (`~/.openclaw/plugins/clawsight/identity.json`).
 * @returns Absolute path to the default identity file.
 */
function defaultIdentityPath(): string {
  return path.join(os.homedir(), ".openclaw", "plugins", "clawsight", "identity.json");
}

/**
 * @description Resolves the plugin version string from environment variables.
 * Checks `CLAWSIGHT_PLUGIN_VERSION` first, then `npm_package_version`.
 * @returns The version string or `undefined` if unavailable.
 */
function resolvePluginVersion(): string | undefined {
  return (
    asString(process.env.CLAWSIGHT_PLUGIN_VERSION) ||
    asString(process.env.npm_package_version) ||
    undefined
  );
}

/**
 * @description Resolves the OpenClaw host version from environment variables.
 * Checks `OPENCLAW_VERSION` first, then `OPENCLAW_BUILD_VERSION`.
 * @returns The version string or `undefined` if unavailable.
 */
function resolveOpenclawVersion(): string | undefined {
  return (
    asString(process.env.OPENCLAW_VERSION) ||
    asString(process.env.OPENCLAW_BUILD_VERSION) ||
    undefined
  );
}

/**
 * @description Reads and parses the persisted identity JSON from disk.
 * Returns an empty object if the file does not exist or cannot be parsed.
 * @param filePath - Absolute path to the identity JSON file.
 * @returns The parsed identity, or an empty object on failure.
 */
async function readPersistedIdentity(filePath: string): Promise<PersistedIdentity> {
  try {
    const raw = await readFile(filePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedIdentity;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * @description Merges the supplied identity data with any existing persisted
 * data and writes the result back to disk. Creates parent directories as
 * needed. Preserves the original `createdAt` timestamp and updates
 * `updatedAt` to the current time.
 * @param filePath - Absolute path to the identity JSON file.
 * @param data - Identity fields to persist (may be partial).
 */
async function writePersistedIdentity(filePath: string, data: PersistedIdentity): Promise<void> {
  const nowIso = new Date().toISOString();
  const current = await readPersistedIdentity(filePath);
  const payload: PersistedIdentity = {
    agentInstanceId: data.agentInstanceId || current.agentInstanceId || crypto.randomUUID(),
    agentName: data.agentName || current.agentName || undefined,
    createdAt: current.createdAt || nowIso,
    updatedAt: nowIso,
  };
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

/**
 * @description Resolves the full runtime agent identity by merging
 * configuration overrides, persisted identity on disk, and live host
 * metadata. If no agent instance ID exists yet, a new UUID is generated and
 * persisted for future runs.
 * @param cfg - The resolved plugin configuration.
 * @returns A complete {@link RuntimeAgentIdentity} for the current session.
 */
export async function resolveRuntimeAgentIdentity(
  cfg: ClawsightPluginConfig,
): Promise<RuntimeAgentIdentity> {
  const identityPath = asString(cfg.identityPath) || defaultIdentityPath();
  const persisted = await readPersistedIdentity(identityPath);

  const configuredInstance = asString(cfg.agentInstanceId);
  const persistedInstance = asString(persisted.agentInstanceId);
  const agentInstanceId = configuredInstance || persistedInstance || crypto.randomUUID();

  const configuredName = asString(cfg.agentName);
  const persistedName = asString(persisted.agentName);
  const agentName = configuredName || persistedName || undefined;

  await writePersistedIdentity(identityPath, {
    agentInstanceId,
    agentName,
  });

  return {
    agentInstanceId,
    agentName,
    identityPath,
    hostName: os.hostname(),
    osPlatform: process.platform,
    osRelease: os.release(),
    osArch: process.arch,
    nodeVersion: process.version,
    pluginVersion: resolvePluginVersion(),
    openclawVersion: resolveOpenclawVersion(),
  };
}

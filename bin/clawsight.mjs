#!/usr/bin/env node
/**
 * @module clawsight-cli
 * @description CLI installer for the ClawSight OpenClaw plugin.
 *
 * Usage:
 *   npx clawsight install --mode local [--link]
 *   npx clawsight install --platform-url <url> --token <token> --mode enforce [--link]
 *
 * This script orchestrates the OpenClaw CLI to:
 * 1. Install the plugin package (`openclaw plugins install`)
 * 2. Enable the plugin (`openclaw plugins enable clawsight`)
 * 3. Set configuration values (mode, platformUrl, apiToken, localRulesPath, etc.)
 *
 * For local mode, it creates the rules directory but does NOT write default rules —
 * that is handled by LocalRuleStore.loadRules() on first gateway start, which creates
 * rules.json with the full 46 default rules and 11 prompt directives.
 *
 * No dependencies — uses only Node.js built-in modules.
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function usage(exitCode = 1) {
  // Keep this lightweight (no deps).
  process.stderr.write(`\
clawsight (OpenClaw plugin installer)

Usage:
  clawsight install --platform-url <url> [--token <token> | --token-env <ENV>] [--mode audit|enforce] [--agent-name <name>] [--agent-instance-id <id>] [--link] [--openclaw <bin>]
  clawsight install --mode local [--platform-url <url>] [--token <token>] [--link] [--openclaw <bin>]

Examples:
  clawsight install --platform-url http://127.0.0.1:8081 --token devtoken --mode enforce --link
  clawsight install --platform-url https://api.example --token-env CLAWSIGHT_API_TOKEN --agent-name prod-agent-a
  clawsight install --mode local --link
  clawsight install --mode local --platform-url http://127.0.0.1:8081 --token devtoken --link
`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a) continue;
    if (!a.startsWith("--")) {
      args._.push(a);
      continue;
    }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      args[key] = next;
      i += 1;
    } else {
      args[key] = true;
    }
  }
  return args;
}

function run(openclawBin, subcommandArgs) {
  const res = spawnSync(openclawBin, subcommandArgs, { stdio: "inherit" });
  if (res.status !== 0) {
    process.exit(res.status ?? 1);
  }
}

function patchConfigClearPlatform() {
  const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
  if (!fs.existsSync(configPath)) return;
  try {
    const raw = fs.readFileSync(configPath, "utf-8");
    const config = JSON.parse(raw);
    const csConfig = config?.plugins?.entries?.clawsight?.config;
    if (!csConfig) return;
    let changed = false;
    if (csConfig.apiToken && typeof csConfig.apiToken === "string" && csConfig.apiToken.includes("${")) {
      delete csConfig.apiToken;
      changed = true;
    }
    if (csConfig.platformUrl) {
      delete csConfig.platformUrl;
      changed = true;
    }
    if (changed) {
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
      process.stderr.write("Cleared stale platformUrl/apiToken from config.\n");
    }
  } catch (err) {
    process.stderr.write(`Warning: could not patch config file: ${err}\n`);
  }
}

const argv = process.argv.slice(2);
if (argv.length === 0) {
  usage(1);
}

const args = parseArgs(argv);
const cmd = args._[0];
if (!cmd) {
  usage(1);
}

const openclawBin = typeof args.openclaw === "string" ? args.openclaw : "openclaw";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pluginRoot = path.resolve(__dirname, "..");

if (cmd === "install") {
  const mode = typeof args.mode === "string" ? args.mode : "audit";
  const link = args.link === true;
  const isLocal = mode === "local";

  const platformUrl = typeof args["platform-url"] === "string" ? args["platform-url"] : "";
  if (!isLocal && !platformUrl) {
    process.stderr.write("Missing --platform-url (not required for --mode local)\n");
    usage(1);
  }
  const token = typeof args.token === "string" ? args.token : "";
  const tokenEnv = typeof args["token-env"] === "string" ? args["token-env"] : "";
  const agentName = typeof args["agent-name"] === "string" ? args["agent-name"] : "";
  const agentInstanceId = typeof args["agent-instance-id"] === "string" ? args["agent-instance-id"] : "";

  // 1) Install plugin
  run(openclawBin, ["plugins", "install", ...(link ? ["-l"] : []), pluginRoot]);
  // 2) Enable plugin
  run(openclawBin, ["plugins", "enable", "clawsight"]);
  // 3) Configure plugin
  run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.mode", mode]);

  if (isLocal) {
    // Local mode: set rules path. Default rules (46 rules, 11 directives) are
    // created automatically by LocalRuleStore on first gateway start when the
    // file doesn't exist. This avoids duplicating the default rules here.
    const rulesDir = path.join(os.homedir(), ".openclaw", "plugins", "clawsight");
    const rulesPath = path.join(rulesDir, "rules.json");
    if (!fs.existsSync(rulesDir)) {
      fs.mkdirSync(rulesDir, { recursive: true });
    }
    run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.localRulesPath", rulesPath]);

    // Optional: configure SIEM telemetry alongside local rules
    if (platformUrl) {
      run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.platformUrl", platformUrl]);
      if (token) {
        run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.apiToken", token]);
      } else if (tokenEnv) {
        run(openclawBin, [
          "config",
          "set",
          "plugins.entries.clawsight.config.apiToken",
          `\${${tokenEnv}}`,
        ]);
        process.stderr.write(`Note: set ${tokenEnv} in the environment of the OpenClaw gateway process.\n`);
      } else {
        run(openclawBin, [
          "config",
          "set",
          "plugins.entries.clawsight.config.apiToken",
          "${CLAWSIGHT_API_TOKEN}",
        ]);
        process.stderr.write("Note: set CLAWSIGHT_API_TOKEN in the environment of the OpenClaw gateway process.\n");
      }
      process.stderr.write(
        `ClawSight installed in local mode with telemetry → ${platformUrl}. Use /cs commands to manage rules.\n`,
      );
    } else {
      // No SIEM — clear any stale platformUrl/apiToken from previous installs.
      // openclaw config set may fail if the config has a broken ${...} ref,
      // so patch the JSON file directly as a fallback.
      patchConfigClearPlatform();
      process.stderr.write(
        "ClawSight installed in local mode (no telemetry). Use /cs commands to manage rules.\n",
      );
    }
    process.exit(0);
  }

  // Platform modes (audit/enforce)
  run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.platformUrl", platformUrl]);
  if (agentName) {
    run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.agentName", agentName]);
  }
  if (agentInstanceId) {
    run(openclawBin, [
      "config",
      "set",
      "plugins.entries.clawsight.config.agentInstanceId",
      agentInstanceId,
    ]);
  }

  if (token) {
    run(openclawBin, ["config", "set", "plugins.entries.clawsight.config.apiToken", token]);
  } else if (tokenEnv) {
    run(openclawBin, [
      "config",
      "set",
      "plugins.entries.clawsight.config.apiToken",
      `\${${tokenEnv}}`,
    ]);
    process.stderr.write(
      `Note: set ${tokenEnv} in the environment of the OpenClaw gateway process.\n`,
    );
  } else {
    // Default convention.
    run(openclawBin, [
      "config",
      "set",
      "plugins.entries.clawsight.config.apiToken",
      "${CLAWSIGHT_API_TOKEN}",
    ]);
    process.stderr.write(
      "Note: set CLAWSIGHT_API_TOKEN in the environment of the OpenClaw gateway process.\n",
    );
  }

  process.stderr.write(
    "Install complete. Restart the OpenClaw gateway for plugin config changes to take effect.\n",
  );
  process.exit(0);
}

usage(1);

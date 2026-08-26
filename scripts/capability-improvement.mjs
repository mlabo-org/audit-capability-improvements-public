#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const LEGACY_EVENT_SCHEMA = "capability-improvement-evidence/v1";
const EVENT_SCHEMA = "capability-improvement-evidence/v2";
const LEGACY_PLAN_SCHEMA = "capability-improvement-repair-plan/v1";
const PLAN_SCHEMA = "capability-improvement-repair-plan/v2";
const RESOLUTION_SCHEMA = "capability-improvement-resolution/v1";
const APP_STATE_RESOLUTION_SCHEMA =
  "capability-improvement-app-state-resolution/v1";
const MONITOR_DISPOSITION_SCHEMA =
  "capability-improvement-monitor-disposition/v1";
const RETIREMENT_DISPOSITION_SCHEMA =
  "capability-improvement-retirement-disposition/v1";
const IMPROVEMENTS_DIR = ".capability-improvements";
const EXCLUDE_ENTRY = ".capability-improvements/";
const SESSION_FLAG = "CAPABILITY_FRICTION_DETECTED";
const INDEX_DIR = "capability-friction-index";
const INDEX_PENDING_DIR = "pending";
const INDEX_PROCESSING_DIR = "processing";
const INDEX_LOCKS_DIR = "locks";
const THREAD_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEFAULT_CLAIM_LEASE_SECONDS = 2 * 60 * 60;
const MAX_CLAIM_LEASE_SECONDS = 24 * 60 * 60;
const MAX_EVENT_BYTES = 64 * 1024;
const MAX_PLAN_BYTES = 128 * 1024;
const MAX_RESOLUTION_BYTES = 128 * 1024;
const MAX_APP_STATE_RESOLUTION_BYTES = 128 * 1024;
const MAX_MONITOR_DISPOSITION_BYTES = 64 * 1024;
const MAX_RETIREMENT_DISPOSITION_BYTES = 64 * 1024;
const MAX_IMPROVEMENT_DOCUMENT_BYTES = Math.max(
  MAX_EVENT_BYTES,
  MAX_PLAN_BYTES,
  MAX_RESOLUTION_BYTES,
  MAX_APP_STATE_RESOLUTION_BYTES,
  MAX_MONITOR_DISPOSITION_BYTES,
  MAX_RETIREMENT_DISPOSITION_BYTES,
);
const MAX_ROLLOUT_LINE_BYTES = 32 * 1024 * 1024;
const ROLLOUT_READ_CHUNK_BYTES = 1024 * 1024;
const MAX_SESSION_TREE_ENTRIES = 100_000;
const EVENT_ID_PATTERN = /^event-\d{17}-[0-9a-f]{8}$/;
const AUTOMATION_RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256_PATTERN = /^[0-9a-fA-F]{64}$/;
const APP_STATE_SURFACE = "codex_automation";
const APP_STATE_SOURCE_CONTROL_REASON =
  "app_managed_ignored_untracked_state";
const FLAG_BLOCK_PATTERN = new RegExp(
  [
    `${SESSION_FLAG}[ \\t]*\\r?\\n`,
    "session_id:[ \\t]*([^\\r\\n]+?)[ \\t]*\\r?\\n",
    "event_id:[ \\t]*([^\\r\\n]+?)[ \\t]*\\r?\\n",
    "capability:[ \\t]*([^\\r\\n]+?)[ \\t]*\\r?\\n",
    "source_repo:[ \\t]*([^\\r\\n]+?)[ \\t]*\\r?\\n",
    "artifact:[ \\t]*([^\\r\\n]+?)[ \\t]*\\r?\\n",
    "state:[ \\t]*([^\\r\\n]+?)[ \\t]*(?=\\r?\\n|$)",
  ].join(""),
  "g",
);

const ENUMS = Object.freeze({
  capability_kind: [
    "skill",
    "plugin",
    "mcp",
    "app",
    "hook",
    "workflow",
    "cli",
    "other",
  ],
  category: [
    "contract_mismatch",
    "input_format_mismatch",
    "route_mismatch",
    "validator_gap",
    "source_cache_runtime_drift",
    "constitution_conflict",
    "compensatory_reasoning",
    "repeated_manual_repair",
    "other",
  ],
  evidence_strength: ["direct", "inferred"],
  repeatability: ["one_off", "unknown", "reproduced", "repeated"],
  severity: ["low", "medium", "high", "critical"],
  source_boundary: [
    "input",
    "source",
    "generated",
    "cache",
    "runtime",
    "route",
    "validator",
    "constitution",
    "unknown",
  ],
});

const STRUCTURAL_CATEGORIES = new Set([
  "contract_mismatch",
  "route_mismatch",
  "validator_gap",
  "source_cache_runtime_drift",
  "constitution_conflict",
  "repeated_manual_repair",
]);

const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

const HELP = `Capability Improvement Auditor

Usage:
  capability-improvement.mjs --help
  capability-improvement.mjs schema
  capability-improvement.mjs doctor --target-cwd <absolute-git-path>
  capability-improvement.mjs validate --target-cwd <absolute-git-path>
  capability-improvement.mjs record [fields] [--execute]
  capability-improvement.mjs triage --target-cwd <absolute-git-path> [--execute]
  capability-improvement.mjs monitor-dispose --target-cwd <absolute-git-path> --proposal-ref <artifact-ref> [--execute]
  capability-improvement.mjs handoff-check --target-cwd <absolute-git-path> --proposal-ref <artifact-ref> --execution-route <direct|coding-agent-orchestrator> --execution-authority <typed-reference>
  capability-improvement.mjs resolve --target-cwd <absolute-git-path> --proposal-ref <artifact-ref> --execution-route <direct|coding-agent-orchestrator> --execution-id <id> --execution-authority <typed-reference> --execution-evidence <typed-reference> --root-cause <text> --commit <sha> [--commit-mode head|ancestor|preexisting] --changed-file <path> --verification <typed-reference> --refresh-status <passed|not_applicable> [--refresh-evidence <typed-reference>] [--execute]
  capability-improvement.mjs app-state-resolve --target-cwd <absolute-git-path> --proposal-ref <artifact-ref> --execution-route <direct|coding-agent-orchestrator> --execution-id <id> --execution-authority <typed-reference> --execution-evidence <typed-reference> --root-cause <text> --state-surface codex_automation --resource-id <id> --state-path automations/<id>/automation.toml --observed-at <iso-time> --before-sha256 <sha256> --after-sha256 <sha256> --changed-field <field> --preserved-field <field> --operation-evidence <typed-success-reference> --readback-evidence <typed-reference> --invariant-evidence <typed-reference> --verification <typed-reference> [--execute]
  capability-improvement.mjs retire-dispose --target-cwd <absolute-git-path> --capability-id <id> --event-artifact <absolute-path> [--event-artifact <absolute-path> ...] --reason <text> [--replacement <id>] [--execute]
  capability-improvement.mjs thread-flags --thread-id <uuid> [--codex-home <absolute-path>]
  capability-improvement.mjs index-audit [--thread-id <uuid>] [--codex-home <absolute-path>]
  capability-improvement.mjs index-list [--codex-home <absolute-path>]
  capability-improvement.mjs index-status --thread-id <uuid> [--codex-home <absolute-path>]
  capability-improvement.mjs index-add --thread-id <uuid> [--codex-home <absolute-path>] [--execute]
  capability-improvement.mjs index-claim --thread-id <uuid> [--lease-seconds <n>] [--codex-home <absolute-path>] [--execute]
  capability-improvement.mjs index-release --thread-id <uuid> [--codex-home <absolute-path>] [--execute]
  capability-improvement.mjs index-close --thread-id <uuid> --event-artifact <absolute-path> [--event-artifact <absolute-path> ...] [--codex-home <absolute-path>] [--execute]

record required fields:
  --target-cwd <absolute-git-path>
  --thread-id <uuid>
  --capability-id <id>
  --capability-kind <${ENUMS.capability_kind.join("|")}>
  --category <${ENUMS.category.join("|")}>
  --summary <text>
  --expected <text>
  --actual <text>
  --compensation <text>
  --outcome <text>
  --evidence-strength <${ENUMS.evidence_strength.join("|")}>
  --repeatability <${ENUMS.repeatability.join("|")}>
  --severity <${ENUMS.severity.join("|")}>
  --source-boundary <${ENUMS.source_boundary.join("|")}>
  --evidence <typed-reference>             repeatable, at least one

record optional fields:
  --source-ref <typed-reference>            default: path:.
  --root-cause <text>
  --repeat-key <stable-key>
  --candidate-file <repo-relative-path>     repeatable
  --verification <typed-reference>          repeatable
  --codex-home <absolute-path>              default: $CODEX_HOME or ~/.codex

record --execute writes source-local evidence and idempotently registers only
the thread ID in the central pending index.
app-state-resolve records evidence for an already-authorized and already-applied
official Codex automation repair. It validates but never mutates automation state.
retire-dispose is allowed only after a current explicit user retirement request. It
records exact source-local events without repairing or changing the retired capability.
index-audit takes one finite read-only marker snapshot and reports close_ready,
repair_required, monitor_required, or blocked without claiming or closing markers.
Persistent writes are opt-in with --execute.
This CLI never launches Codex, Coding Agent Orchestrator, CLI Agent Runner, or any other worker.
`;

function fail(message, details = undefined, exitCode = 1) {
  const error = new Error(message);
  error.details = details;
  error.exitCode = exitCode;
  throw error;
}

function parseArgs(argv) {
  const parsed = { _: [], execute: false };
  const repeatable = new Set([
    "evidence",
    "candidate-file",
    "verification",
    "changed-file",
    "changed-field",
    "preserved-field",
    "readback-evidence",
    "invariant-evidence",
    "execution-evidence",
    "event-artifact",
  ]);

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      parsed._.push(token);
      continue;
    }

    const name = token.slice(2);
    if (name === "help") {
      parsed.help = true;
      continue;
    }
    if (name === "execute") {
      parsed.execute = true;
      continue;
    }

    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`Missing value for --${name}`, undefined, 2);
    }
    index += 1;
    if (repeatable.has(name)) {
      parsed[name] ??= [];
      parsed[name].push(value);
    } else {
      if (Object.hasOwn(parsed, name)) {
        fail(`Duplicate option --${name}`, undefined, 2);
      }
      parsed[name] = value;
    }
  }

  return parsed;
}

function runGit(rootOrCwd, args, { allowFailure = false } = {}) {
  const result = spawnSync("git", args, {
    cwd: rootOrCwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    fail(`Unable to run git: ${result.error.message}`);
  }
  if (result.status !== 0 && !allowFailure) {
    fail(`git ${args.join(" ")} failed`, {
      exit_code: result.status,
      stderr: result.stderr.trim(),
    });
  }
  return result;
}

function resolveGitRoot(targetCwd) {
  requireText(targetCwd, "target-cwd", 4096);
  if (!path.isAbsolute(targetCwd)) {
    fail("--target-cwd must be an absolute path");
  }

  let stat;
  try {
    stat = fs.statSync(targetCwd);
  } catch {
    fail(`--target-cwd does not exist: ${targetCwd}`);
  }
  if (!stat.isDirectory()) {
    fail(`--target-cwd is not a directory: ${targetCwd}`);
  }

  const result = runGit(targetCwd, ["rev-parse", "--show-toplevel"], {
    allowFailure: true,
  });
  if (result.status !== 0) {
    fail(`Unable to resolve an authoritative Git root from: ${targetCwd}`, {
      stderr: result.stderr.trim(),
    });
  }
  return fs.realpathSync(result.stdout.trim());
}

function trackedCodingAgentsFiles(root) {
  const result = runGit(root, ["ls-files", "--", ".capability-improvements"]);
  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function assertWorkflowStateUntracked(root) {
  const tracked = trackedCodingAgentsFiles(root);
  if (tracked.length > 0) {
    fail("Refusing to use tracked .capability-improvements workflow state", {
      tracked_files: tracked,
    });
  }
}

function gitExcludePath(root) {
  const result = runGit(root, ["rev-parse", "--git-path", "info/exclude"]);
  const reported = result.stdout.trim();
  return path.isAbsolute(reported) ? reported : path.resolve(root, reported);
}

function excludeHasEntry(root) {
  const excludePath = gitExcludePath(root);
  if (!fs.existsSync(excludePath)) {
    return false;
  }
  return fs
    .readFileSync(excludePath, "utf8")
    .split(/\r?\n/)
    .some((line) => line.trim() === EXCLUDE_ENTRY);
}

function ensureExcludeEntry(root) {
  const excludePath = gitExcludePath(root);
  fs.mkdirSync(path.dirname(excludePath), { recursive: true });
  const existing = fs.existsSync(excludePath)
    ? fs.readFileSync(excludePath, "utf8")
    : "";
  if (
    existing
      .split(/\r?\n/)
      .some((line) => line.trim() === EXCLUDE_ENTRY)
  ) {
    return excludePath;
  }
  const prefix = existing.length === 0 || existing.endsWith("\n") ? "" : "\n";
  fs.appendFileSync(excludePath, `${prefix}${EXCLUDE_ENTRY}\n`, "utf8");
  return excludePath;
}

function requireThreadId(value, label = "thread-id") {
  requireText(value, label, 64);
  if (!THREAD_ID_PATTERN.test(value)) {
    fail(`${label} must be a lowercase UUID`);
  }
  return value;
}

function resolveCodexHome(value) {
  const candidate =
    value ??
    process.env.CODEX_HOME ??
    path.join(os.homedir(), ".codex");
  requireText(candidate, "codex-home", 4096);
  if (!path.isAbsolute(candidate)) {
    fail("--codex-home must be an absolute path");
  }
  return path.resolve(candidate);
}

function indexPaths(codexHome, threadId = undefined) {
  const root = path.join(codexHome, INDEX_DIR);
  const paths = {
    root,
    pendingDir: path.join(root, INDEX_PENDING_DIR),
    processingDir: path.join(root, INDEX_PROCESSING_DIR),
    locksDir: path.join(root, INDEX_LOCKS_DIR),
  };
  if (threadId !== undefined) {
    paths.pending = path.join(paths.pendingDir, threadId);
    paths.processing = path.join(paths.processingDir, threadId);
    paths.lock = path.join(paths.locksDir, threadId);
  }
  return paths;
}

function markerMetadata(markerPath) {
  if (!fs.existsSync(markerPath)) {
    return { exists: false, age_seconds: null };
  }
  const stat = fs.lstatSync(markerPath);
  if (!stat.isFile() || stat.size !== 0) {
    fail(`Central index marker must be a zero-byte regular file: ${markerPath}`);
  }
  return {
    exists: true,
    age_seconds: Math.max(0, (Date.now() - stat.mtimeMs) / 1000),
  };
}

function createMarker(markerPath) {
  fs.mkdirSync(path.dirname(markerPath), { recursive: true });
  try {
    const descriptor = fs.openSync(markerPath, "wx", 0o600);
    fs.closeSync(descriptor);
    return "created";
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    markerMetadata(markerPath);
    return "existing";
  }
}

function sleepMilliseconds(milliseconds) {
  const signal = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(signal, 0, 0, milliseconds);
}

function withIndexLock(codexHome, threadId, callback) {
  const paths = indexPaths(codexHome, threadId);
  fs.mkdirSync(paths.locksDir, { recursive: true });
  let descriptor;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      descriptor = fs.openSync(paths.lock, "wx", 0o600);
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const lock = markerMetadata(paths.lock);
      if (lock.age_seconds > 5 * 60) {
        fs.unlinkSync(paths.lock);
        continue;
      }
      sleepMilliseconds(25);
    }
  }
  if (descriptor === undefined) {
    fail(`Central index is busy for thread: ${threadId}`);
  }
  fs.closeSync(descriptor);
  try {
    return callback(paths);
  } finally {
    if (fs.existsSync(paths.lock)) {
      fs.unlinkSync(paths.lock);
    }
  }
}

function listMarkerIds(directory) {
  if (!fs.existsSync(directory)) return [];
  const entries = fs
    .readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name));
  const ids = [];
  for (const entry of entries) {
    if (!entry.isFile() || !THREAD_ID_PATTERN.test(entry.name)) {
      fail(`Unexpected central index entry: ${path.join(directory, entry.name)}`);
    }
    markerMetadata(path.join(directory, entry.name));
    ids.push(entry.name);
  }
  return ids;
}

function parseLeaseSeconds(value) {
  if (value === undefined) return DEFAULT_CLAIM_LEASE_SECONDS;
  if (!/^[1-9]\d*$/.test(value)) {
    fail("--lease-seconds must be a positive integer", undefined, 2);
  }
  const parsed = Number(value);
  if (parsed > MAX_CLAIM_LEASE_SECONDS) {
    fail(`--lease-seconds must not exceed ${MAX_CLAIM_LEASE_SECONDS}`, undefined, 2);
  }
  return parsed;
}

function eventThreadId(event) {
  if (event.schema_version === EVENT_SCHEMA) {
    return event.origin.thread_id;
  }
  if (
    event.schema_version === LEGACY_EVENT_SCHEMA &&
    typeof event.session_ref === "string" &&
    THREAD_ID_PATTERN.test(event.session_ref)
  ) {
    return event.session_ref;
  }
  return null;
}

function formatSessionFlag(event, artifactRef) {
  const threadId = eventThreadId(event);
  return [
    SESSION_FLAG,
    `session_id: ${threadId}`,
    `event_id: ${event.event_id}`,
    `capability: ${event.capability.id}`,
    `source_repo: ${event.target_repo}`,
    `artifact: ${artifactRef}`,
    "state: pending",
  ].join("\n");
}

function findThreadRollout(codexHome, threadId) {
  const sessionsRoot = path.join(codexHome, "sessions");
  if (!fs.existsSync(sessionsRoot) || !fs.lstatSync(sessionsRoot).isDirectory()) {
    fail(`Codex sessions directory is unavailable: ${sessionsRoot}`);
  }

  const expectedSuffix = `-${threadId}.jsonl`;
  const matches = [];
  let entryCount = 0;
  const visit = (directory) => {
    const entries = fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      entryCount += 1;
      if (entryCount > MAX_SESSION_TREE_ENTRIES) {
        fail(`Codex sessions tree exceeds ${MAX_SESSION_TREE_ENTRIES} entries`);
      }
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        visit(absolutePath);
        continue;
      }
      if (
        entry.isFile() &&
        entry.name.startsWith("rollout-") &&
        entry.name.endsWith(expectedSuffix)
      ) {
        matches.push(absolutePath);
      }
    }
  };
  visit(sessionsRoot);

  if (matches.length === 0) {
    fail(`No Codex rollout found for thread: ${threadId}`);
  }
  if (matches.length > 1) {
    fail(`Multiple Codex rollouts found for thread: ${threadId}`, {
      rollout_paths: matches,
    });
  }
  return matches[0];
}

function visitStringValues(value, visitor) {
  if (typeof value === "string") {
    visitor(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => visitStringValues(item, visitor));
    return;
  }
  if (value && typeof value === "object") {
    Object.values(value).forEach((item) => visitStringValues(item, visitor));
  }
}

function flagRecordFromMatch(match, requestedThreadId) {
  const [
    ,
    sessionIdRaw,
    eventIdRaw,
    capabilityRaw,
    sourceRepoRaw,
    artifactRefRaw,
    stateRaw,
  ] = match;
  const sessionId = sessionIdRaw.trim();
  if (sessionId !== requestedThreadId) {
    return null;
  }

  const eventId = eventIdRaw.trim();
  const capability = capabilityRaw.trim();
  const sourceRepo = sourceRepoRaw.trim();
  const artifactRef = artifactRefRaw.trim();
  const state = stateRaw.trim();
  requireThreadId(sessionId, "session flag session_id");
  requireText(eventId, "session flag event_id", 128);
  if (!EVENT_ID_PATTERN.test(eventId)) {
    fail("session flag event_id has an invalid format");
  }
  requireText(capability, "session flag capability", 256);
  requireText(sourceRepo, "session flag source_repo", 4096);
  if (!path.isAbsolute(sourceRepo) || path.resolve(sourceRepo) !== sourceRepo) {
    fail("session flag source_repo must be a normalized absolute path");
  }
  const artifactRelativePath = requireImprovementArtifactRef(
    artifactRef,
    "session flag artifact",
  );
  if (path.basename(artifactRelativePath) !== `${eventId}.json`) {
    fail("session flag artifact filename must match event_id");
  }
  if (state !== "pending") {
    fail("session flag state must be pending");
  }

  return {
    session_id: sessionId,
    event_id: eventId,
    capability,
    source_repo: sourceRepo,
    artifact: artifactRef,
    artifact_path: path.join(sourceRepo, artifactRelativePath),
    state,
  };
}

function visitRolloutJsonlLines(rolloutPath, visitor) {
  const descriptor = fs.openSync(rolloutPath, "r");
  const readBuffer = Buffer.allocUnsafe(ROLLOUT_READ_CHUNK_BYTES);
  let lineParts = [];
  let lineBytes = 0;
  let lineNumber = 0;

  const visitLine = (lastPart = undefined) => {
    const lastBytes = lastPart?.length ?? 0;
    const totalBytes = lineBytes + lastBytes;
    lineNumber += 1;
    if (totalBytes > MAX_ROLLOUT_LINE_BYTES) {
      fail(
        `Codex rollout JSONL line ${lineNumber} exceeds ${MAX_ROLLOUT_LINE_BYTES} bytes`,
        {
          rollout_path: rolloutPath,
          line: lineNumber,
          bytes: totalBytes,
        },
      );
    }
    let line;
    if (lineParts.length === 0) {
      line = lastPart ?? Buffer.alloc(0);
    } else {
      const parts = lastPart === undefined ? lineParts : [...lineParts, lastPart];
      line = Buffer.concat(parts, totalBytes);
    }
    if (line.length > 0 && line.at(-1) === 0x0d) {
      line = line.subarray(0, line.length - 1);
    }
    visitor(line, lineNumber);
    lineParts = [];
    lineBytes = 0;
  };

  try {
    while (true) {
      const bytesRead = fs.readSync(
        descriptor,
        readBuffer,
        0,
        readBuffer.length,
        null,
      );
      if (bytesRead === 0) break;
      let start = 0;
      while (start < bytesRead) {
        const newline = readBuffer.indexOf(0x0a, start);
        if (newline === -1 || newline >= bytesRead) {
          const tail = readBuffer.subarray(start, bytesRead);
          lineBytes += tail.length;
          if (lineBytes > MAX_ROLLOUT_LINE_BYTES) {
            fail(
              `Codex rollout JSONL line ${lineNumber + 1} exceeds ${MAX_ROLLOUT_LINE_BYTES} bytes`,
              {
                rollout_path: rolloutPath,
                line: lineNumber + 1,
                bytes: lineBytes,
              },
            );
          }
          lineParts.push(Buffer.from(tail));
          break;
        }
        visitLine(readBuffer.subarray(start, newline));
        start = newline + 1;
      }
    }
    if (lineParts.length > 0) {
      visitLine();
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function extractThreadFlags(codexHome, threadId) {
  const rolloutPath = findThreadRollout(codexHome, threadId);
  const stat = fs.lstatSync(rolloutPath);
  if (!stat.isFile()) {
    fail(`Codex rollout must be a regular file: ${rolloutPath}`);
  }

  const flagsByEventId = new Map();
  visitRolloutJsonlLines(rolloutPath, (lineBytes, lineNumber) => {
    const line = lineBytes.toString("utf8");
    if (line.trim().length === 0) return;
    let document;
    try {
      document = JSON.parse(line);
    } catch (error) {
      fail(`Invalid Codex rollout JSONL at line ${lineNumber}`, {
        rollout_path: rolloutPath,
        message: error.message,
      });
    }
    visitStringValues(document, (text) => {
      FLAG_BLOCK_PATTERN.lastIndex = 0;
      for (const match of text.matchAll(FLAG_BLOCK_PATTERN)) {
        const record = flagRecordFromMatch(match, threadId);
        if (record === null) continue;
        const existing = flagsByEventId.get(record.event_id);
        if (
          existing !== undefined &&
          JSON.stringify(existing) !== JSON.stringify(record)
        ) {
          fail(`Conflicting session flags found for event: ${record.event_id}`);
        }
        flagsByEventId.set(record.event_id, record);
      }
    });
  });

  const flags = [...flagsByEventId.values()].sort((left, right) =>
    left.event_id.localeCompare(right.event_id),
  );
  return {
    ok: true,
    mode: "read_only",
    thread_id: threadId,
    rollout_path: rolloutPath,
    rollout_bytes: stat.size,
    rollout_line_max_bytes: MAX_ROLLOUT_LINE_BYTES,
    flag_count: flags.length,
    flags,
    transcript_persisted: false,
    dispatched: false,
  };
}

function commandThreadFlags(args) {
  if (args.execute) {
    fail("thread-flags is read-only and does not accept --execute", undefined, 2);
  }
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  return extractThreadFlags(codexHome, threadId);
}

function requireText(value, label, maxLength, { nullable = false } = {}) {
  if (nullable && value === null) {
    return;
  }
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(`${label} must be a non-empty string`);
  }
  if (value.length > maxLength) {
    fail(`${label} exceeds ${maxLength} characters`);
  }
  if (value.includes("\u0000")) {
    fail(`${label} contains a NUL byte`);
  }
}

function requireEnum(value, label, allowed) {
  if (!allowed.includes(value)) {
    fail(`${label} must be one of: ${allowed.join(", ")}`);
  }
}

function requireExactKeys(value, label, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has unexpected or missing fields`, {
      expected,
      actual,
    });
  }
}

function requireStringArray(
  value,
  label,
  { min = 0, max = 64, itemMax = 2048 } = {},
) {
  if (
    !Array.isArray(value) ||
    value.length < min ||
    (max !== null && value.length > max)
  ) {
    fail(
      max === null
        ? `${label} must contain at least ${min} items`
        : `${label} must contain between ${min} and ${max} items`,
    );
  }
  for (const [index, item] of value.entries()) {
    requireText(item, `${label}[${index}]`, itemMax);
  }
  if (new Set(value).size !== value.length) {
    fail(`${label} contains duplicate items`);
  }
}

function isTypedReference(value) {
  if (
    /^(?:file|path|artifact|packet|collected-packet|role|collected-role):.+$/s.test(
      value,
    )
  ) {
    return true;
  }
  if (/^command:.+\s+exit:-?\d+$/s.test(value)) {
    return true;
  }
  return /^test:.+\s+result:(?:pass|fail|-?\d+)$/s.test(value);
}

function requireTypedReferences(value, label, options = {}) {
  requireStringArray(value, label, options);
  for (const [index, reference] of value.entries()) {
    if (!isTypedReference(reference)) {
      fail(`${label}[${index}] is not a capability-auditor-compatible typed reference`);
    }
  }
}

function requireRepoRelativePath(value, label) {
  requireText(value, label, 1024);
  if (path.isAbsolute(value)) {
    fail(`${label} must be repository-relative`);
  }
  const normalized = path.posix.normalize(value.replaceAll("\\", "/"));
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.startsWith(".capability-improvements/")
  ) {
    fail(`${label} is outside the allowed source scope: ${value}`);
  }
}

function requireIsoTimestamp(value, label) {
  requireText(value, label, 64);
  if (Number.isNaN(Date.parse(value))) {
    fail(`${label} is not an ISO date`);
  }
  return value;
}

function requireSha256(value, label) {
  requireText(value, label, 64);
  if (!SHA256_PATTERN.test(value)) {
    fail(`${label} must be a 64-hex SHA-256 digest`);
  }
  return value.toLowerCase();
}

function requireAutomationResourceId(value, label = "resource-id") {
  requireText(value, label, 128);
  if (!AUTOMATION_RESOURCE_ID_PATTERN.test(value)) {
    fail(
      `${label} must be one safe automation path segment containing only letters, digits, dot, underscore, or hyphen`,
    );
  }
  return value;
}

function requireAutomationStatePath(value, resourceId, label = "state-path") {
  requireText(value, label, 1024);
  const expected = `automations/${resourceId}/automation.toml`;
  if (value !== expected) {
    fail(`${label} must be exactly ${expected}`);
  }
  requireRepoRelativePath(value, label);
  return value;
}

function resolveRegularNonSymlinkRepoPath(root, relativePath, label) {
  const parts = relativePath.split("/");
  let current = root;
  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      fail(`${label} does not exist: ${current}`);
    }
    if (stat.isSymbolicLink()) {
      fail(`${label} must not contain a symlink component: ${current}`);
    }
    if (index < parts.length - 1 && !stat.isDirectory()) {
      fail(`${label} parent must be a directory: ${current}`);
    }
    if (index === parts.length - 1 && !stat.isFile()) {
      fail(`${label} must be a regular file: ${current}`);
    }
  }

  const realPath = fs.realpathSync(current);
  const realRelative = path.relative(root, realPath).split(path.sep).join("/");
  if (
    realRelative !== relativePath ||
    realRelative === ".." ||
    realRelative.startsWith("../")
  ) {
    fail(`${label} must resolve to the exact in-repository path`, {
      declared: relativePath,
      resolved: realRelative,
    });
  }
  return realPath;
}

function assertGitIgnoredUntracked(root, relativePath) {
  const tracked = runGit(
    root,
    ["ls-files", "--error-unmatch", "--", relativePath],
    { allowFailure: true },
  );
  if (tracked.status === 0) {
    fail(`App-managed state must be untracked by Git: ${relativePath}`);
  }

  const ignored = runGit(
    root,
    ["check-ignore", "--quiet", "--", relativePath],
    { allowFailure: true },
  );
  if (ignored.status !== 0) {
    fail(`App-managed state must be Git-ignored: ${relativePath}`);
  }

  const ignoredUntracked = runGit(root, [
    "ls-files",
    "--others",
    "--ignored",
    "--exclude-standard",
    "--",
    relativePath,
  ]).stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!ignoredUntracked.includes(relativePath)) {
    fail(`App-managed state must be an ignored untracked file: ${relativePath}`);
  }
}

function sha256File(absolutePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(absolutePath))
    .digest("hex");
}

function requireSuccessfulAutomationUpdateEvidence(value, label) {
  requireText(value, label, 2048);
  if (!isTypedReference(value)) {
    fail(`${label} must be a capability-auditor-compatible typed reference`);
  }
  if (!/\bcodex_app\.automation_update\b/.test(value)) {
    fail(`${label} must name codex_app.automation_update`);
  }
  if (
    !/(?:\bexit:0|\bresult:(?:pass|0)|\bstatus:(?:success|succeeded|passed))$/i.test(
      value,
    )
  ) {
    fail(`${label} must prove a successful codex_app.automation_update`);
  }
  return value;
}

function requireImprovementArtifactRef(value, label) {
  requireText(value, label, 2048);
  const match =
    /^artifact:(\.capability-improvements\/[^/]+\.json)$/.exec(value);
  if (!match) {
    fail(`${label} must reference one direct .capability-improvements JSON artifact`);
  }
  return match[1];
}

function loadImprovementArtifact(root, artifactRef, expectedSchemas) {
  const relativePath = requireImprovementArtifactRef(
    artifactRef,
    "improvement artifact reference",
  );
  const absolutePath = path.join(root, relativePath);
  if (!fs.existsSync(absolutePath)) {
    fail(`Improvement artifact does not exist: ${absolutePath}`);
  }
  const stat = fs.lstatSync(absolutePath);
  if (!stat.isFile()) {
    fail(`Improvement artifact must be a regular file: ${absolutePath}`);
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
  } catch (error) {
    fail(`Invalid JSON: ${absolutePath}`, { message: error.message });
  }
  if (!expectedSchemas.includes(document.schema_version)) {
    fail(`Unexpected improvement artifact schema: ${document.schema_version}`);
  }
  if (
    document.schema_version === PLAN_SCHEMA ||
    document.schema_version === LEGACY_PLAN_SCHEMA
  ) {
    validateProposal(document, root);
  } else if (
    document.schema_version === EVENT_SCHEMA ||
    document.schema_version === LEGACY_EVENT_SCHEMA
  ) {
    validateEvent(document, root);
  } else if (document.schema_version === RESOLUTION_SCHEMA) {
    validateResolution(document, root);
  } else if (document.schema_version === APP_STATE_RESOLUTION_SCHEMA) {
    validateAppStateResolution(document, root);
  } else if (document.schema_version === MONITOR_DISPOSITION_SCHEMA) {
    validateMonitorDisposition(document, root);
  } else if (document.schema_version === RETIREMENT_DISPOSITION_SCHEMA) {
    validateRetirementDisposition(document, root);
  }
  return { artifactRef, relativePath, absolutePath, document };
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function sameStringSet(left, right) {
  const normalizedLeft = sortedUnique(left);
  const normalizedRight = sortedUnique(right);
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

function requireCaoAuthority(route, authorityRef, label) {
  if (
    route === "coding-agent-orchestrator" &&
    !/(?:\bCAO\b|coding-agent-orchestrator|Coding Agent Orchestrator)/i.test(
      authorityRef,
    )
  ) {
    fail(`${label} requires explicit CAO authority evidence`);
  }
}

function repairExecutionFromArgs(args, { requireEvidence = false } = {}) {
  requireEnum(args["execution-route"], "execution-route", [
    "direct",
    "coding-agent-orchestrator",
  ]);
  requireTypedReferences(
    [args["execution-authority"]],
    "execution-authority",
    { min: 1, max: 1 },
  );
  requireCaoAuthority(
    args["execution-route"],
    args["execution-authority"],
    "Coding Agent Orchestrator",
  );
  const evidenceRefs = args["execution-evidence"] ?? [];
  requireTypedReferences(evidenceRefs, "execution-evidence", {
    min: requireEvidence ? 1 : 0,
  });
  let executionId = null;
  if (requireEvidence) {
    requireText(args["execution-id"], "execution-id", 256);
    executionId = args["execution-id"];
  }
  return {
    route: args["execution-route"],
    execution_id: executionId,
    authority_ref: args["execution-authority"],
    evidence_refs: sortedUnique(evidenceRefs),
  };
}

function assertNoLikelySecret(value, label) {
  const serialized =
    typeof value === "string" ? value : JSON.stringify(value);
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(serialized)) {
      fail(`${label} contains a likely credential or private key`);
    }
  }
}

function assertJsonSize(value, label, maximum) {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > maximum) {
    fail(`${label} exceeds ${maximum} bytes`, { bytes });
  }
}

function isoTimestamp() {
  return new Date().toISOString();
}

function compactTimestamp(iso) {
  return iso.replace(/[-:.TZ]/g, "").slice(0, 17);
}

function stableHash(value) {
  return crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : JSON.stringify(value))
    .digest("hex");
}

function normalizedForKey(value) {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function computeRepeatKey(fields) {
  const material = [
    fields.capability_id,
    fields.category,
    fields.source_boundary,
    normalizedForKey(fields.expected),
    normalizedForKey(fields.actual),
  ].join("\u001f");
  return `repeat-${stableHash(material).slice(0, 24)}`;
}

function eventFromArgs(args, root) {
  const required = [
    "capability-id",
    "capability-kind",
    "category",
    "summary",
    "expected",
    "actual",
    "compensation",
    "outcome",
    "evidence-strength",
    "repeatability",
    "severity",
    "source-boundary",
  ];
  for (const field of required) {
    if (!Object.hasOwn(args, field)) {
      fail(`record requires --${field}`, undefined, 2);
    }
  }
  if (!Array.isArray(args.evidence) || args.evidence.length === 0) {
    fail("record requires at least one --evidence", undefined, 2);
  }
  if (!Object.hasOwn(args, "thread-id")) {
    fail("record requires --thread-id", undefined, 2);
  }
  const threadId = requireThreadId(args["thread-id"]);

  const recordedAt = isoTimestamp();
  const repeatFields = {
    capability_id: args["capability-id"],
    category: args.category,
    source_boundary: args["source-boundary"],
    expected: args.expected,
    actual: args.actual,
  };
  const event = {
    schema_version: EVENT_SCHEMA,
    event_id: `event-${compactTimestamp(recordedAt)}-${crypto.randomUUID().slice(0, 8)}`,
    recorded_at: recordedAt,
    target_repo: root,
    capability: {
      id: args["capability-id"],
      kind: args["capability-kind"],
      source_ref: args["source-ref"] ?? "path:.",
    },
    incident: {
      category: args.category,
      summary: args.summary,
      expected_contract: args.expected,
      observed_behavior: args.actual,
      compensation: args.compensation,
      outcome: args.outcome,
      root_cause: args["root-cause"] ?? null,
    },
    classification: {
      evidence_strength: args["evidence-strength"],
      repeatability: args.repeatability,
      severity: args.severity,
      source_boundary: args["source-boundary"],
    },
    evidence_refs: args.evidence,
    candidate_files: args["candidate-file"] ?? [],
    verification_refs: args.verification ?? [],
    repeat_key:
      args["repeat-key"] ??
      computeRepeatKey(repeatFields),
    origin: {
      thread_id: threadId,
      session_flag: SESSION_FLAG,
    },
    status: "open",
  };
  validateEvent(event, root);
  return event;
}

function validateEvent(event, expectedRoot = undefined) {
  const legacy = event.schema_version === LEGACY_EVENT_SCHEMA;
  if (!legacy && event.schema_version !== EVENT_SCHEMA) {
    fail(`event.schema_version must be ${EVENT_SCHEMA} or ${LEGACY_EVENT_SCHEMA}`);
  }
  requireExactKeys(event, "event", [
    "schema_version",
    "event_id",
    "recorded_at",
    "target_repo",
    "capability",
    "incident",
    "classification",
    "evidence_refs",
    "candidate_files",
    "verification_refs",
    "repeat_key",
    legacy ? "session_ref" : "origin",
    "status",
  ]);
  requireText(event.event_id, "event.event_id", 128);
  if (!EVENT_ID_PATTERN.test(event.event_id)) {
    fail("event.event_id has an invalid format");
  }
  requireText(event.recorded_at, "event.recorded_at", 64);
  if (Number.isNaN(Date.parse(event.recorded_at))) {
    fail("event.recorded_at is not an ISO date");
  }
  requireText(event.target_repo, "event.target_repo", 4096);
  if (!path.isAbsolute(event.target_repo)) {
    fail("event.target_repo must be absolute");
  }
  if (expectedRoot && fs.realpathSync(event.target_repo) !== expectedRoot) {
    fail("event.target_repo does not match the resolved repository", {
      expected: expectedRoot,
      actual: event.target_repo,
    });
  }

  requireExactKeys(event.capability, "event.capability", [
    "id",
    "kind",
    "source_ref",
  ]);
  requireText(event.capability.id, "event.capability.id", 256);
  requireEnum(
    event.capability.kind,
    "event.capability.kind",
    ENUMS.capability_kind,
  );
  requireText(event.capability.source_ref, "event.capability.source_ref", 2048);
  if (!isTypedReference(event.capability.source_ref)) {
    fail("event.capability.source_ref must be a typed reference");
  }

  requireExactKeys(event.incident, "event.incident", [
    "category",
    "summary",
    "expected_contract",
    "observed_behavior",
    "compensation",
    "outcome",
    "root_cause",
  ]);
  requireEnum(event.incident.category, "event.incident.category", ENUMS.category);
  requireText(event.incident.summary, "event.incident.summary", 512);
  requireText(
    event.incident.expected_contract,
    "event.incident.expected_contract",
    4000,
  );
  requireText(
    event.incident.observed_behavior,
    "event.incident.observed_behavior",
    4000,
  );
  requireText(event.incident.compensation, "event.incident.compensation", 4000);
  requireText(event.incident.outcome, "event.incident.outcome", 4000);
  requireText(event.incident.root_cause, "event.incident.root_cause", 4000, {
    nullable: true,
  });

  requireExactKeys(event.classification, "event.classification", [
    "evidence_strength",
    "repeatability",
    "severity",
    "source_boundary",
  ]);
  requireEnum(
    event.classification.evidence_strength,
    "event.classification.evidence_strength",
    ENUMS.evidence_strength,
  );
  requireEnum(
    event.classification.repeatability,
    "event.classification.repeatability",
    ENUMS.repeatability,
  );
  requireEnum(
    event.classification.severity,
    "event.classification.severity",
    ENUMS.severity,
  );
  requireEnum(
    event.classification.source_boundary,
    "event.classification.source_boundary",
    ENUMS.source_boundary,
  );

  requireTypedReferences(event.evidence_refs, "event.evidence_refs", {
    min: 1,
  });
  requireStringArray(event.candidate_files, "event.candidate_files", {
    max: 64,
    itemMax: 1024,
  });
  event.candidate_files.forEach((candidate, index) =>
    requireRepoRelativePath(candidate, `event.candidate_files[${index}]`),
  );
  requireTypedReferences(
    event.verification_refs,
    "event.verification_refs",
    { max: 64 },
  );
  requireText(event.repeat_key, "event.repeat_key", 256);
  if (legacy) {
    requireText(event.session_ref, "event.session_ref", 1024, {
      nullable: true,
    });
    if (
      event.session_ref !== null &&
      !THREAD_ID_PATTERN.test(event.session_ref)
    ) {
      fail("event.session_ref must be a lowercase UUID when present");
    }
  } else {
    requireExactKeys(event.origin, "event.origin", [
      "thread_id",
      "session_flag",
    ]);
    requireThreadId(event.origin.thread_id, "event.origin.thread_id");
    if (event.origin.session_flag !== SESSION_FLAG) {
      fail(`event.origin.session_flag must be ${SESSION_FLAG}`);
    }
  }
  if (event.status !== "open") {
    fail("event.status must be open");
  }

  assertNoLikelySecret(event, "event");
  assertJsonSize(event, "event", MAX_EVENT_BYTES);
  return true;
}

function proposalFromGroup(root, repeatKey, records) {
  const events = records
    .map((record) => record.document)
    .sort((left, right) => left.event_id.localeCompare(right.event_id));
  const categories = [...new Set(events.map((event) => event.incident.category))];
  const capabilityIds = [
    ...new Set(events.map((event) => event.capability.id)),
  ];
  const threadIds = [
    ...new Set(events.map(eventThreadId).filter(Boolean)),
  ].sort();
  const highSeverity = events.some((event) =>
    ["high", "critical"].includes(event.classification.severity),
  );
  const explicitRepeat = events.some((event) =>
    ["reproduced", "repeated"].includes(event.classification.repeatability),
  );
  const groupedRepeat = events.length >= 2;
  const directStructural = events.some(
    (event) =>
      event.classification.evidence_strength === "direct" &&
      STRUCTURAL_CATEGORIES.has(event.incident.category),
  );
  const repairCandidate =
    highSeverity || explicitRepeat || groupedRepeat || directStructural;

  const rationale = [];
  if (highSeverity) rationale.push("high_or_critical_severity");
  if (explicitRepeat) rationale.push("declared_reproduced_or_repeated");
  if (groupedRepeat) rationale.push("multiple_events_share_repeat_key");
  if (directStructural) rationale.push("direct_structural_contract_evidence");
  if (!repairCandidate) {
    rationale.push("insufficient_evidence_for_source_repair");
  }
  if (
    events.every(
      (event) =>
        event.incident.category === "input_format_mismatch" &&
        ["low", "medium"].includes(event.classification.severity) &&
        ["one_off", "unknown"].includes(event.classification.repeatability),
    ) &&
    events.length === 1
  ) {
    rationale.push("single_weak_input_anomaly_remains_monitor");
  }

  const candidateFiles = [
    ...new Set(events.flatMap((event) => event.candidate_files)),
  ].sort();
  const verificationRefs = [
    ...new Set(events.flatMap((event) => event.verification_refs)),
  ].sort();
  const evidenceRefs = [
    ...new Set(events.flatMap((event) => event.evidence_refs)),
  ].sort();
  const handoffReady =
    repairCandidate &&
    capabilityIds.length === 1 &&
    threadIds.length > 0 &&
    candidateFiles.length > 0 &&
    verificationRefs.length > 0;

  if (capabilityIds.length > 1) {
    rationale.push("mixed_capability_ids_require_manual_split");
  }
  if (repairCandidate && candidateFiles.length === 0) {
    rationale.push("candidate_source_scope_missing");
  }
  if (repairCandidate && verificationRefs.length === 0) {
    rationale.push("verification_plan_missing");
  }
  if (repairCandidate && threadIds.length === 0) {
    rationale.push("verified_thread_id_missing");
  }

  const proposalDigest = stableHash({
    repeat_key: repeatKey,
    event_ids: events.map((event) => event.event_id),
    classification: repairCandidate ? "repair_candidate" : "monitor",
  }).slice(0, 20);
  const proposalId = `proposal-${proposalDigest}`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    `${proposalId}.json`,
  );
  const createdAt = events
    .map((event) => event.recorded_at)
    .sort()
    .at(-1);
  const proposal = {
    schema_version: PLAN_SCHEMA,
    proposal_id: proposalId,
    created_at: createdAt,
    target_repo: root,
    capability: {
      id: capabilityIds.length === 1 ? capabilityIds[0] : "mixed",
      kinds: [...new Set(events.map((event) => event.capability.kind))].sort(),
    },
    repeat_key: repeatKey,
    classification: repairCandidate ? "repair_candidate" : "monitor",
    handoff_ready: handoffReady,
    rationale,
    source_events: records
      .map(
        (record) =>
          `artifact:${path.posix.join(
            ".capability-improvements",
            record.filename,
          )}`,
      )
      .sort(),
    event_ids: events.map((event) => event.event_id),
    thread_ids: threadIds,
    evidence_refs: evidenceRefs,
    candidate_files: candidateFiles,
    verification_refs: verificationRefs,
    repair_policy: {
      test_relaxation_for_single_anomaly: "forbidden",
      required_approach:
        "Repair the demonstrated source or contract boundary; preserve existing acceptance strength unless contrary evidence is reproduced and validated.",
    },
    recommended_actions: repairCandidate
      ? [
          "Reproduce or confirm the demonstrated failure boundary.",
          "Inspect the declared candidate source scope and competing input, route, runtime, and validator hypotheses.",
          "Implement the smallest source-owned root-cause repair.",
          "Run the declared verification references and preserve regression coverage.",
        ]
      : [
          "Retain the evidence without changing source behavior.",
          "Seek an independent reproduction or stronger structural evidence.",
        ],
    stop_conditions: [
      "Do not weaken a test, schema, or validator solely for one anomalous input.",
      "Stop if the authoritative source boundary changes or cannot be verified.",
      "Keep commit, refresh, activation, deletion, publication, and external actions outside this proposal's authority.",
    ],
    repair_handoff: {
      artifact_ref: `artifact:${relativePath}`,
      ready: handoffReady,
      required_intake: [
        "Read this proposal and the affected authoritative source before repair.",
        "Obtain explicit authority for the repair and for any optional orchestration route.",
        "Use Coding Agent Orchestrator only when the current user explicitly selects CAO or $coding-agent-orchestrator in the current GUI Codex task.",
        "Seal the repair scope, ownership, acceptance criteria, and minimum verification before execution.",
      ],
    },
    status: "proposed",
  };
  validateProposal(proposal, root);
  return { proposal, relativePath };
}

function validateProposal(proposal, expectedRoot = undefined) {
  const legacy = proposal.schema_version === LEGACY_PLAN_SCHEMA;
  if (!legacy && proposal.schema_version !== PLAN_SCHEMA) {
    fail(`proposal.schema_version must be ${PLAN_SCHEMA} or ${LEGACY_PLAN_SCHEMA}`);
  }
  requireExactKeys(proposal, "proposal", [
    "schema_version",
    "proposal_id",
    "created_at",
    "target_repo",
    "capability",
    "repeat_key",
    "classification",
    "handoff_ready",
    "rationale",
    "source_events",
    "event_ids",
    ...(legacy ? [] : ["thread_ids"]),
    "evidence_refs",
    "candidate_files",
    "verification_refs",
    "repair_policy",
    "recommended_actions",
    "stop_conditions",
    "repair_handoff",
    "status",
  ]);
  requireText(proposal.proposal_id, "proposal.proposal_id", 128);
  if (!/^proposal-[0-9a-f]{20}$/.test(proposal.proposal_id)) {
    fail("proposal.proposal_id has an invalid format");
  }
  requireText(proposal.created_at, "proposal.created_at", 64);
  if (Number.isNaN(Date.parse(proposal.created_at))) {
    fail("proposal.created_at is not an ISO date");
  }
  requireText(proposal.target_repo, "proposal.target_repo", 4096);
  if (!path.isAbsolute(proposal.target_repo)) {
    fail("proposal.target_repo must be absolute");
  }
  if (expectedRoot && fs.realpathSync(proposal.target_repo) !== expectedRoot) {
    fail("proposal.target_repo does not match the resolved repository");
  }

  requireExactKeys(proposal.capability, "proposal.capability", ["id", "kinds"]);
  requireText(proposal.capability.id, "proposal.capability.id", 256);
  requireStringArray(proposal.capability.kinds, "proposal.capability.kinds", {
    min: 1,
    max: ENUMS.capability_kind.length,
    itemMax: 32,
  });
  proposal.capability.kinds.forEach((kind) =>
    requireEnum(kind, "proposal.capability.kinds[]", ENUMS.capability_kind),
  );
  requireText(proposal.repeat_key, "proposal.repeat_key", 256);
  requireEnum(proposal.classification, "proposal.classification", [
    "monitor",
    "repair_candidate",
  ]);
  if (typeof proposal.handoff_ready !== "boolean") {
    fail("proposal.handoff_ready must be boolean");
  }
  requireStringArray(proposal.rationale, "proposal.rationale", {
    min: 1,
    max: 16,
    itemMax: 256,
  });
  requireTypedReferences(proposal.source_events, "proposal.source_events", {
    min: 1,
  });
  requireStringArray(proposal.event_ids, "proposal.event_ids", {
    min: 1,
    itemMax: 128,
  });
  if (!legacy) {
    requireStringArray(proposal.thread_ids, "proposal.thread_ids", {
      min: 1,
      itemMax: 64,
    });
    proposal.thread_ids.forEach((threadId, index) =>
      requireThreadId(threadId, `proposal.thread_ids[${index}]`),
    );
  }
  requireTypedReferences(proposal.evidence_refs, "proposal.evidence_refs", {
    min: 1,
  });
  requireStringArray(proposal.candidate_files, "proposal.candidate_files", {
    max: 64,
    itemMax: 1024,
  });
  proposal.candidate_files.forEach((candidate, index) =>
    requireRepoRelativePath(candidate, `proposal.candidate_files[${index}]`),
  );
  requireTypedReferences(
    proposal.verification_refs,
    "proposal.verification_refs",
    { max: 64 },
  );

  requireExactKeys(proposal.repair_policy, "proposal.repair_policy", [
    "test_relaxation_for_single_anomaly",
    "required_approach",
  ]);
  if (
    proposal.repair_policy.test_relaxation_for_single_anomaly !== "forbidden"
  ) {
    fail(
      "proposal.repair_policy.test_relaxation_for_single_anomaly must be forbidden",
    );
  }
  requireText(
    proposal.repair_policy.required_approach,
    "proposal.repair_policy.required_approach",
    2000,
  );
  requireStringArray(
    proposal.recommended_actions,
    "proposal.recommended_actions",
    { min: 1, max: 16, itemMax: 1000 },
  );
  requireStringArray(proposal.stop_conditions, "proposal.stop_conditions", {
    min: 1,
    max: 16,
    itemMax: 1000,
  });
  requireExactKeys(
    proposal.repair_handoff,
    "proposal.repair_handoff",
    ["artifact_ref", "ready", "required_intake"],
  );
  requireText(
    proposal.repair_handoff.artifact_ref,
    "proposal.repair_handoff.artifact_ref",
    2048,
  );
  if (!/^artifact:\.capability-improvements\/.+\.json$/.test(
    proposal.repair_handoff.artifact_ref,
  )) {
    fail("proposal repair handoff artifact reference is invalid");
  }
  if (proposal.repair_handoff.ready !== proposal.handoff_ready) {
    fail("proposal handoff readiness fields disagree");
  }
  requireStringArray(
    proposal.repair_handoff.required_intake,
    "proposal.repair_handoff.required_intake",
    { min: 1, max: 16, itemMax: 1000 },
  );
  if (
    proposal.handoff_ready &&
    (proposal.classification !== "repair_candidate" ||
      proposal.candidate_files.length === 0 ||
      proposal.verification_refs.length === 0)
  ) {
    fail("handoff_ready requires repair_candidate, candidate files, and verification");
  }
  if (proposal.status !== "proposed") {
    fail("proposal.status must be proposed");
  }

  assertNoLikelySecret(proposal, "proposal");
  assertJsonSize(proposal, "proposal", MAX_PLAN_BYTES);
  return true;
}

function validateResolution(resolution, expectedRoot = undefined) {
  if (resolution.schema_version !== RESOLUTION_SCHEMA) {
    fail(`resolution.schema_version must be ${RESOLUTION_SCHEMA}`);
  }
  requireExactKeys(resolution, "resolution", [
    "schema_version",
    "resolution_id",
    "resolved_at",
    "target_repo",
    "proposal_ref",
    "proposal_id",
    "event_ids",
    "thread_ids",
    "root_cause",
    "changed_files",
    "verification_refs",
    "repair_execution",
    "source_control",
    "refresh",
    "status",
  ]);
  requireText(resolution.resolution_id, "resolution.resolution_id", 128);
  if (!/^resolution-[0-9a-f]{24}$/.test(resolution.resolution_id)) {
    fail("resolution.resolution_id has an invalid format");
  }
  requireText(resolution.resolved_at, "resolution.resolved_at", 64);
  if (Number.isNaN(Date.parse(resolution.resolved_at))) {
    fail("resolution.resolved_at is not an ISO date");
  }
  requireText(resolution.target_repo, "resolution.target_repo", 4096);
  if (!path.isAbsolute(resolution.target_repo)) {
    fail("resolution.target_repo must be absolute");
  }
  if (expectedRoot && fs.realpathSync(resolution.target_repo) !== expectedRoot) {
    fail("resolution.target_repo does not match the resolved repository");
  }
  requireImprovementArtifactRef(
    resolution.proposal_ref,
    "resolution.proposal_ref",
  );
  requireText(resolution.proposal_id, "resolution.proposal_id", 128);
  requireStringArray(resolution.event_ids, "resolution.event_ids", {
    min: 1,
    itemMax: 128,
  });
  requireStringArray(resolution.thread_ids, "resolution.thread_ids", {
    min: 1,
    itemMax: 64,
  });
  resolution.thread_ids.forEach((threadId, index) =>
    requireThreadId(threadId, `resolution.thread_ids[${index}]`),
  );
  requireText(resolution.root_cause, "resolution.root_cause", 4000);
  requireStringArray(resolution.changed_files, "resolution.changed_files", {
    min: 1,
    max: null,
    itemMax: 1024,
  });
  resolution.changed_files.forEach((filename, index) =>
    requireRepoRelativePath(filename, `resolution.changed_files[${index}]`),
  );
  requireTypedReferences(
    resolution.verification_refs,
    "resolution.verification_refs",
    { min: 1 },
  );

  requireExactKeys(resolution.repair_execution, "resolution.repair_execution", [
    "route",
    "execution_id",
    "authority_ref",
    "evidence_refs",
  ]);
  requireEnum(resolution.repair_execution.route, "resolution.repair_execution.route", [
    "direct",
    "coding-agent-orchestrator",
  ]);
  requireText(
    resolution.repair_execution.execution_id,
    "resolution.repair_execution.execution_id",
    256,
  );
  requireTypedReferences(
    [resolution.repair_execution.authority_ref],
    "resolution.repair_execution.authority_ref",
    { min: 1, max: 1 },
  );
  requireCaoAuthority(
    resolution.repair_execution.route,
    resolution.repair_execution.authority_ref,
    "resolution.repair_execution",
  );
  requireTypedReferences(
    resolution.repair_execution.evidence_refs,
    "resolution.repair_execution.evidence_refs",
    { min: 1 },
  );

  const sourceControlKeys = Object.keys(resolution.source_control ?? {}).sort();
  const legacySourceControlKeys = ["commit", "head_verified"].sort();
  const currentSourceControlKeys = [
    "commit",
    "commit_mode",
    "head_verified",
    "verified_head",
  ].sort();
  const legacySourceControl =
    sourceControlKeys.length === legacySourceControlKeys.length &&
    sourceControlKeys.every(
      (key, index) => key === legacySourceControlKeys[index],
    );
  const currentSourceControl =
    sourceControlKeys.length === currentSourceControlKeys.length &&
    sourceControlKeys.every(
      (key, index) => key === currentSourceControlKeys[index],
    );
  if (!legacySourceControl && !currentSourceControl) {
    fail("resolution.source_control has unexpected or missing fields", {
      expected: [legacySourceControlKeys, currentSourceControlKeys],
      actual: sourceControlKeys,
    });
  }
  if (!/^[0-9a-f]{40}$/.test(resolution.source_control.commit)) {
    fail("resolution.source_control.commit must be a full lowercase Git SHA");
  }
  if (resolution.source_control.head_verified !== true) {
    fail("resolution.source_control.head_verified must be true");
  }
  if (currentSourceControl) {
    if (!/^[0-9a-f]{40}$/.test(resolution.source_control.verified_head)) {
      fail(
        "resolution.source_control.verified_head must be a full lowercase Git SHA",
      );
    }
    requireEnum(
      resolution.source_control.commit_mode,
      "resolution.source_control.commit_mode",
      ["head", "ancestor", "preexisting"],
    );
    if (
      resolution.source_control.commit_mode === "head" &&
      resolution.source_control.commit !== resolution.source_control.verified_head
    ) {
      fail("head-mode resolution commit must equal verified_head");
    }
    if (
      resolution.source_control.commit_mode === "ancestor" &&
      resolution.source_control.commit === resolution.source_control.verified_head
    ) {
      fail("ancestor-mode resolution commit must predate verified_head");
    }
    if (expectedRoot) {
      const commitExists = runGit(
        expectedRoot,
        ["cat-file", "-e", `${resolution.source_control.commit}^{commit}`],
        { allowFailure: true },
      );
      const verifiedHeadExists = runGit(
        expectedRoot,
        [
          "cat-file",
          "-e",
          `${resolution.source_control.verified_head}^{commit}`,
        ],
        { allowFailure: true },
      );
      if (commitExists.status !== 0 || verifiedHeadExists.status !== 0) {
        fail("resolution.source_control references an unavailable Git commit");
      }
      if (
        resolution.source_control.commit_mode === "ancestor" ||
        (resolution.source_control.commit_mode === "preexisting" &&
          resolution.source_control.commit !==
            resolution.source_control.verified_head)
      ) {
        const ancestry = runGit(
          expectedRoot,
          [
            "merge-base",
            "--is-ancestor",
            resolution.source_control.commit,
            resolution.source_control.verified_head,
          ],
          { allowFailure: true },
        );
        if (ancestry.status !== 0) {
          fail("resolution repair commit is not an ancestor of verified_head");
        }
      }
    }
  }

  requireExactKeys(resolution.refresh, "resolution.refresh", [
    "status",
    "evidence_ref",
  ]);
  requireEnum(resolution.refresh.status, "resolution.refresh.status", [
    "passed",
    "not_applicable",
  ]);
  if (resolution.refresh.status === "passed") {
    requireTypedReferences(
      [resolution.refresh.evidence_ref],
      "resolution.refresh.evidence_ref",
      { min: 1, max: 1 },
    );
  } else if (resolution.refresh.evidence_ref !== null) {
    fail("resolution.refresh.evidence_ref must be null when not_applicable");
  }
  if (resolution.status !== "closed") {
    fail("resolution.status must be closed");
  }
  assertNoLikelySecret(resolution, "resolution");
  assertJsonSize(resolution, "resolution", MAX_RESOLUTION_BYTES);
  return true;
}

function validateAppStateResolution(resolution, expectedRoot = undefined) {
  if (resolution.schema_version !== APP_STATE_RESOLUTION_SCHEMA) {
    fail(
      `app state resolution.schema_version must be ${APP_STATE_RESOLUTION_SCHEMA}`,
    );
  }
  requireExactKeys(resolution, "app state resolution", [
    "schema_version",
    "resolution_id",
    "resolved_at",
    "target_repo",
    "proposal_ref",
    "proposal_id",
    "event_ids",
    "thread_ids",
    "root_cause",
    "state",
    "evidence",
    "repair_execution",
    "source_control",
    "status",
  ]);
  requireText(
    resolution.resolution_id,
    "app state resolution.resolution_id",
    128,
  );
  if (!/^app-state-resolution-[0-9a-f]{24}$/.test(resolution.resolution_id)) {
    fail("app state resolution.resolution_id has an invalid format");
  }
  requireIsoTimestamp(
    resolution.resolved_at,
    "app state resolution.resolved_at",
  );
  requireText(
    resolution.target_repo,
    "app state resolution.target_repo",
    4096,
  );
  if (!path.isAbsolute(resolution.target_repo)) {
    fail("app state resolution.target_repo must be absolute");
  }
  if (
    expectedRoot &&
    fs.realpathSync(resolution.target_repo) !== expectedRoot
  ) {
    fail(
      "app state resolution.target_repo does not match the resolved repository",
    );
  }
  requireImprovementArtifactRef(
    resolution.proposal_ref,
    "app state resolution.proposal_ref",
  );
  requireText(
    resolution.proposal_id,
    "app state resolution.proposal_id",
    128,
  );
  requireStringArray(
    resolution.event_ids,
    "app state resolution.event_ids",
    { min: 1, itemMax: 128 },
  );
  requireStringArray(
    resolution.thread_ids,
    "app state resolution.thread_ids",
    { min: 1, itemMax: 64 },
  );
  resolution.thread_ids.forEach((threadId, index) =>
    requireThreadId(
      threadId,
      `app state resolution.thread_ids[${index}]`,
    ),
  );
  requireText(
    resolution.root_cause,
    "app state resolution.root_cause",
    4000,
  );

  requireExactKeys(resolution.state, "app state resolution.state", [
    "surface",
    "resource_id",
    "path",
    "observed_at",
    "before_sha256",
    "after_sha256",
    "changed_fields",
    "preserved_fields",
  ]);
  if (resolution.state.surface !== APP_STATE_SURFACE) {
    fail(`app state resolution.state.surface must be ${APP_STATE_SURFACE}`);
  }
  const resourceId = requireAutomationResourceId(
    resolution.state.resource_id,
    "app state resolution.state.resource_id",
  );
  requireAutomationStatePath(
    resolution.state.path,
    resourceId,
    "app state resolution.state.path",
  );
  requireIsoTimestamp(
    resolution.state.observed_at,
    "app state resolution.state.observed_at",
  );
  if (resolution.resolved_at !== resolution.state.observed_at) {
    fail(
      "app state resolution.resolved_at must equal state.observed_at",
    );
  }
  const beforeSha256 = requireSha256(
    resolution.state.before_sha256,
    "app state resolution.state.before_sha256",
  );
  const afterSha256 = requireSha256(
    resolution.state.after_sha256,
    "app state resolution.state.after_sha256",
  );
  if (beforeSha256 === afterSha256) {
    fail(
      "app state resolution before_sha256 and after_sha256 must differ",
    );
  }
  requireStringArray(
    resolution.state.changed_fields,
    "app state resolution.state.changed_fields",
    { min: 1, max: 64, itemMax: 512 },
  );
  requireStringArray(
    resolution.state.preserved_fields,
    "app state resolution.state.preserved_fields",
    { min: 1, max: 64, itemMax: 512 },
  );

  requireExactKeys(resolution.evidence, "app state resolution.evidence", [
    "operation",
    "readback_refs",
    "invariant_refs",
    "verification_refs",
  ]);
  requireSuccessfulAutomationUpdateEvidence(
    resolution.evidence.operation,
    "app state resolution.evidence.operation",
  );
  requireTypedReferences(
    resolution.evidence.readback_refs,
    "app state resolution.evidence.readback_refs",
    { min: 1 },
  );
  requireTypedReferences(
    resolution.evidence.invariant_refs,
    "app state resolution.evidence.invariant_refs",
    { min: 1 },
  );
  requireTypedReferences(
    resolution.evidence.verification_refs,
    "app state resolution.evidence.verification_refs",
    { min: 1 },
  );

  requireExactKeys(
    resolution.repair_execution,
    "app state resolution.repair_execution",
    [
      "route",
      "execution_id",
      "authority_ref",
      "evidence_refs",
    ],
  );
  requireEnum(
    resolution.repair_execution.route,
    "app state resolution.repair_execution.route",
    ["direct", "coding-agent-orchestrator"],
  );
  requireText(
    resolution.repair_execution.execution_id,
    "app state resolution.repair_execution.execution_id",
    256,
  );
  requireTypedReferences(
    [resolution.repair_execution.authority_ref],
    "app state resolution.repair_execution.authority_ref",
    { min: 1, max: 1 },
  );
  requireCaoAuthority(
    resolution.repair_execution.route,
    resolution.repair_execution.authority_ref,
    "app state resolution.repair_execution",
  );
  requireTypedReferences(
    resolution.repair_execution.evidence_refs,
    "app state resolution.repair_execution.evidence_refs",
    { min: 1 },
  );

  requireExactKeys(
    resolution.source_control,
    "app state resolution.source_control",
    ["required", "reason"],
  );
  if (resolution.source_control.required !== false) {
    fail("app state resolution.source_control.required must be false");
  }
  if (
    resolution.source_control.reason !== APP_STATE_SOURCE_CONTROL_REASON
  ) {
    fail(
      `app state resolution.source_control.reason must be ${APP_STATE_SOURCE_CONTROL_REASON}`,
    );
  }
  if (resolution.status !== "closed_after_app_state_repair") {
    fail(
      "app state resolution.status must be closed_after_app_state_repair",
    );
  }
  assertNoLikelySecret(resolution, "app state resolution");
  assertJsonSize(
    resolution,
    "app state resolution",
    MAX_APP_STATE_RESOLUTION_BYTES,
  );
  return true;
}

function validateMonitorDisposition(disposition, expectedRoot = undefined) {
  if (disposition.schema_version !== MONITOR_DISPOSITION_SCHEMA) {
    fail(
      `monitor disposition.schema_version must be ${MONITOR_DISPOSITION_SCHEMA}`,
    );
  }
  requireExactKeys(disposition, "monitor disposition", [
    "schema_version",
    "disposition_id",
    "disposed_at",
    "target_repo",
    "proposal_ref",
    "proposal_id",
    "event_ids",
    "thread_ids",
    "classification",
    "rationale",
    "repair_dispatched",
    "source_changed",
    "future_evidence_reopens",
    "status",
  ]);
  requireText(
    disposition.disposition_id,
    "monitor disposition.disposition_id",
    128,
  );
  if (!/^monitor-disposition-[0-9a-f]{24}$/.test(disposition.disposition_id)) {
    fail("monitor disposition.disposition_id has an invalid format");
  }
  requireText(
    disposition.disposed_at,
    "monitor disposition.disposed_at",
    64,
  );
  if (Number.isNaN(Date.parse(disposition.disposed_at))) {
    fail("monitor disposition.disposed_at is not an ISO date");
  }
  requireText(
    disposition.target_repo,
    "monitor disposition.target_repo",
    4096,
  );
  if (!path.isAbsolute(disposition.target_repo)) {
    fail("monitor disposition.target_repo must be absolute");
  }
  if (
    expectedRoot &&
    fs.realpathSync(disposition.target_repo) !== expectedRoot
  ) {
    fail("monitor disposition.target_repo does not match the resolved repository");
  }
  requireImprovementArtifactRef(
    disposition.proposal_ref,
    "monitor disposition.proposal_ref",
  );
  requireText(
    disposition.proposal_id,
    "monitor disposition.proposal_id",
    128,
  );
  requireStringArray(
    disposition.event_ids,
    "monitor disposition.event_ids",
    { min: 1, itemMax: 128 },
  );
  requireStringArray(
    disposition.thread_ids,
    "monitor disposition.thread_ids",
    { min: 1, itemMax: 64 },
  );
  disposition.thread_ids.forEach((threadId, index) =>
    requireThreadId(
      threadId,
      `monitor disposition.thread_ids[${index}]`,
    ),
  );
  if (disposition.classification !== "monitor") {
    fail("monitor disposition.classification must be monitor");
  }
  requireStringArray(
    disposition.rationale,
    "monitor disposition.rationale",
    { min: 1, max: 16, itemMax: 256 },
  );
  if (disposition.repair_dispatched !== false) {
    fail("monitor disposition.repair_dispatched must be false");
  }
  if (disposition.source_changed !== false) {
    fail("monitor disposition.source_changed must be false");
  }
  if (disposition.future_evidence_reopens !== true) {
    fail("monitor disposition.future_evidence_reopens must be true");
  }
  if (disposition.status !== "closed_without_repair") {
    fail("monitor disposition.status must be closed_without_repair");
  }
  assertNoLikelySecret(disposition, "monitor disposition");
  assertJsonSize(
    disposition,
    "monitor disposition",
    MAX_MONITOR_DISPOSITION_BYTES,
  );
  return true;
}

function validateRetirementDisposition(disposition, expectedRoot = undefined) {
  if (disposition.schema_version !== RETIREMENT_DISPOSITION_SCHEMA) {
    fail(
      `retirement disposition.schema_version must be ${RETIREMENT_DISPOSITION_SCHEMA}`,
    );
  }
  requireExactKeys(disposition, "retirement disposition", [
    "schema_version",
    "disposition_id",
    "retired_at",
    "target_repo",
    "capability_id",
    "event_ids",
    "thread_ids",
    "reason",
    "replacement",
    "authority",
    "repair_dispatched",
    "source_changed",
    "status",
  ]);
  requireText(
    disposition.disposition_id,
    "retirement disposition.disposition_id",
    128,
  );
  if (
    !/^retirement-disposition-[0-9a-f]{24}$/.test(
      disposition.disposition_id,
    )
  ) {
    fail("retirement disposition.disposition_id has an invalid format");
  }
  requireIsoTimestamp(
    disposition.retired_at,
    "retirement disposition.retired_at",
  );
  requireText(
    disposition.target_repo,
    "retirement disposition.target_repo",
    4096,
  );
  if (!path.isAbsolute(disposition.target_repo)) {
    fail("retirement disposition.target_repo must be absolute");
  }
  if (
    expectedRoot &&
    fs.realpathSync(disposition.target_repo) !== expectedRoot
  ) {
    fail(
      "retirement disposition.target_repo does not match the resolved repository",
    );
  }
  requireText(
    disposition.capability_id,
    "retirement disposition.capability_id",
    256,
  );
  requireStringArray(
    disposition.event_ids,
    "retirement disposition.event_ids",
    { min: 1, itemMax: 128 },
  );
  disposition.event_ids.forEach((eventId) => {
    if (!EVENT_ID_PATTERN.test(eventId)) {
      fail("retirement disposition.event_ids contains an invalid event ID");
    }
  });
  requireStringArray(
    disposition.thread_ids,
    "retirement disposition.thread_ids",
    { min: 1, itemMax: 64 },
  );
  disposition.thread_ids.forEach((threadId, index) =>
    requireThreadId(
      threadId,
      `retirement disposition.thread_ids[${index}]`,
    ),
  );
  requireText(disposition.reason, "retirement disposition.reason", 4000);
  requireText(
    disposition.replacement,
    "retirement disposition.replacement",
    256,
    { nullable: true },
  );
  if (disposition.authority !== "explicit_user_request") {
    fail(
      "retirement disposition.authority must be explicit_user_request",
    );
  }
  if (disposition.repair_dispatched !== false) {
    fail("retirement disposition.repair_dispatched must be false");
  }
  if (disposition.source_changed !== false) {
    fail("retirement disposition.source_changed must be false");
  }
  if (disposition.status !== "closed_due_to_capability_retirement") {
    fail(
      "retirement disposition.status must be closed_due_to_capability_retirement",
    );
  }
  assertNoLikelySecret(disposition, "retirement disposition");
  assertJsonSize(
    disposition,
    "retirement disposition",
    MAX_RETIREMENT_DISPOSITION_BYTES,
  );
  return true;
}

function validateResolutionLinks(root, documents, resolutionRecord) {
  const resolution = resolutionRecord.document;
  const proposalRecord = documents.find(
    (record) =>
      record.document.proposal_id === resolution.proposal_id &&
      (record.document.schema_version === PLAN_SCHEMA ||
        record.document.schema_version === LEGACY_PLAN_SCHEMA),
  );
  if (!proposalRecord) {
    fail(`Resolution proposal is missing: ${resolution.proposal_id}`);
  }
  const expectedProposalRef =
    `artifact:${path.posix.join(
      ".capability-improvements",
      proposalRecord.filename,
    )}`;
  if (resolution.proposal_ref !== expectedProposalRef) {
    fail(`Resolution proposal_ref does not match ${resolution.proposal_id}`);
  }
  if (!sameStringSet(resolution.event_ids, proposalRecord.document.event_ids)) {
    fail(`Resolution event_ids do not match ${resolution.proposal_id}`);
  }
  const proposalThreadIds =
    proposalRecord.document.schema_version === PLAN_SCHEMA
      ? proposalRecord.document.thread_ids
      : [];
  if (!sameStringSet(resolution.thread_ids, proposalThreadIds)) {
    fail(`Resolution thread_ids do not match ${resolution.proposal_id}`);
  }
  for (const eventId of resolution.event_ids) {
    const eventRecord = documents.find(
      (record) =>
        record.document.event_id === eventId &&
        (record.document.schema_version === EVENT_SCHEMA ||
          record.document.schema_version === LEGACY_EVENT_SCHEMA),
    );
    if (!eventRecord) {
      fail(`Resolution event is missing: ${eventId}`);
    }
  }
  return true;
}

function validateAppStateResolutionLinks(root, documents, resolutionRecord) {
  const resolution = resolutionRecord.document;
  const proposalRecord = documents.find(
    (record) =>
      record.document.proposal_id === resolution.proposal_id &&
      record.document.schema_version === PLAN_SCHEMA,
  );
  if (!proposalRecord) {
    fail(`App state resolution proposal is missing: ${resolution.proposal_id}`);
  }
  const proposal = proposalRecord.document;
  const expectedProposalRef =
    `artifact:${path.posix.join(
      ".capability-improvements",
      proposalRecord.filename,
    )}`;
  if (resolution.proposal_ref !== expectedProposalRef) {
    fail(
      `App state resolution proposal_ref does not match ${resolution.proposal_id}`,
    );
  }
  if (
    proposal.classification !== "repair_candidate" ||
    proposal.handoff_ready !== true
  ) {
    fail(
      "App state resolution requires a handoff-ready repair_candidate proposal",
    );
  }
  if (
    proposal.capability.kinds.length === 0 ||
    !proposal.capability.kinds.every((kind) =>
      ["workflow", "app"].includes(kind),
    )
  ) {
    fail("App state resolution proposal kind must be workflow or app");
  }
  if (
    proposal.candidate_files.length !== 1 ||
    proposal.candidate_files[0] !== resolution.state.path
  ) {
    fail(
      "App state resolution proposal candidate_files must exactly match the state path",
    );
  }
  if (!sameStringSet(resolution.event_ids, proposal.event_ids)) {
    fail(
      `App state resolution event_ids do not match ${resolution.proposal_id}`,
    );
  }
  if (!sameStringSet(resolution.thread_ids, proposal.thread_ids)) {
    fail(
      `App state resolution thread_ids do not match ${resolution.proposal_id}`,
    );
  }
  if (
    Date.parse(resolution.state.observed_at) <
    Date.parse(proposal.created_at)
  ) {
    fail("App state resolution observation predates the proposal");
  }
  for (const eventId of resolution.event_ids) {
    const eventRecord = documents.find(
      (record) =>
        record.document.event_id === eventId &&
        (record.document.schema_version === EVENT_SCHEMA ||
          record.document.schema_version === LEGACY_EVENT_SCHEMA),
    );
    if (!eventRecord) {
      fail(`App state resolution event is missing: ${eventId}`);
    }
  }
  return true;
}

function validateMonitorDispositionLinks(root, documents, dispositionRecord) {
  const disposition = dispositionRecord.document;
  const proposalRecord = documents.find(
    (record) =>
      record.document.proposal_id === disposition.proposal_id &&
      record.document.schema_version === PLAN_SCHEMA,
  );
  if (!proposalRecord) {
    fail(`Monitor disposition proposal is missing: ${disposition.proposal_id}`);
  }
  const proposal = proposalRecord.document;
  const expectedProposalRef =
    `artifact:${path.posix.join(
      ".capability-improvements",
      proposalRecord.filename,
    )}`;
  if (disposition.proposal_ref !== expectedProposalRef) {
    fail(
      `Monitor disposition proposal_ref does not match ${disposition.proposal_id}`,
    );
  }
  if (
    proposal.classification !== "monitor" ||
    proposal.handoff_ready !== false
  ) {
    fail("Monitor disposition requires a non-handoff monitor proposal");
  }
  if (!sameStringSet(disposition.event_ids, proposal.event_ids)) {
    fail(`Monitor disposition event_ids do not match ${disposition.proposal_id}`);
  }
  if (!sameStringSet(disposition.thread_ids, proposal.thread_ids)) {
    fail(`Monitor disposition thread_ids do not match ${disposition.proposal_id}`);
  }
  for (const eventId of disposition.event_ids) {
    const eventRecord = documents.find(
      (record) =>
        record.document.event_id === eventId &&
        (record.document.schema_version === EVENT_SCHEMA ||
          record.document.schema_version === LEGACY_EVENT_SCHEMA),
    );
    if (!eventRecord) {
      fail(`Monitor disposition event is missing: ${eventId}`);
    }
  }
  return true;
}

function validateRetirementDispositionLinks(
  root,
  documents,
  dispositionRecord,
) {
  const disposition = dispositionRecord.document;
  const linkedEvents = [];
  for (const eventId of disposition.event_ids) {
    const eventRecord = documents.find(
      (record) =>
        record.document.event_id === eventId &&
        (record.document.schema_version === EVENT_SCHEMA ||
          record.document.schema_version === LEGACY_EVENT_SCHEMA),
    );
    if (!eventRecord) {
      fail(`Retirement disposition event is missing: ${eventId}`);
    }
    if (eventRecord.document.capability.id !== disposition.capability_id) {
      fail(
        `Retirement disposition capability does not match event ${eventId}`,
      );
    }
    if (
      Date.parse(disposition.retired_at) <
      Date.parse(eventRecord.document.recorded_at)
    ) {
      fail(`Retirement disposition predates event ${eventId}`);
    }
    linkedEvents.push(eventRecord.document);
  }
  if (
    !sameStringSet(
      disposition.thread_ids,
      linkedEvents.map((event) => eventThreadId(event)),
    )
  ) {
    fail("Retirement disposition thread_ids do not match its events");
  }

  const conflictingTerminalRecords = documents.filter((record) => {
    if (record === dispositionRecord) return false;
    if (
      ![
        RESOLUTION_SCHEMA,
        APP_STATE_RESOLUTION_SCHEMA,
        MONITOR_DISPOSITION_SCHEMA,
        RETIREMENT_DISPOSITION_SCHEMA,
      ].includes(record.document.schema_version)
    ) {
      return false;
    }
    return record.document.event_ids.some((eventId) =>
      disposition.event_ids.includes(eventId),
    );
  });
  if (conflictingTerminalRecords.length > 0) {
    fail("Retirement disposition overlaps existing terminal coverage", {
      disposition_id: disposition.disposition_id,
      conflicting_artifacts: conflictingTerminalRecords.map(
        (record) => record.filename,
      ),
    });
  }
  return true;
}

function improvementsPath(root) {
  return path.join(root, IMPROVEMENTS_DIR);
}

function loadDocuments(root) {
  const directory = improvementsPath(root);
  if (!fs.existsSync(directory)) {
    return [];
  }
  const entries = fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .sort((left, right) => left.name.localeCompare(right.name));
  const documents = [];
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    const bytes = fs.readFileSync(absolutePath);
    if (bytes.length > MAX_IMPROVEMENT_DOCUMENT_BYTES) {
      fail(
        `Improvement document exceeds ${MAX_IMPROVEMENT_DOCUMENT_BYTES} bytes`,
        {
          path: absolutePath,
          bytes: bytes.length,
        },
      );
    }
    let document;
    try {
      document = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      fail(`Invalid JSON: ${absolutePath}`, { message: error.message });
    }
    if (
      document.schema_version === EVENT_SCHEMA ||
      document.schema_version === LEGACY_EVENT_SCHEMA
    ) {
      validateEvent(document, root);
    } else if (
      document.schema_version === PLAN_SCHEMA ||
      document.schema_version === LEGACY_PLAN_SCHEMA
    ) {
      validateProposal(document, root);
    } else if (document.schema_version === RESOLUTION_SCHEMA) {
      validateResolution(document, root);
    } else if (document.schema_version === APP_STATE_RESOLUTION_SCHEMA) {
      validateAppStateResolution(document, root);
    } else if (document.schema_version === MONITOR_DISPOSITION_SCHEMA) {
      validateMonitorDisposition(document, root);
    } else if (document.schema_version === RETIREMENT_DISPOSITION_SCHEMA) {
      validateRetirementDisposition(document, root);
    } else {
      fail(`Unknown improvement schema in: ${absolutePath}`);
    }
    documents.push({
      filename: entry.name,
      absolutePath,
      document,
    });
  }
  return documents;
}

function writeJsonCreateNew(absolutePath, document) {
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  const serialized = `${JSON.stringify(document, null, 2)}\n`;
  try {
    fs.writeFileSync(absolutePath, serialized, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  } catch (error) {
    if (error.code === "EEXIST") {
      fail(`Refusing to overwrite existing artifact: ${absolutePath}`);
    }
    throw error;
  }
}

function writeJsonIdempotent(absolutePath, document) {
  if (!fs.existsSync(absolutePath)) {
    writeJsonCreateNew(absolutePath, document);
    return "created";
  }
  const existing = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
  if (JSON.stringify(existing) !== JSON.stringify(document)) {
    fail(`Existing artifact differs from deterministic retry: ${absolutePath}`);
  }
  return "existing";
}

function commandSchema() {
  return {
    event_schema: EVENT_SCHEMA,
    repair_plan_schema: PLAN_SCHEMA,
    resolution_schema: RESOLUTION_SCHEMA,
    app_state_resolution_schema: APP_STATE_RESOLUTION_SCHEMA,
    monitor_disposition_schema: MONITOR_DISPOSITION_SCHEMA,
    retirement_disposition_schema: RETIREMENT_DISPOSITION_SCHEMA,
    legacy_event_schema: LEGACY_EVENT_SCHEMA,
    legacy_repair_plan_schema: LEGACY_PLAN_SCHEMA,
    storage: "{affected-git-root}/.capability-improvements/*.json",
    session_flag: SESSION_FLAG,
    central_index:
      "{$CODEX_HOME:-~/.codex}/capability-friction-index/{pending|processing}/<thread-id>",
    central_index_payload: "zero-byte marker; the filename is the only durable value",
    central_index_cleanup:
      "index-close deletes a thread marker only after the supplied artifacts exactly match every indexed event flag and every source-repo event is covered by a validated Git repair resolution, app-state repair resolution, monitor disposition, or explicit capability-retirement disposition",
    thread_flag_extraction:
      `thread-flags streams the one exact local rollout for a verified thread ID without a total-file cap, enforces a ${MAX_ROLLOUT_LINE_BYTES}-byte per-line cap, returns deduplicated fixed CAPABILITY_FRICTION_DETECTED blocks only, and never persists transcript content`,
    index_audit: {
      mode: "read_only",
      snapshot: "one finite pending/processing marker snapshot",
      classifications: [
        "close_ready",
        "repair_required",
        "monitor_required",
        "blocked",
      ],
      official_thread_read_required_before_action: true,
      side_effects:
        "Does not claim, release, close, or create markers; does not write proposals, dispatch workers, or persist transcript content.",
      repository_fault_isolation:
        "A failed source-repo group is reported as blocked without hiding independently valid groups in the same thread.",
      source_repo_groups:
        "Aggregates active groups and omits cohabiting repositories whose indexed events are all terminal and whose completion includes explicit capability-retirement coverage.",
    },
    retirement_disposition: {
      authority: "explicit_user_request",
      scope: "exact source-local events for one capability and repository",
      source_changed: false,
      repair_dispatched: false,
      marker_deleted: false,
    },
    create_new_only: true,
    passive_dispatch: false,
    app_state_resolution: {
      state_surface: APP_STATE_SURFACE,
      state_path: "automations/<resource-id>/automation.toml",
      source_control: {
        required: false,
        reason: APP_STATE_SOURCE_CONTROL_REASON,
      },
      operation:
        "Records an already-authorized successful codex_app.automation_update; the command never mutates app state.",
      live_state_validation:
        "Creation verifies a regular non-symlink ignored untracked file and its current after SHA-256. Later artifact validation checks immutable structure and links without rehashing mutable live state.",
    },
    git_resolution: {
      commit_modes: {
        head:
          "Default strict mode: the repair commit must equal the clean target repository HEAD.",
        ancestor:
          "Explicit delayed-reconciliation mode: the exact repair commit must be a strict ancestor of the clean verified HEAD, retain its exact changed-file set, and use current repair-execution evidence plus passed named-refresh evidence only when runtime reflection is in scope. Otherwise refresh status is not_applicable. It must not bind an unrelated HEAD or manufacture a cosmetic commit.",
        preexisting:
          "Explicit recovery mode for legacy evidence recorded only after its repair had already landed: the exact repair commit may equal or be an ancestor of the clean verified HEAD, while current verification and evidence-linked repair-execution proof remain mandatory. Require passed named-refresh evidence only when runtime reflection is in scope; otherwise use not_applicable. Do not use it for a normally ordered new event.",
      },
    },
    enums: ENUMS,
    typed_reference_forms: [
      "file:<path>",
      "path:<path>",
      "artifact:<path>",
      "packet:<id>",
      "collected-packet:<id>",
      "role:<id>",
      "collected-role:<id>",
      "command:<command> exit:<integer>",
      "test:<test> result:<pass|fail|integer>",
    ],
    triage: {
      monitor:
        "Default for insufficient evidence, including one low/medium one-off input-format anomaly.",
      repair_candidate:
        "High/critical severity, reproduced/repeated evidence, multiple events with one repeat key, or direct structural contract evidence.",
      handoff_ready:
        "repair_candidate with one capability id, candidate files, and verification references.",
      test_relaxation_for_single_anomaly: "forbidden",
    },
  };
}

function commandDoctor(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  const tracked = trackedCodingAgentsFiles(root);
  const documents = tracked.length === 0 ? loadDocuments(root) : [];
  return {
    ok: tracked.length === 0,
    target_repo: root,
    workflow_state_tracked: tracked.length > 0,
    tracked_files: tracked,
    exclude_entry_present: excludeHasEntry(root),
    improvements_directory_present: fs.existsSync(improvementsPath(root)),
    event_count: documents.filter(
      (record) =>
        record.document.schema_version === EVENT_SCHEMA ||
        record.document.schema_version === LEGACY_EVENT_SCHEMA,
    ).length,
    proposal_count: documents.filter(
      (record) =>
        record.document.schema_version === PLAN_SCHEMA ||
        record.document.schema_version === LEGACY_PLAN_SCHEMA,
    ).length,
    resolution_count: documents.filter(
      (record) => record.document.schema_version === RESOLUTION_SCHEMA,
    ).length,
    app_state_resolution_count: documents.filter(
      (record) =>
        record.document.schema_version === APP_STATE_RESOLUTION_SCHEMA,
    ).length,
    monitor_disposition_count: documents.filter(
      (record) =>
        record.document.schema_version === MONITOR_DISPOSITION_SCHEMA,
    ).length,
    retirement_disposition_count: documents.filter(
      (record) =>
        record.document.schema_version === RETIREMENT_DISPOSITION_SCHEMA,
    ).length,
    passive_dispatch: false,
  };
}

function commandValidate(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  for (const record of documents.filter(
    (candidate) => candidate.document.schema_version === RESOLUTION_SCHEMA,
  )) {
    validateResolutionLinks(root, documents, record);
  }
  for (const record of documents.filter(
    (candidate) =>
      candidate.document.schema_version === APP_STATE_RESOLUTION_SCHEMA,
  )) {
    validateAppStateResolutionLinks(root, documents, record);
  }
  for (const record of documents.filter(
    (candidate) =>
      candidate.document.schema_version === MONITOR_DISPOSITION_SCHEMA,
  )) {
    validateMonitorDispositionLinks(root, documents, record);
  }
  for (const record of documents.filter(
    (candidate) =>
      candidate.document.schema_version === RETIREMENT_DISPOSITION_SCHEMA,
  )) {
    validateRetirementDispositionLinks(root, documents, record);
  }
  return {
    ok: true,
    target_repo: root,
    validated: documents.length,
    event_count: documents.filter(
      (record) =>
        record.document.schema_version === EVENT_SCHEMA ||
        record.document.schema_version === LEGACY_EVENT_SCHEMA,
    ).length,
    proposal_count: documents.filter(
      (record) =>
        record.document.schema_version === PLAN_SCHEMA ||
        record.document.schema_version === LEGACY_PLAN_SCHEMA,
    ).length,
    resolution_count: documents.filter(
      (record) => record.document.schema_version === RESOLUTION_SCHEMA,
    ).length,
    app_state_resolution_count: documents.filter(
      (record) =>
        record.document.schema_version === APP_STATE_RESOLUTION_SCHEMA,
    ).length,
    monitor_disposition_count: documents.filter(
      (record) =>
        record.document.schema_version === MONITOR_DISPOSITION_SCHEMA,
    ).length,
    retirement_disposition_count: documents.filter(
      (record) =>
        record.document.schema_version === RETIREMENT_DISPOSITION_SCHEMA,
    ).length,
  };
}

function commandRecord(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const event = eventFromArgs(args, root);
  const filename = `${event.event_id}.json`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    filename,
  );
  const absolutePath = path.join(root, relativePath);

  const threadId = eventThreadId(event);
  const codexHome = resolveCodexHome(args["codex-home"]);
  let indexResult = {
    mode: args.execute ? "execute" : "dry_run",
    thread_id: threadId,
    pending_marker: indexPaths(codexHome, threadId).pending,
    state: "planned",
  };
  if (args.execute) {
    indexResult = withIndexLock(codexHome, threadId, (paths) => {
      ensureExcludeEntry(root);
      writeJsonCreateNew(absolutePath, event);
      try {
        const marker = createMarker(paths.pending);
        return {
          mode: "execute",
          thread_id: threadId,
          pending_marker: paths.pending,
          state: marker,
        };
      } catch (error) {
        if (fs.existsSync(absolutePath)) {
          fs.unlinkSync(absolutePath);
        }
        throw error;
      }
    });
  }
  const artifactRef = `artifact:${relativePath}`;
  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    artifact_ref: artifactRef,
    artifact_path: absolutePath,
    event,
    session_flag: formatSessionFlag(event, artifactRef),
    central_index: indexResult,
    dispatched: false,
  };
}

function analyzeTerminalState(root, documents) {
  const events = documents.filter(
    (record) =>
      record.document.schema_version === EVENT_SCHEMA ||
      record.document.schema_version === LEGACY_EVENT_SCHEMA,
  );
  const resolutionRecords = documents.filter(
    (record) => record.document.schema_version === RESOLUTION_SCHEMA,
  );
  for (const record of resolutionRecords) {
    validateResolutionLinks(root, documents, record);
  }
  const appStateResolutionRecords = documents.filter(
    (record) =>
      record.document.schema_version === APP_STATE_RESOLUTION_SCHEMA,
  );
  for (const record of appStateResolutionRecords) {
    validateAppStateResolutionLinks(root, documents, record);
  }
  const resolvedEventIds = new Set(
    [...resolutionRecords, ...appStateResolutionRecords].flatMap(
      (record) => record.document.event_ids,
    ),
  );
  const monitorDispositionRecords = documents.filter(
    (record) =>
      record.document.schema_version === MONITOR_DISPOSITION_SCHEMA,
  );
  for (const record of monitorDispositionRecords) {
    validateMonitorDispositionLinks(root, documents, record);
  }
  const monitoredEventIds = new Set(
    monitorDispositionRecords.flatMap(
      (record) => record.document.event_ids,
    ),
  );
  const retirementDispositionRecords = documents.filter(
    (record) =>
      record.document.schema_version === RETIREMENT_DISPOSITION_SCHEMA,
  );
  for (const record of retirementDispositionRecords) {
    validateRetirementDispositionLinks(root, documents, record);
  }
  const retiredEventIds = new Set(
    retirementDispositionRecords.flatMap(
      (record) => record.document.event_ids,
    ),
  );
  const openEvents = events.filter(
    (record) =>
      !resolvedEventIds.has(record.document.event_id) &&
      !monitoredEventIds.has(record.document.event_id) &&
      !retiredEventIds.has(record.document.event_id),
  );
  return {
    events,
    resolvedEventIds,
    monitoredEventIds,
    retiredEventIds,
    openEvents,
  };
}

function proposalPlansForOpenEvents(root, terminalState, seedOpenEvents) {
  const openRepeatKeys = new Set(
    seedOpenEvents.map((record) => record.document.repeat_key),
  );
  const triageEvents = terminalState.events.filter(
    (record) =>
      !terminalState.resolvedEventIds.has(record.document.event_id) &&
      !terminalState.retiredEventIds.has(record.document.event_id) &&
      openRepeatKeys.has(record.document.repeat_key),
  );
  const groups = new Map();
  for (const record of triageEvents) {
    const key = record.document.repeat_key;
    groups.set(key, [...(groups.get(key) ?? []), record]);
  }
  return [...groups.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([repeatKey, records]) => proposalFromGroup(root, repeatKey, records));
}

function commandTriage(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  const terminalState = analyzeTerminalState(root, documents);
  if (terminalState.events.length === 0) {
    fail("No validated improvement evidence events were found");
  }
  if (terminalState.openEvents.length === 0) {
    return {
      ok: true,
      mode: args.execute ? "execute" : "dry_run",
      target_repo: root,
      proposals: [],
      all_resolved: terminalState.events.every((record) =>
        terminalState.resolvedEventIds.has(record.document.event_id),
      ),
      all_terminal: true,
      dispatched: false,
    };
  }

  const plans = proposalPlansForOpenEvents(
    root,
    terminalState,
    terminalState.openEvents,
  );

  if (args.execute) {
    ensureExcludeEntry(root);
    for (const plan of plans) {
      writeJsonIdempotent(
        path.join(root, plan.relativePath),
        plan.proposal,
      );
    }
  }

  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    proposals: plans.map(({ proposal, relativePath }) => ({
      artifact_ref: `artifact:${relativePath}`,
      ...proposal,
    })),
    dispatched: false,
  };
}

function commandMonitorDispose(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  const proposalRecord = loadImprovementArtifact(
    root,
    args["proposal-ref"],
    [PLAN_SCHEMA],
  );
  const proposal = proposalRecord.document;
  if (
    proposal.classification !== "monitor" ||
    proposal.handoff_ready !== false
  ) {
    fail("monitor-dispose requires a non-handoff monitor proposal");
  }
  for (const eventId of proposal.event_ids) {
    if (
      !documents.some(
        (record) =>
          record.document.event_id === eventId &&
          (record.document.schema_version === EVENT_SCHEMA ||
            record.document.schema_version === LEGACY_EVENT_SCHEMA),
      )
    ) {
      fail(`Proposal event is missing: ${eventId}`);
    }
  }
  const dispositionId =
    `monitor-disposition-${stableHash({
      proposal_id: proposal.proposal_id,
      classification: proposal.classification,
    }).slice(0, 24)}`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    `${dispositionId}.json`,
  );
  const disposition = {
    schema_version: MONITOR_DISPOSITION_SCHEMA,
    disposition_id: dispositionId,
    disposed_at: proposal.created_at,
    target_repo: root,
    proposal_ref: proposalRecord.artifactRef,
    proposal_id: proposal.proposal_id,
    event_ids: sortedUnique(proposal.event_ids),
    thread_ids: sortedUnique(proposal.thread_ids),
    classification: "monitor",
    rationale: sortedUnique(proposal.rationale),
    repair_dispatched: false,
    source_changed: false,
    future_evidence_reopens: true,
    status: "closed_without_repair",
  };
  validateMonitorDisposition(disposition, root);
  const absolutePath = path.join(root, relativePath);
  let writeState = "planned";
  if (args.execute) {
    ensureExcludeEntry(root);
    writeState = writeJsonIdempotent(absolutePath, disposition);
  }
  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    artifact_ref: `artifact:${relativePath}`,
    artifact_path: absolutePath,
    write_state: writeState,
    disposition,
    marker_deleted: false,
    repair_dispatched: false,
  };
}

function loadRetirementEventArtifact(root, absolutePath) {
  requireText(absolutePath, "event-artifact", 4096);
  if (!path.isAbsolute(absolutePath)) {
    fail("--event-artifact must be an absolute path");
  }
  if (!fs.existsSync(absolutePath) || !fs.lstatSync(absolutePath).isFile()) {
    fail(`Event artifact must be a regular file: ${absolutePath}`);
  }
  const realArtifact = fs.realpathSync(absolutePath);
  const eventRoot = resolveGitRoot(path.dirname(realArtifact));
  if (eventRoot !== root) {
    fail("Event artifact does not belong to --target-cwd", {
      target_repo: root,
      event_artifact: realArtifact,
      event_source_repo: eventRoot,
    });
  }
  const expectedDirectory = fs.realpathSync(improvementsPath(root));
  if (path.dirname(realArtifact) !== expectedDirectory) {
    fail(
      `Event artifact is outside the source repo improvements directory: ${absolutePath}`,
    );
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(realArtifact, "utf8"));
  } catch (error) {
    fail(`Invalid JSON: ${realArtifact}`, { message: error.message });
  }
  if (
    document.schema_version !== EVENT_SCHEMA &&
    document.schema_version !== LEGACY_EVENT_SCHEMA
  ) {
    fail(`Not a capability improvement event: ${realArtifact}`);
  }
  validateEvent(document, root);
  return {
    filename: path.basename(realArtifact),
    absolutePath: realArtifact,
    eventId: document.event_id,
    document,
  };
}

function commandRetireDispose(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  requireText(args["capability-id"], "capability-id", 256);
  requireText(args.reason, "reason", 4000);
  const replacement = args.replacement ?? null;
  requireText(replacement, "replacement", 256, { nullable: true });
  requireStringArray(args["event-artifact"], "event-artifact", {
    min: 1,
    max: null,
    itemMax: 4096,
  });
  const eventRecords = args["event-artifact"].map((absolutePath) =>
    loadRetirementEventArtifact(root, absolutePath),
  );
  const eventIds = sortedUnique(
    eventRecords.map((record) => record.eventId),
  );
  if (eventIds.length !== eventRecords.length) {
    fail("--event-artifact contains duplicate events");
  }
  for (const record of eventRecords) {
    if (record.document.capability.id !== args["capability-id"]) {
      fail(
        `Event ${record.eventId} does not belong to capability ${args["capability-id"]}`,
      );
    }
  }
  const threadIds = sortedUnique(
    eventRecords.map((record) => eventThreadId(record.document)),
  );
  const dispositionId =
    `retirement-disposition-${stableHash({
      target_repo: root,
      capability_id: args["capability-id"],
      event_ids: eventIds,
    }).slice(0, 24)}`;
  const filename = `${dispositionId}.json`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    filename,
  );
  const absolutePath = path.join(root, relativePath);
  const documents = loadDocuments(root);
  const existingRecord = documents.find(
    (record) => record.filename === filename,
  );
  if (existingRecord) {
    if (existingRecord.document.schema_version !== RETIREMENT_DISPOSITION_SCHEMA) {
      fail(`Existing retirement artifact has another schema: ${absolutePath}`);
    }
    validateRetirementDispositionLinks(root, documents, existingRecord);
    const existing = existingRecord.document;
    if (
      existing.target_repo !== root ||
      existing.capability_id !== args["capability-id"] ||
      !sameStringSet(existing.event_ids, eventIds) ||
      !sameStringSet(existing.thread_ids, threadIds) ||
      existing.reason !== args.reason ||
      existing.replacement !== replacement
    ) {
      fail(`Existing retirement disposition differs: ${absolutePath}`);
    }
    return {
      ok: true,
      mode: args.execute ? "execute" : "dry_run",
      target_repo: root,
      artifact_ref: `artifact:${relativePath}`,
      artifact_path: absolutePath,
      write_state: "existing",
      disposition: existing,
      marker_deleted: false,
      repair_dispatched: false,
    };
  }
  if (fs.existsSync(absolutePath)) {
    fail(`Retirement artifact is not a validated document: ${absolutePath}`);
  }

  const terminalState = analyzeTerminalState(root, documents);
  const alreadyTerminal = eventIds.filter(
    (eventId) =>
      terminalState.resolvedEventIds.has(eventId) ||
      terminalState.monitoredEventIds.has(eventId) ||
      terminalState.retiredEventIds.has(eventId),
  );
  if (alreadyTerminal.length > 0) {
    fail("Retirement events already have terminal coverage", {
      event_ids: alreadyTerminal,
    });
  }
  const disposition = {
    schema_version: RETIREMENT_DISPOSITION_SCHEMA,
    disposition_id: dispositionId,
    retired_at: isoTimestamp(),
    target_repo: root,
    capability_id: args["capability-id"],
    event_ids: eventIds,
    thread_ids: threadIds,
    reason: args.reason,
    replacement,
    authority: "explicit_user_request",
    repair_dispatched: false,
    source_changed: false,
    status: "closed_due_to_capability_retirement",
  };
  validateRetirementDisposition(disposition, root);
  const dispositionRecord = {
    filename,
    absolutePath,
    document: disposition,
  };
  validateRetirementDispositionLinks(
    root,
    [...documents, dispositionRecord],
    dispositionRecord,
  );
  let writeState = "planned";
  if (args.execute) {
    ensureExcludeEntry(root);
    writeJsonCreateNew(absolutePath, disposition);
    writeState = "created";
  }
  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    artifact_ref: `artifact:${relativePath}`,
    artifact_path: absolutePath,
    write_state: writeState,
    disposition,
    marker_deleted: false,
    repair_dispatched: false,
  };
}

function commandHandoffCheck(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const proposalRecord = loadImprovementArtifact(
    root,
    args["proposal-ref"],
    [PLAN_SCHEMA],
  );
  const proposal = proposalRecord.document;
  if (
    proposal.classification !== "repair_candidate" ||
    proposal.handoff_ready !== true
  ) {
    fail("repair handoff requires a handoff-ready repair_candidate");
  }
  const repairExecution = repairExecutionFromArgs(args);
  return {
    ok: true,
    target_repo: root,
    proposal_ref: proposalRecord.artifactRef,
    handoff_ready: true,
    repair_handoff: {
      ...proposal.repair_handoff,
      route: repairExecution.route,
      authority_ref: repairExecution.authority_ref,
      coding_agent_orchestrator_explicit_only: true,
      coding_agent_orchestrator_gui_only: true,
    },
    dispatched: false,
  };
}

function commandResolve(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  const proposalRecord = loadImprovementArtifact(
    root,
    args["proposal-ref"],
    [PLAN_SCHEMA],
  );
  const proposal = proposalRecord.document;
  if (
    proposal.classification !== "repair_candidate" ||
    proposal.handoff_ready !== true
  ) {
    fail("resolve requires a handoff-ready repair_candidate");
  }
  for (const eventId of proposal.event_ids) {
    if (
      !documents.some(
        (record) =>
          record.document.event_id === eventId &&
          (record.document.schema_version === EVENT_SCHEMA ||
            record.document.schema_version === LEGACY_EVENT_SCHEMA),
      )
    ) {
      fail(`Proposal event is missing: ${eventId}`);
    }
  }

  requireText(args["root-cause"], "root-cause", 4000);
  requireText(args.commit, "commit", 64);
  if (!/^[0-9a-f]{40}$/.test(args.commit)) {
    fail("--commit must be a full lowercase Git SHA");
  }
  const head = runGit(root, ["rev-parse", "HEAD"]).stdout.trim();
  const commitMode = args["commit-mode"] ?? "head";
  requireEnum(commitMode, "commit-mode", ["head", "ancestor", "preexisting"]);
  if (commitMode === "head" && head !== args.commit) {
    fail(
      "--commit must equal the target repository HEAD unless --commit-mode ancestor is explicit",
      {
        expected: head,
        actual: args.commit,
      },
    );
  }
  if (commitMode === "ancestor") {
    if (head === args.commit) {
      fail("--commit-mode ancestor requires a repair commit older than HEAD");
    }
    const commitExists = runGit(
      root,
      ["cat-file", "-e", `${args.commit}^{commit}`],
      { allowFailure: true },
    );
    if (commitExists.status !== 0) {
      fail("--commit-mode ancestor requires an existing repair commit");
    }
    const ancestry = runGit(
      root,
      ["merge-base", "--is-ancestor", args.commit, head],
      { allowFailure: true },
    );
    if (ancestry.status !== 0) {
      fail("--commit-mode ancestor requires the repair commit to be an ancestor of HEAD");
    }
  }
  if (commitMode === "preexisting") {
    const commitExists = runGit(
      root,
      ["cat-file", "-e", `${args.commit}^{commit}`],
      { allowFailure: true },
    );
    if (commitExists.status !== 0) {
      fail("--commit-mode preexisting requires an existing repair commit");
    }
    if (head !== args.commit) {
      const ancestry = runGit(
        root,
        ["merge-base", "--is-ancestor", args.commit, head],
        { allowFailure: true },
      );
      if (ancestry.status !== 0) {
        fail(
          "--commit-mode preexisting requires the repair commit to equal or be an ancestor of HEAD",
        );
      }
    }
    const proposalEvents = documents
      .filter(
        (record) =>
          proposal.event_ids.includes(record.document.event_id) &&
          (record.document.schema_version === EVENT_SCHEMA ||
            record.document.schema_version === LEGACY_EVENT_SCHEMA),
      )
      .map((record) => record.document);
    if (
      proposalEvents.length !== proposal.event_ids.length ||
      proposalEvents.some(
        (event) =>
          typeof event.incident?.root_cause !== "string" ||
          event.incident.root_cause.trim().length === 0,
      )
    ) {
      fail(
        "--commit-mode preexisting requires every covered event to record a root cause",
      );
    }
  }
  const trackedStatus = runGit(root, [
    "status",
    "--short",
    "--untracked-files=no",
  ]).stdout.trim();
  if (trackedStatus) {
    fail("resolve requires a clean tracked worktree after the repair commit", {
      status: trackedStatus,
    });
  }

  const committedFiles = runGit(root, [
    "diff-tree",
    "--root",
    "--no-commit-id",
    "--name-only",
    "-r",
    args.commit,
  ]).stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const changedFiles = args["changed-file"] ?? [];
  requireStringArray(changedFiles, "changed-file", {
    min: 1,
    max: committedFiles.length,
    itemMax: 1024,
  });
  changedFiles.forEach((filename, index) =>
    requireRepoRelativePath(filename, `changed-file[${index}]`),
  );
  if (!sameStringSet(changedFiles, committedFiles)) {
    fail("--changed-file must exactly match the repair commit file set", {
      declared: sortedUnique(changedFiles),
      committed: sortedUnique(committedFiles),
    });
  }
  if (committedFiles.some((filename) => filename.startsWith(".capability-improvements/"))) {
    fail("The repair commit must not contain .capability-improvements workflow state");
  }

  const verificationRefs = args.verification ?? [];
  requireTypedReferences(verificationRefs, "verification", { min: 1 });
  requireEnum(args["refresh-status"], "refresh-status", [
    "passed",
    "not_applicable",
  ]);
  let refreshEvidence = null;
  if (args["refresh-status"] === "passed") {
    requireTypedReferences(
      [args["refresh-evidence"]],
      "refresh-evidence",
      { min: 1, max: 1 },
    );
    refreshEvidence = args["refresh-evidence"];
  } else if (args["refresh-evidence"] !== undefined) {
    fail("--refresh-evidence is allowed only with --refresh-status passed");
  }

  const repairExecution = repairExecutionFromArgs(args, {
    requireEvidence: true,
  });
  const repairCommittedAt = runGit(root, [
    "show",
    "-s",
    "--format=%cI",
    args.commit,
  ]).stdout.trim();
  if (
    commitMode !== "preexisting" &&
    Date.parse(repairCommittedAt) + 1000 < Date.parse(proposal.created_at)
  ) {
    fail("Repair commit predates the improvement proposal");
  }
  const verifiedHeadCommittedAt = runGit(root, [
    "show",
    "-s",
    "--format=%cI",
    head,
  ]).stdout.trim();
  const resolvedAt =
    commitMode === "preexisting" &&
    Date.parse(verifiedHeadCommittedAt) < Date.parse(proposal.created_at)
      ? proposal.created_at
      : verifiedHeadCommittedAt;
  const resolutionId =
    `resolution-${stableHash({
      proposal_id: proposal.proposal_id,
      commit: args.commit,
      commit_mode: commitMode,
      verified_head: head,
      execution_route: repairExecution.route,
      execution_id: repairExecution.execution_id,
    }).slice(0, 24)}`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    `${resolutionId}.json`,
  );
  const resolution = {
    schema_version: RESOLUTION_SCHEMA,
    resolution_id: resolutionId,
    resolved_at: resolvedAt,
    target_repo: root,
    proposal_ref: proposalRecord.artifactRef,
    proposal_id: proposal.proposal_id,
    event_ids: sortedUnique(proposal.event_ids),
    thread_ids: sortedUnique(proposal.thread_ids),
    root_cause: args["root-cause"],
    changed_files: sortedUnique(changedFiles),
    verification_refs: sortedUnique(verificationRefs),
    repair_execution: repairExecution,
    source_control: {
      commit: args.commit,
      commit_mode: commitMode,
      head_verified: true,
      verified_head: head,
    },
    refresh: {
      status: args["refresh-status"],
      evidence_ref: refreshEvidence,
    },
    status: "closed",
  };
  validateResolution(resolution, root);
  const absolutePath = path.join(root, relativePath);
  let writeState = "planned";
  if (args.execute) {
    ensureExcludeEntry(root);
    writeState = writeJsonIdempotent(absolutePath, resolution);
  }
  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    artifact_ref: `artifact:${relativePath}`,
    artifact_path: absolutePath,
    write_state: writeState,
    resolution,
    marker_deleted: false,
  };
}

function commandAppStateResolve(args) {
  const root = resolveGitRoot(args["target-cwd"]);
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  const proposalRecord = loadImprovementArtifact(
    root,
    args["proposal-ref"],
    [PLAN_SCHEMA],
  );
  const proposal = proposalRecord.document;
  if (
    proposal.classification !== "repair_candidate" ||
    proposal.handoff_ready !== true
  ) {
    fail("app-state-resolve requires a handoff-ready repair_candidate");
  }
  if (
    proposal.capability.kinds.length === 0 ||
    !proposal.capability.kinds.every((kind) =>
      ["workflow", "app"].includes(kind),
    )
  ) {
    fail("app-state-resolve requires a workflow or app capability kind");
  }
  for (const eventId of proposal.event_ids) {
    if (
      !documents.some(
        (record) =>
          record.document.event_id === eventId &&
          (record.document.schema_version === EVENT_SCHEMA ||
            record.document.schema_version === LEGACY_EVENT_SCHEMA),
      )
    ) {
      fail(`Proposal event is missing: ${eventId}`);
    }
  }

  requireText(args["root-cause"], "root-cause", 4000);
  if (args["state-surface"] !== APP_STATE_SURFACE) {
    fail(`--state-surface must be ${APP_STATE_SURFACE}`);
  }
  const resourceId = requireAutomationResourceId(
    args["resource-id"],
    "resource-id",
  );
  const statePath = requireAutomationStatePath(
    args["state-path"],
    resourceId,
    "state-path",
  );
  if (
    proposal.candidate_files.length !== 1 ||
    proposal.candidate_files[0] !== statePath
  ) {
    fail(
      "Proposal candidate_files must contain exactly the declared app state path",
      {
        declared: statePath,
        proposal_candidate_files: proposal.candidate_files,
      },
    );
  }

  const absoluteStatePath = resolveRegularNonSymlinkRepoPath(
    root,
    statePath,
    "app-managed state path",
  );
  assertGitIgnoredUntracked(root, statePath);

  const observedAt = requireIsoTimestamp(args["observed-at"], "observed-at");
  if (Date.parse(observedAt) < Date.parse(proposal.created_at)) {
    fail("--observed-at must not predate the improvement proposal");
  }
  const beforeSha256 = requireSha256(
    args["before-sha256"],
    "before-sha256",
  );
  const afterSha256 = requireSha256(
    args["after-sha256"],
    "after-sha256",
  );
  if (beforeSha256 === afterSha256) {
    fail("--before-sha256 and --after-sha256 must differ");
  }
  const currentSha256 = sha256File(absoluteStatePath);
  if (currentSha256 !== afterSha256) {
    fail("--after-sha256 must equal the current app-managed state file hash", {
      declared: afterSha256,
      current: currentSha256,
    });
  }

  const changedFields = args["changed-field"] ?? [];
  requireStringArray(changedFields, "changed-field", {
    min: 1,
    max: 64,
    itemMax: 512,
  });
  const preservedFields = args["preserved-field"] ?? [];
  requireStringArray(preservedFields, "preserved-field", {
    min: 1,
    max: 64,
    itemMax: 512,
  });
  const operationEvidence = requireSuccessfulAutomationUpdateEvidence(
    args["operation-evidence"],
    "operation-evidence",
  );
  const readbackRefs = args["readback-evidence"] ?? [];
  requireTypedReferences(readbackRefs, "readback-evidence", { min: 1 });
  const invariantRefs = args["invariant-evidence"] ?? [];
  requireTypedReferences(invariantRefs, "invariant-evidence", { min: 1 });
  const verificationRefs = args.verification ?? [];
  requireTypedReferences(verificationRefs, "verification", { min: 1 });

  const repairExecution = repairExecutionFromArgs(args, {
    requireEvidence: true,
  });
  const resolutionId =
    `app-state-resolution-${stableHash({
      proposal_id: proposal.proposal_id,
      state_surface: APP_STATE_SURFACE,
      resource_id: resourceId,
      state_path: statePath,
      after_sha256: afterSha256,
      execution_route: repairExecution.route,
      execution_id: repairExecution.execution_id,
    }).slice(0, 24)}`;
  const relativePath = path.posix.join(
    ".capability-improvements",
    `${resolutionId}.json`,
  );
  const resolution = {
    schema_version: APP_STATE_RESOLUTION_SCHEMA,
    resolution_id: resolutionId,
    resolved_at: observedAt,
    target_repo: root,
    proposal_ref: proposalRecord.artifactRef,
    proposal_id: proposal.proposal_id,
    event_ids: sortedUnique(proposal.event_ids),
    thread_ids: sortedUnique(proposal.thread_ids),
    root_cause: args["root-cause"],
    state: {
      surface: APP_STATE_SURFACE,
      resource_id: resourceId,
      path: statePath,
      observed_at: observedAt,
      before_sha256: beforeSha256,
      after_sha256: afterSha256,
      changed_fields: sortedUnique(changedFields),
      preserved_fields: sortedUnique(preservedFields),
    },
    evidence: {
      operation: operationEvidence,
      readback_refs: sortedUnique(readbackRefs),
      invariant_refs: sortedUnique(invariantRefs),
      verification_refs: sortedUnique(verificationRefs),
    },
    repair_execution: repairExecution,
    source_control: {
      required: false,
      reason: APP_STATE_SOURCE_CONTROL_REASON,
    },
    status: "closed_after_app_state_repair",
  };
  validateAppStateResolution(resolution, root);
  const absolutePath = path.join(root, relativePath);
  let writeState = "planned";
  if (args.execute) {
    ensureExcludeEntry(root);
    writeState = writeJsonIdempotent(absolutePath, resolution);
  }
  return {
    ok: true,
    mode: args.execute ? "execute" : "dry_run",
    target_repo: root,
    artifact_ref: `artifact:${relativePath}`,
    artifact_path: absolutePath,
    write_state: writeState,
    resolution,
    state_mutated: false,
    marker_deleted: false,
  };
}

function commandIndexList(args) {
  const codexHome = resolveCodexHome(args["codex-home"]);
  const paths = indexPaths(codexHome);
  const pending = listMarkerIds(paths.pendingDir);
  const processing = listMarkerIds(paths.processingDir);
  const threadIds = [...new Set([...pending, ...processing])].sort();
  return {
    ok: true,
    codex_home: codexHome,
    index_root: paths.root,
    thread_ids: threadIds,
    entries: threadIds.map((threadId) => ({
      thread_id: threadId,
      pending: pending.includes(threadId),
      processing: processing.includes(threadId),
    })),
  };
}

function loadIndexedFlagEvent(flag, threadId) {
  const eventRecord = loadAbsoluteEventArtifact(flag.artifact_path, threadId);
  if (eventRecord.root !== flag.source_repo) {
    fail(`Session flag source_repo does not match its authoritative Git root`, {
      event_id: flag.event_id,
      session_flag_source_repo: flag.source_repo,
      authoritative_source_repo: eventRecord.root,
    });
  }
  if (eventRecord.absolutePath !== flag.artifact_path) {
    fail(`Session flag artifact path does not match its source-local artifact`, {
      event_id: flag.event_id,
      session_flag_artifact_path: flag.artifact_path,
      source_local_artifact_path: eventRecord.absolutePath,
    });
  }
  if (eventRecord.eventId !== flag.event_id) {
    fail(`Session flag event_id does not match its source-local event`, {
      session_flag_event_id: flag.event_id,
      source_local_event_id: eventRecord.eventId,
    });
  }
  if (eventRecord.document.capability.id !== flag.capability) {
    fail(`Session flag capability does not match its source-local event`, {
      event_id: flag.event_id,
      session_flag_capability: flag.capability,
      source_local_capability: eventRecord.document.capability.id,
    });
  }
  const relativeArtifactPath = path
    .relative(eventRecord.root, eventRecord.absolutePath)
    .split(path.sep)
    .join(path.posix.sep);
  const expectedArtifactRef = `artifact:${relativeArtifactPath}`;
  if (flag.artifact !== expectedArtifactRef) {
    fail(`Session flag artifact reference does not match its source-local event`, {
      event_id: flag.event_id,
      session_flag_artifact: flag.artifact,
      source_local_artifact: expectedArtifactRef,
    });
  }
  return eventRecord;
}

function indexAuditOfficialReadAction(threadId) {
  return {
    type: "official_thread_read",
    required: true,
    thread_id: threadId,
    reason:
      "Use the official Codex thread surface to verify the originating thread before any close, disposition, repair, or dispatch action.",
  };
}

function blockedIndexedRepository(root, records, failures) {
  return {
    source_repo: root,
    classification: "blocked",
    event_ids: sortedUnique(records.map(({ flag }) => flag.event_id)),
    event_artifacts: sortedUnique(
      records.map(({ flag }) => flag.artifact_path),
    ),
    terminal_event_ids: [],
    retired_event_ids: [],
    open_event_ids: [],
    proposals: [],
    retirement_terminal: false,
    blocker: {
      errors: failures.map(({ flag, error }) => ({
        event_id: flag?.event_id ?? null,
        error: error.message,
        ...(error.details === undefined ? {} : { details: error.details }),
      })),
    },
  };
}

function auditIndexedRepository(root, records, threadId) {
  assertWorkflowStateUntracked(root);
  const documents = loadDocuments(root);
  const terminalState = analyzeTerminalState(root, documents);
  const threadEvents = terminalState.events.filter(
    (record) => eventThreadId(record.document) === threadId,
  );
  if (threadEvents.length === 0) {
    fail(`No source-repo events found for indexed thread ${threadId}`, {
      source_repo: root,
    });
  }
  const flaggedEventIds = sortedUnique(
    records.map(({ eventRecord }) => eventRecord.eventId),
  );
  const sourceEventIds = sortedUnique(
    threadEvents.map((record) => record.document.event_id),
  );
  if (!sameStringSet(flaggedEventIds, sourceEventIds)) {
    fail(`Indexed thread flags do not exactly cover its source-local events`, {
      source_repo: root,
      thread_id: threadId,
      flag_event_ids: flaggedEventIds,
      source_event_ids: sourceEventIds,
    });
  }

  const openThreadEvents = threadEvents.filter((record) =>
    terminalState.openEvents.some(
      (openRecord) =>
        openRecord.document.event_id === record.document.event_id,
    ),
  );
  const plans = proposalPlansForOpenEvents(
    root,
    terminalState,
    openThreadEvents,
  );
  const classification =
    openThreadEvents.length === 0
      ? "close_ready"
      : plans.some(
            ({ proposal }) =>
              proposal.classification === "repair_candidate",
          )
        ? "repair_required"
        : "monitor_required";
  const retiredEventIds = sourceEventIds.filter((eventId) =>
    terminalState.retiredEventIds.has(eventId),
  );
  return {
    source_repo: root,
    classification,
    event_ids: sourceEventIds,
    event_artifacts: records
      .map(({ eventRecord }) => eventRecord.absolutePath)
      .sort(),
    terminal_event_ids: sourceEventIds.filter(
      (eventId) =>
        terminalState.resolvedEventIds.has(eventId) ||
        terminalState.monitoredEventIds.has(eventId) ||
        terminalState.retiredEventIds.has(eventId),
    ),
    retired_event_ids: retiredEventIds,
    open_event_ids: openThreadEvents
      .map((record) => record.document.event_id)
      .sort(),
    proposals: plans.map(({ proposal, relativePath }) => ({
      artifact_ref: `artifact:${relativePath}`,
      proposal_id: proposal.proposal_id,
      persisted: false,
      classification: proposal.classification,
      handoff_ready: proposal.handoff_ready,
      event_ids: proposal.event_ids,
      thread_ids: proposal.thread_ids,
      rationale: proposal.rationale,
      candidate_files: proposal.candidate_files,
      verification_refs: proposal.verification_refs,
    })),
    retirement_terminal:
      classification === "close_ready" && retiredEventIds.length > 0,
  };
}

function auditIndexedThread(entry, codexHome) {
  const threadId = entry.thread_id;
  const extracted = extractThreadFlags(codexHome, threadId);
  if (extracted.flags.length === 0) {
    fail(`No complete ${SESSION_FLAG} blocks found for indexed thread ${threadId}`);
  }

  const eventsByRepo = new Map();
  const failuresByRepo = new Map();
  for (const flag of extracted.flags) {
    try {
      const eventRecord = loadIndexedFlagEvent(flag, threadId);
      const records = eventsByRepo.get(eventRecord.root) ?? [];
      records.push({ flag, eventRecord });
      eventsByRepo.set(eventRecord.root, records);
    } catch (error) {
      const failures = failuresByRepo.get(flag.source_repo) ?? [];
      failures.push({ flag, error });
      failuresByRepo.set(flag.source_repo, failures);
    }
  }

  const repositoryRoots = sortedUnique([
    ...eventsByRepo.keys(),
    ...failuresByRepo.keys(),
  ]);
  const repositories = [];
  for (const root of repositoryRoots) {
    const records = eventsByRepo.get(root) ?? [];
    const failures = failuresByRepo.get(root) ?? [];
    const allRecords = [
      ...records,
      ...failures.map(({ flag }) => ({ flag })),
    ];
    if (failures.length > 0) {
      repositories.push(
        blockedIndexedRepository(root, allRecords, failures),
      );
      continue;
    }
    try {
      repositories.push(auditIndexedRepository(root, records, threadId));
    } catch (error) {
      repositories.push(
        blockedIndexedRepository(root, records, [
          { flag: records[0]?.flag, error },
        ]),
      );
    }
  }

  const classification = repositories.some(
    (repository) => repository.classification === "blocked",
  )
    ? "blocked"
    : repositories.some(
          (repository) => repository.classification === "repair_required",
        )
      ? "repair_required"
      : repositories.some(
            (repository) => repository.classification === "monitor_required",
          )
        ? "monitor_required"
        : "close_ready";
  const nextActions = [indexAuditOfficialReadAction(threadId)];
  if (classification === "close_ready") {
    nextActions.push({
      type: "index_close",
      allowed_after_official_thread_read: true,
      thread_id: threadId,
      source_repos: repositories.map((repository) => repository.source_repo),
      event_artifacts: repositories
        .flatMap((repository) => repository.event_artifacts)
        .sort(),
    });
  } else {
    for (const repository of repositories) {
      if (repository.classification === "close_ready") continue;
      if (repository.classification === "blocked") {
        nextActions.push({
          type: "investigate_blocker",
          required: true,
          thread_id: threadId,
          source_repo: repository.source_repo,
          blocker: repository.blocker,
          writes_performed: false,
        });
        continue;
      }
      nextActions.push({
        type:
          repository.classification === "repair_required"
            ? "repair_triage"
            : "monitor_triage",
        allowed_after_official_thread_read: true,
        thread_id: threadId,
        source_repo: repository.source_repo,
        planned_proposal_artifacts: repository.proposals.map(
          (proposal) => proposal.artifact_ref,
        ),
        required_sequence:
          repository.classification === "repair_required"
            ? [
                "triage_execute",
                "authorized_source_repair",
                "terminal_resolution",
                "index_close",
              ]
            : ["triage_execute", "monitor_dispose", "index_close"],
        writes_performed: false,
        repair_authority_granted: false,
      });
    }
  }

  return {
    thread_id: threadId,
    marker_state: {
      pending: entry.pending,
      processing: entry.processing,
    },
    classification,
    official_thread_read_required: true,
    rollout_path: extracted.rollout_path,
    rollout_bytes: extracted.rollout_bytes,
    flag_count: extracted.flag_count,
    source_repos: repositories.map((repository) => repository.source_repo),
    active_source_repos: repositories
      .filter((repository) => !repository.retirement_terminal)
      .map((repository) => repository.source_repo),
    event_ids: repositories
      .flatMap((repository) => repository.event_ids)
      .sort(),
    event_artifacts: repositories
      .flatMap((repository) => repository.event_artifacts)
      .sort(),
    repositories,
    next_actions: nextActions,
  };
}

function blockedIndexAuditResult(entry, error) {
  return {
    thread_id: entry.thread_id,
    marker_state: {
      pending: entry.pending,
      processing: entry.processing,
    },
    classification: "blocked",
    official_thread_read_required: true,
    blocker: {
      error: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
    },
    source_repos: [],
    active_source_repos: [],
    event_ids: [],
    event_artifacts: [],
    repositories: [],
    next_actions: [
      indexAuditOfficialReadAction(entry.thread_id),
      {
        type: "investigate_blocker",
        required: true,
        error: error.message,
      },
    ],
  };
}

function commandIndexAudit(args) {
  if (args.execute) {
    fail("index-audit is read-only and does not accept --execute", undefined, 2);
  }
  const codexHome = resolveCodexHome(args["codex-home"]);
  const requestedThreadId =
    args["thread-id"] === undefined
      ? undefined
      : requireThreadId(args["thread-id"]);
  const snapshot = commandIndexList({ "codex-home": codexHome });
  const selectedEntries =
    requestedThreadId === undefined
      ? snapshot.entries
      : snapshot.entries.filter(
          (entry) => entry.thread_id === requestedThreadId,
        );
  if (requestedThreadId !== undefined && selectedEntries.length === 0) {
    fail(`Thread is not present in the central index snapshot: ${requestedThreadId}`);
  }

  const threads = selectedEntries.map((entry) => {
    try {
      return auditIndexedThread(entry, codexHome);
    } catch (error) {
      return blockedIndexAuditResult(entry, error);
    }
  });
  const classifications = [
    "close_ready",
    "repair_required",
    "monitor_required",
    "blocked",
  ];
  const summary = Object.fromEntries(
    classifications.map((classification) => [
      classification,
      threads.filter((thread) => thread.classification === classification)
        .length,
    ]),
  );

  const groups = new Map();
  for (const thread of threads) {
    for (const repository of thread.repositories) {
      if (repository.retirement_terminal) continue;
      const group = groups.get(repository.source_repo) ?? {
        source_repo: repository.source_repo,
        thread_ids: [],
        classifications: [],
        event_ids: [],
        event_artifacts: [],
        proposals: [],
        next_actions: [],
      };
      group.thread_ids.push(thread.thread_id);
      group.classifications.push(repository.classification);
      group.event_ids.push(...repository.event_ids);
      group.event_artifacts.push(...repository.event_artifacts);
      group.proposals.push(...repository.proposals);
      group.next_actions.push(
        ...thread.next_actions.filter(
          (action) =>
            action.type === "official_thread_read" ||
            action.source_repo === repository.source_repo ||
            action.source_repos?.includes(repository.source_repo),
        ),
      );
      groups.set(repository.source_repo, group);
    }
  }
  const sourceRepoGroups = [...groups.values()]
    .map((group) => ({
      ...group,
      thread_ids: sortedUnique(group.thread_ids),
      classifications: sortedUnique(group.classifications),
      event_ids: sortedUnique(group.event_ids),
      event_artifacts: sortedUnique(group.event_artifacts),
      proposals: [
        ...new Map(
          group.proposals.map((proposal) => [proposal.proposal_id, proposal]),
        ).values(),
      ].sort((left, right) => left.proposal_id.localeCompare(right.proposal_id)),
    }))
    .sort((left, right) => left.source_repo.localeCompare(right.source_repo));

  return {
    ok: true,
    mode: "read_only",
    codex_home: codexHome,
    index_root: snapshot.index_root,
    finite_snapshot: true,
    snapshot_thread_count: snapshot.entries.length,
    selected_thread_count: selectedEntries.length,
    requested_thread_id: requestedThreadId ?? null,
    summary: {
      audited: threads.length,
      ...summary,
    },
    threads,
    source_repo_groups: sourceRepoGroups,
    official_thread_read_required_before_action: true,
    marker_mutated: false,
    proposals_written: false,
    transcript_persisted: false,
    dispatched: false,
  };
}

function commandIndexStatus(args) {
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  const paths = indexPaths(codexHome, threadId);
  return {
    ok: true,
    thread_id: threadId,
    pending: markerMetadata(paths.pending),
    processing: markerMetadata(paths.processing),
  };
}

function commandIndexAdd(args) {
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  const paths = indexPaths(codexHome, threadId);
  if (!args.execute) {
    return {
      ok: true,
      mode: "dry_run",
      thread_id: threadId,
      pending_marker: paths.pending,
      state: markerMetadata(paths.pending).exists ? "existing" : "planned",
    };
  }
  return withIndexLock(codexHome, threadId, (lockedPaths) => ({
    ok: true,
    mode: "execute",
    thread_id: threadId,
    pending_marker: lockedPaths.pending,
    state: createMarker(lockedPaths.pending),
  }));
}

function commandIndexClaim(args) {
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  const leaseSeconds = parseLeaseSeconds(args["lease-seconds"]);
  const paths = indexPaths(codexHome, threadId);
  const inspect = () => {
    const pending = markerMetadata(paths.pending);
    const processing = markerMetadata(paths.processing);
    if (processing.exists && processing.age_seconds <= leaseSeconds) {
      return {
        state: "busy",
        claimed: false,
        pending: pending.exists,
        processing_age_seconds: processing.age_seconds,
      };
    }
    if (processing.exists) {
      return {
        state: "stale_processing",
        claimed: false,
        pending: pending.exists,
        processing_age_seconds: processing.age_seconds,
      };
    }
    if (pending.exists) {
      return {
        state: "claimable",
        claimed: false,
        pending: true,
        processing_age_seconds: null,
      };
    }
    return {
      state: "absent",
      claimed: false,
      pending: false,
      processing_age_seconds: null,
    };
  };
  if (!args.execute) {
    return {
      ok: true,
      mode: "dry_run",
      thread_id: threadId,
      lease_seconds: leaseSeconds,
      ...inspect(),
    };
  }
  return withIndexLock(codexHome, threadId, (lockedPaths) => {
    const current = inspect();
    if (current.state === "busy" || current.state === "absent") {
      return {
        ok: true,
        mode: "execute",
        thread_id: threadId,
        lease_seconds: leaseSeconds,
        ...current,
      };
    }
    if (current.state === "stale_processing") {
      const now = new Date();
      fs.utimesSync(lockedPaths.processing, now, now);
      return {
        ok: true,
        mode: "execute",
        thread_id: threadId,
        lease_seconds: leaseSeconds,
        state: "reclaimed",
        claimed: true,
        pending: current.pending,
        processing_age_seconds: 0,
      };
    }
    fs.mkdirSync(lockedPaths.processingDir, { recursive: true });
    fs.renameSync(lockedPaths.pending, lockedPaths.processing);
    return {
      ok: true,
      mode: "execute",
      thread_id: threadId,
      lease_seconds: leaseSeconds,
      state: "claimed",
      claimed: true,
      pending: false,
      processing_age_seconds: 0,
    };
  });
}

function commandIndexRelease(args) {
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  const paths = indexPaths(codexHome, threadId);
  const pending = markerMetadata(paths.pending);
  const processing = markerMetadata(paths.processing);
  if (!args.execute) {
    return {
      ok: true,
      mode: "dry_run",
      thread_id: threadId,
      state: processing.exists
        ? pending.exists
          ? "would_merge_to_pending"
          : "would_release"
        : pending.exists
          ? "already_pending"
          : "absent",
    };
  }
  return withIndexLock(codexHome, threadId, (lockedPaths) => {
    const currentPending = markerMetadata(lockedPaths.pending);
    const currentProcessing = markerMetadata(lockedPaths.processing);
    let state;
    if (currentProcessing.exists && currentPending.exists) {
      fs.unlinkSync(lockedPaths.processing);
      state = "merged_to_pending";
    } else if (currentProcessing.exists) {
      fs.mkdirSync(lockedPaths.pendingDir, { recursive: true });
      fs.renameSync(lockedPaths.processing, lockedPaths.pending);
      state = "released";
    } else if (currentPending.exists) {
      state = "already_pending";
    } else {
      state = "absent";
    }
    return {
      ok: true,
      mode: "execute",
      thread_id: threadId,
      state,
    };
  });
}

function loadAbsoluteEventArtifact(absolutePath, threadId) {
  requireText(absolutePath, "event-artifact", 4096);
  if (!path.isAbsolute(absolutePath)) {
    fail("--event-artifact must be an absolute path");
  }
  if (!fs.existsSync(absolutePath) || !fs.lstatSync(absolutePath).isFile()) {
    fail(`Event artifact must be a regular file: ${absolutePath}`);
  }
  const root = resolveGitRoot(path.dirname(absolutePath));
  const expectedDirectory = fs.realpathSync(improvementsPath(root));
  const realArtifact = fs.realpathSync(absolutePath);
  if (path.dirname(realArtifact) !== expectedDirectory) {
    fail(`Event artifact is outside the source repo improvements directory: ${absolutePath}`);
  }
  let document;
  try {
    document = JSON.parse(fs.readFileSync(realArtifact, "utf8"));
  } catch (error) {
    fail(`Invalid JSON: ${realArtifact}`, { message: error.message });
  }
  if (
    document.schema_version !== EVENT_SCHEMA &&
    document.schema_version !== LEGACY_EVENT_SCHEMA
  ) {
    fail(`Not a capability improvement event: ${realArtifact}`);
  }
  validateEvent(document, root);
  if (eventThreadId(document) !== threadId) {
    fail(`Event artifact does not belong to thread ${threadId}: ${realArtifact}`);
  }
  return {
    root,
    absolutePath: realArtifact,
    eventId: document.event_id,
    document,
  };
}

function verifyIndexedEventCoverage(codexHome, threadId, suppliedEvents) {
  const extracted = extractThreadFlags(codexHome, threadId);
  if (extracted.flags.length === 0) {
    fail(`No complete ${SESSION_FLAG} blocks found for indexed thread ${threadId}`);
  }
  const indexedEventIds = sortedUnique(
    extracted.flags.map((flag) => flag.event_id),
  );
  const suppliedEventIds = sortedUnique(
    suppliedEvents.map((record) => record.eventId),
  );
  const indexedArtifacts = sortedUnique(
    extracted.flags.map((flag) => flag.artifact_path),
  );
  const suppliedArtifacts = sortedUnique(
    suppliedEvents.map((record) => record.absolutePath),
  );
  if (
    !sameStringSet(indexedEventIds, suppliedEventIds) ||
    !sameStringSet(indexedArtifacts, suppliedArtifacts)
  ) {
    fail(
      `index-close event artifacts do not exactly cover indexed thread ${threadId}`,
      {
        indexed_event_ids: indexedEventIds,
        supplied_event_ids: suppliedEventIds,
        indexed_event_artifacts: indexedArtifacts,
        supplied_event_artifacts: suppliedArtifacts,
      },
    );
  }
  for (const flag of extracted.flags) {
    loadIndexedFlagEvent(flag, threadId);
  }
  return {
    rollout_path: extracted.rollout_path,
    indexed_event_ids: indexedEventIds,
    indexed_event_artifacts: indexedArtifacts,
  };
}

function verifyThreadResolved(threadId, suppliedEvents) {
  const roots = sortedUnique(suppliedEvents.map((record) => record.root));
  const covered = [];
  for (const root of roots) {
    const documents = loadDocuments(root);
    const resolutions = documents.filter(
      (record) => record.document.schema_version === RESOLUTION_SCHEMA,
    );
    for (const resolution of resolutions) {
      validateResolutionLinks(root, documents, resolution);
    }
    const appStateResolutions = documents.filter(
      (record) =>
        record.document.schema_version === APP_STATE_RESOLUTION_SCHEMA,
    );
    for (const resolution of appStateResolutions) {
      validateAppStateResolutionLinks(root, documents, resolution);
    }
    const monitorDispositions = documents.filter(
      (record) =>
        record.document.schema_version === MONITOR_DISPOSITION_SCHEMA,
    );
    for (const disposition of monitorDispositions) {
      validateMonitorDispositionLinks(root, documents, disposition);
    }
    const retirementDispositions = documents.filter(
      (record) =>
        record.document.schema_version === RETIREMENT_DISPOSITION_SCHEMA,
    );
    for (const disposition of retirementDispositions) {
      validateRetirementDispositionLinks(root, documents, disposition);
    }
    const threadEvents = documents.filter(
      (record) =>
        (record.document.schema_version === EVENT_SCHEMA ||
          record.document.schema_version === LEGACY_EVENT_SCHEMA) &&
        eventThreadId(record.document) === threadId,
    );
    if (threadEvents.length === 0) {
      fail(`No source-repo events found for thread ${threadId} in ${root}`);
    }
    const resolvedIds = new Set(
      [
        ...resolutions
          .filter((record) => record.document.thread_ids.includes(threadId))
          .flatMap((record) => record.document.event_ids),
        ...appStateResolutions
          .filter((record) => record.document.thread_ids.includes(threadId))
          .flatMap((record) => record.document.event_ids),
        ...monitorDispositions
          .filter((record) => record.document.thread_ids.includes(threadId))
          .flatMap((record) => record.document.event_ids),
        ...retirementDispositions
          .filter((record) => record.document.thread_ids.includes(threadId))
          .flatMap((record) => record.document.event_ids),
      ],
    );
    const unresolved = threadEvents
      .map((record) => record.document.event_id)
      .filter((eventId) => !resolvedIds.has(eventId));
    if (unresolved.length > 0) {
      fail(`Thread ${threadId} still has unresolved or undisposed events`, {
        target_repo: root,
        unresolved_event_ids: unresolved,
      });
    }
    covered.push(
      ...threadEvents.map((record) => ({
        target_repo: root,
        event_id: record.document.event_id,
      })),
    );
  }
  for (const supplied of suppliedEvents) {
    if (
      !covered.some(
        (record) =>
          record.target_repo === supplied.root &&
          record.event_id === supplied.eventId,
      )
    ) {
      fail(
        `Supplied event was not covered by a terminal disposition: ${supplied.absolutePath}`,
      );
    }
  }
  return { roots, covered };
}

function commandIndexClose(args) {
  const threadId = requireThreadId(args["thread-id"]);
  const codexHome = resolveCodexHome(args["codex-home"]);
  const eventArtifacts = args["event-artifact"] ?? [];
  if (eventArtifacts.length === 0) {
    fail("index-close requires at least one --event-artifact", undefined, 2);
  }
  const loadAndVerify = (requireIndexedCoverage) => {
    const supplied = eventArtifacts.map((artifact) =>
      loadAbsoluteEventArtifact(artifact, threadId),
    );
    const indexedCoverage = requireIndexedCoverage
      ? verifyIndexedEventCoverage(codexHome, threadId, supplied)
      : null;
    return {
      ...verifyThreadResolved(threadId, supplied),
      indexed_coverage: indexedCoverage,
    };
  };
  if (!args.execute) {
    const paths = indexPaths(codexHome, threadId);
    const markerPresent =
      markerMetadata(paths.pending).exists ||
      markerMetadata(paths.processing).exists;
    const verification = loadAndVerify(markerPresent);
    return {
      ok: true,
      mode: "dry_run",
      thread_id: threadId,
      state:
        markerMetadata(paths.pending).exists ||
        markerMetadata(paths.processing).exists
          ? "would_close"
          : "already_absent",
      ...verification,
    };
  }
  return withIndexLock(codexHome, threadId, (paths) => {
    const pending = markerMetadata(paths.pending);
    const processing = markerMetadata(paths.processing);
    const verification = loadAndVerify(pending.exists || processing.exists);
    if (pending.exists) fs.unlinkSync(paths.pending);
    if (processing.exists) fs.unlinkSync(paths.processing);
    return {
      ok: true,
      mode: "execute",
      thread_id: threadId,
      state:
        pending.exists || processing.exists ? "closed" : "already_absent",
      ...verification,
    };
  });
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args._.length === 0) {
    process.stdout.write(HELP);
    return;
  }
  if (args._.length !== 1) {
    fail("Expected exactly one command", undefined, 2);
  }
  const command = args._[0];
  let result;
  switch (command) {
    case "schema":
      result = commandSchema();
      break;
    case "doctor":
      result = commandDoctor(args);
      if (!result.ok) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        process.exitCode = 1;
        return;
      }
      break;
    case "validate":
      result = commandValidate(args);
      break;
    case "record":
      result = commandRecord(args);
      break;
    case "triage":
      result = commandTriage(args);
      break;
    case "monitor-dispose":
      result = commandMonitorDispose(args);
      break;
    case "retire-dispose":
      result = commandRetireDispose(args);
      break;
    case "handoff-check":
      result = commandHandoffCheck(args);
      break;
    case "resolve":
      result = commandResolve(args);
      break;
    case "app-state-resolve":
      result = commandAppStateResolve(args);
      break;
    case "thread-flags":
      result = commandThreadFlags(args);
      break;
    case "index-audit":
      result = commandIndexAudit(args);
      break;
    case "index-list":
      result = commandIndexList(args);
      break;
    case "index-status":
      result = commandIndexStatus(args);
      break;
    case "index-add":
      result = commandIndexAdd(args);
      break;
    case "index-claim":
      result = commandIndexClaim(args);
      break;
    case "index-release":
      result = commandIndexRelease(args);
      break;
    case "index-close":
      result = commandIndexClose(args);
      break;
    default:
      fail(`Unknown command: ${command}`, undefined, 2);
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  const payload = {
    ok: false,
    error: error.message,
  };
  if (error.details !== undefined) {
    payload.details = error.details;
  }
  process.stderr.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exitCode = error.exitCode ?? 1;
}

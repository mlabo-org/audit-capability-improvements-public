import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT = path.resolve(
  TEST_DIR,
  "..",
  "scripts",
  "capability-improvement.mjs",
);
const THREAD_ID = "019f7282-bb38-7712-b4bf-94fb5442f1ab";
const SECOND_THREAD_ID = "019f7282-bb38-7712-b4bf-94fb5442f1ac";
const THIRD_THREAD_ID = "019f7282-bb38-7712-b4bf-94fb5442f1ad";
const FOURTH_THREAD_ID = "019f7282-bb38-7712-b4bf-94fb5442f1ae";

function codexHomeFor(repo) {
  return `${repo}-codex-home`;
}

function run(args, options = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...(options.env ?? {}) },
  });
}

function git(cwd, args) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
  });
  assert.equal(
    result.status,
    0,
    `git ${args.join(" ")} failed: ${result.stderr}`,
  );
  return result.stdout.trim();
}

function gitWithEnv(cwd, args, env) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  assert.equal(
    result.status,
    0,
    `git ${args.join(" ")} failed: ${result.stderr}`,
  );
  return result.stdout.trim();
}

function createRepo() {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "capability-improvement-test-"),
  );
  git(directory, ["init", "--quiet"]);
  return directory;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function addLocalExclude(repo, entry) {
  const reported = git(repo, ["rev-parse", "--git-path", "info/exclude"]);
  const excludePath = path.isAbsolute(reported)
    ? reported
    : path.resolve(repo, reported);
  const existing = fs.readFileSync(excludePath, "utf8");
  const prefix = existing.length === 0 || existing.endsWith("\n") ? "" : "\n";
  fs.appendFileSync(excludePath, `${prefix}${entry}\n`, "utf8");
}

function cleanup(directory) {
  fs.rmSync(directory, { recursive: true, force: true });
  fs.rmSync(codexHomeFor(directory), { recursive: true, force: true });
}

function writeThreadRollout(codexHome, threadId, sessionFlags, extraLines = []) {
  const rolloutDirectory = path.join(codexHome, "sessions", "2026", "07", "27");
  const rolloutPath = path.join(
    rolloutDirectory,
    `rollout-2026-07-27T00-00-00-${threadId}.jsonl`,
  );
  fs.mkdirSync(rolloutDirectory, { recursive: true });
  fs.writeFileSync(
    rolloutPath,
    [
      ...sessionFlags.map((text) =>
        JSON.stringify({
          type: "response_item",
          payload: { content: [{ text }] },
        }),
      ),
      ...extraLines,
      "",
    ].join("\n"),
    "utf8",
  );
  return rolloutPath;
}

function repairExecutionArgs(
  executionId,
  {
    route = "direct",
    authority = "role:user-request:repair-authorized",
    includeEvidence = true,
  } = {},
) {
  const args = [
    "--execution-route",
    route,
    "--execution-authority",
    authority,
  ];
  if (executionId) args.push("--execution-id", executionId);
  if (includeEvidence) {
    args.push(
      "--execution-evidence",
      `test:repair-execution-${executionId || "handoff"} result:pass`,
    );
  }
  return args;
}

function recordArgs(repo, overrides = {}) {
  const values = {
    "target-cwd": repo,
    "thread-id": THREAD_ID,
    "codex-home": codexHomeFor(repo),
    "capability-id": "sample-skill",
    "capability-kind": "skill",
    category: "input_format_mismatch",
    summary: "Provider returned an unexpected payload shape",
    expected: "Object with records array",
    actual: "Top-level array",
    compensation: "Normalized the input for this execution",
    outcome: "The requested result completed",
    "evidence-strength": "direct",
    repeatability: "one_off",
    severity: "medium",
    "source-boundary": "input",
    evidence: ["file:.capability-improvements/audit.md"],
    "candidate-file": ["src/parser.js"],
    verification: ["test:parser-contract result:pass"],
    ...overrides,
  };
  const args = ["record"];
  for (const [name, rawValue] of Object.entries(values)) {
    const items = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of items) {
      args.push(`--${name}`, value);
    }
  }
  return args;
}

function createAppStateRepairFixture({
  ignored = true,
  extraCandidates = [],
  capabilityKind = "workflow",
} = {}) {
  const repo = createRepo();
  const resourceId = "automation-123";
  const statePath = `automations/${resourceId}/automation.toml`;
  const absoluteStatePath = path.join(repo, statePath);
  const beforeContent = [
    'name = "Cloudflare audit"',
    'status = "PAUSED"',
    'schedule = "0 9 * * *"',
    "",
  ].join("\n");
  const afterContent = [
    'name = "Cloudflare audit"',
    'status = "ACTIVE"',
    'schedule = "0 9 * * *"',
    "",
  ].join("\n");
  fs.mkdirSync(path.dirname(absoluteStatePath), { recursive: true });
  fs.writeFileSync(absoluteStatePath, afterContent, "utf8");
  if (ignored) {
    addLocalExclude(repo, "automations/");
  }

  const recorded = parseStdout(
    run([
      ...recordArgs(repo, {
        "capability-id": "cloudflare-repair-automation",
        "capability-kind": capabilityKind,
        category: "source_cache_runtime_drift",
        summary: "Automation state required an official app update",
        expected: "Official automation state reflects the authorized repair",
        actual: "The state needed repair outside Git source control",
        compensation: "Applied the authorized official automation update",
        outcome: "The repaired state was read back and verified",
        repeatability: "reproduced",
        severity: "high",
        "source-boundary": "runtime",
        "candidate-file": [statePath, ...extraCandidates],
        verification: ["test:automation-repair result:pass"],
      }),
      "--execute",
    ]),
  );
  const triage = parseStdout(
    run(["triage", "--target-cwd", repo, "--execute"]),
  );
  assert.equal(triage.proposals.length, 1);
  assert.equal(triage.proposals[0].classification, "repair_candidate");
  assert.equal(triage.proposals[0].handoff_ready, true);
  const proposalRef = triage.proposals[0].artifact_ref;
  const executionId = "repair-cloudflare-automation";
  const proposalCreatedAt = triage.proposals[0].created_at;
  const observedAt = new Date(
    Math.max(Date.now(), Date.parse(proposalCreatedAt)) + 1000,
  ).toISOString();
  return {
    repo,
    resourceId,
    statePath,
    absoluteStatePath,
    beforeContent,
    afterContent,
    beforeSha256: sha256(beforeContent),
    afterSha256: sha256(afterContent),
    recorded,
    proposalRef,
    proposalCreatedAt,
    observedAt,
    executionId,
  };
}

function appStateResolveArgs(fixture, overrides = {}) {
  const values = {
    "target-cwd": fixture.repo,
    "proposal-ref": fixture.proposalRef,
    "execution-route": "direct",
    "execution-id": fixture.executionId,
    "execution-authority": "role:user-request:repair-authorized",
    "execution-evidence": ["test:repair-execution-automation result:pass"],
    "root-cause":
      "The terminal workflow modeled only Git commits and lacked an app-managed state resolution.",
    "state-surface": "codex_automation",
    "resource-id": fixture.resourceId,
    "state-path": fixture.statePath,
    "observed-at": fixture.observedAt,
    "before-sha256": fixture.beforeSha256,
    "after-sha256": fixture.afterSha256,
    "changed-field": ["status"],
    "preserved-field": ["name", "schedule"],
    "operation-evidence": "test:codex_app.automation_update result:pass",
    "readback-evidence": ["test:codex_app.automation_readback result:pass"],
    "invariant-evidence": ["test:automation-schedule-preserved result:pass"],
    verification: ["test:automation-repair result:pass"],
    ...overrides,
  };
  const args = ["app-state-resolve"];
  for (const [name, rawValue] of Object.entries(values)) {
    const items = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of items) {
      args.push(`--${name}`, value);
    }
  }
  return args;
}

function parseStdout(result) {
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("--help and schema expose the stable contract", () => {
  const help = run(["--help"]);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /Persistent writes are opt-in with --execute/);
  assert.match(help.stdout, /never launches Codex/);
  assert.match(help.stdout, /thread-flags --thread-id <uuid>/);
  assert.match(help.stdout, /index-audit \[--thread-id <uuid>\]/);
  assert.match(help.stdout, /close_ready/);
  assert.match(help.stdout, /app-state-resolve/);
  assert.match(help.stdout, /retire-dispose/);
  assert.match(help.stdout, /never mutates automation state/);

  const schema = parseStdout(run(["schema"]));
  assert.equal(
    schema.event_schema,
    "capability-improvement-evidence/v2",
  );
  assert.equal(
    schema.repair_plan_schema,
    "capability-improvement-repair-plan/v2",
  );
  assert.equal(
    schema.legacy_event_schema,
    "capability-improvement-evidence/v1",
  );
  assert.equal(schema.session_flag, "CAPABILITY_FRICTION_DETECTED");
  assert.match(schema.central_index, /capability-friction-index/);
  assert.equal(
    schema.resolution_schema,
    "capability-improvement-resolution/v1",
  );
  assert.equal(
    schema.app_state_resolution_schema,
    "capability-improvement-app-state-resolution/v1",
  );
  assert.equal(
    schema.monitor_disposition_schema,
    "capability-improvement-monitor-disposition/v1",
  );
  assert.equal(
    schema.retirement_disposition_schema,
    "capability-improvement-retirement-disposition/v1",
  );
  assert.match(
    schema.central_index_cleanup,
    /app-state repair resolution/,
  );
  assert.match(
    schema.thread_flag_extraction,
    /returns deduplicated fixed CAPABILITY_FRICTION_DETECTED blocks only/,
  );
  assert.match(schema.thread_flag_extraction, /without a total-file cap/);
  assert.deepEqual(schema.index_audit.classifications, [
    "close_ready",
    "repair_required",
    "monitor_required",
    "blocked",
  ]);
  assert.equal(
    schema.index_audit.official_thread_read_required_before_action,
    true,
  );
  assert.match(
    schema.index_audit.repository_fault_isolation,
    /without hiding independently valid groups/,
  );
  assert.equal(
    schema.retirement_disposition.authority,
    "explicit_user_request",
  );
  assert.equal(schema.passive_dispatch, false);
  assert.equal(schema.app_state_resolution.state_surface, "codex_automation");
  assert.equal(schema.app_state_resolution.source_control.required, false);
  assert.equal(
    schema.app_state_resolution.source_control.reason,
    "app_managed_ignored_untracked_state",
  );
  assert.match(
    schema.git_resolution.commit_modes.ancestor,
    /delayed-reconciliation mode/,
  );
  assert.match(
    schema.git_resolution.commit_modes.preexisting,
    /legacy evidence recorded only after its repair/,
  );
  assert.equal(
    schema.triage.test_relaxation_for_single_anomaly,
    "forbidden",
  );
});

test("record refuses a non-Git target", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "capability-improvement-nongit-"),
  );
  try {
    const result = run(recordArgs(directory));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unable to resolve an authoritative Git root/);
    assert.equal(fs.existsSync(path.join(directory, ".capability-improvements")), false);
  } finally {
    cleanup(directory);
  }
});

test("record is dry-run by default and makes no filesystem change", () => {
  const repo = createRepo();
  try {
    const output = parseStdout(run(recordArgs(repo)));
    assert.equal(output.mode, "dry_run");
    assert.equal(output.dispatched, false);
    assert.equal(output.target_repo, fs.realpathSync(repo));
    assert.equal(fs.existsSync(path.join(repo, ".capability-improvements")), false);
    assert.equal(
      fs.existsSync(path.join(codexHomeFor(repo), "capability-friction-index")),
      false,
    );
    const exclude = git(repo, ["rev-parse", "--git-path", "info/exclude"]);
    const excludePath = path.isAbsolute(exclude)
      ? exclude
      : path.resolve(repo, exclude);
    assert.doesNotMatch(
      fs.readFileSync(excludePath, "utf8"),
      /^\.capability-improvements\/$/m,
    );
  } finally {
    cleanup(repo);
  }
});

test("record --execute writes one validated event and local exclude entry", () => {
  const repo = createRepo();
  try {
    const output = parseStdout(run([...recordArgs(repo), "--execute"]));
    assert.equal(output.mode, "execute");
    assert.equal(fs.existsSync(output.artifact_path), true);
    assert.equal(
      JSON.parse(fs.readFileSync(output.artifact_path, "utf8")).schema_version,
      "capability-improvement-evidence/v2",
    );
    assert.equal(output.event.origin.thread_id, THREAD_ID);
    assert.match(
      output.session_flag,
      new RegExp(`^CAPABILITY_FRICTION_DETECTED\\nsession_id: ${THREAD_ID}`, "m"),
    );
    const pendingMarker = path.join(
      codexHomeFor(repo),
      "capability-friction-index",
      "pending",
      THREAD_ID,
    );
    assert.equal(fs.statSync(pendingMarker).size, 0);
    const exclude = git(repo, ["rev-parse", "--git-path", "info/exclude"]);
    const excludePath = path.isAbsolute(exclude)
      ? exclude
      : path.resolve(repo, exclude);
    assert.match(
      fs.readFileSync(excludePath, "utf8"),
      /^\.capability-improvements\/$/m,
    );

    const validation = parseStdout(
      run(["validate", "--target-cwd", repo]),
    );
    assert.equal(validation.event_count, 1);
    assert.equal(validation.proposal_count, 0);
  } finally {
    cleanup(repo);
  }
});

test("one weak input-format anomaly remains monitor", () => {
  const repo = createRepo();
  try {
    parseStdout(run([...recordArgs(repo), "--execute"]));
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo]),
    );
    assert.equal(triage.mode, "dry_run");
    assert.equal(triage.proposals.length, 1);
    assert.equal(triage.proposals[0].classification, "monitor");
    assert.equal(triage.proposals[0].handoff_ready, false);
    assert.ok(
      triage.proposals[0].rationale.includes(
        "single_weak_input_anomaly_remains_monitor",
      ),
    );
  } finally {
    cleanup(repo);
  }
});

test("monitor disposition closes the marker and remains evidence for repeat escalation", () => {
  const repo = createRepo();
  try {
    const first = parseStdout(
      run([...recordArgs(repo), "--execute"]),
    );
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    const proposalRef = triage.proposals[0].artifact_ref;
    const dryRun = parseStdout(
      run([
        "monitor-dispose",
        "--target-cwd",
        repo,
        "--proposal-ref",
        proposalRef,
      ]),
    );
    assert.equal(dryRun.write_state, "planned");
    assert.equal(fs.existsSync(dryRun.artifact_path), false);

    const dispositionArgs = [
      "monitor-dispose",
      "--target-cwd",
      repo,
      "--proposal-ref",
      proposalRef,
      "--execute",
    ];
    const disposed = parseStdout(run(dispositionArgs));
    assert.equal(disposed.write_state, "created");
    assert.equal(disposed.disposition.status, "closed_without_repair");
    assert.equal(disposed.disposition.future_evidence_reopens, true);
    assert.equal(disposed.marker_deleted, false);
    assert.equal(parseStdout(run(dispositionArgs)).write_state, "existing");

    const validation = parseStdout(
      run(["validate", "--target-cwd", repo]),
    );
    assert.equal(validation.monitor_disposition_count, 1);
    const terminalTriage = parseStdout(
      run(["triage", "--target-cwd", repo]),
    );
    assert.equal(terminalTriage.all_resolved, false);
    assert.equal(terminalTriage.all_terminal, true);
    assert.deepEqual(terminalTriage.proposals, []);
    writeThreadRollout(codexHomeFor(repo), THREAD_ID, [first.session_flag]);

    const close = parseStdout(
      run([
        "index-close",
        "--thread-id",
        THREAD_ID,
        "--event-artifact",
        first.artifact_path,
        "--codex-home",
        codexHomeFor(repo),
        "--execute",
      ]),
    );
    assert.equal(close.state, "closed");

    parseStdout(
      run([
        ...recordArgs(repo, { "thread-id": SECOND_THREAD_ID }),
        "--execute",
      ]),
    );
    const repeated = parseStdout(
      run(["triage", "--target-cwd", repo]),
    );
    assert.equal(repeated.proposals.length, 1);
    assert.equal(repeated.proposals[0].classification, "repair_candidate");
    assert.equal(repeated.proposals[0].handoff_ready, true);
    assert.equal(repeated.proposals[0].event_ids.length, 2);
    assert.deepEqual(repeated.proposals[0].thread_ids, [
      THREAD_ID,
      SECOND_THREAD_ID,
    ]);
    assert.ok(
      repeated.proposals[0].rationale.includes(
        "multiple_events_share_repeat_key",
      ),
    );
  } finally {
    cleanup(repo);
  }
});

test("repeated matching anomalies become a handoff-ready repair candidate", () => {
  const repo = createRepo();
  try {
    parseStdout(run([...recordArgs(repo), "--execute"]));
    parseStdout(run([...recordArgs(repo), "--execute"]));
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    assert.equal(triage.proposals.length, 1);
    assert.equal(triage.proposals[0].classification, "repair_candidate");
    assert.equal(triage.proposals[0].handoff_ready, true);
    assert.ok(
      triage.proposals[0].rationale.includes(
        "multiple_events_share_repeat_key",
      ),
    );
    const artifact = triage.proposals[0].artifact_ref.replace(
      /^artifact:/,
      "",
    );
    const persisted = JSON.parse(
      fs.readFileSync(path.join(repo, artifact), "utf8"),
    );
    assert.equal(
      persisted.repair_policy.test_relaxation_for_single_anomaly,
      "forbidden",
    );
    assert.equal(
      persisted.repair_handoff.artifact_ref,
      triage.proposals[0].artifact_ref,
    );
  } finally {
    cleanup(repo);
  }
});

test("direct structural evidence is a repair candidate", () => {
  const repo = createRepo();
  try {
    parseStdout(
      run([
        ...recordArgs(repo, {
          category: "validator_gap",
          summary: "Validator omits a declared required field",
          expected: "Validator enforces the published schema",
          actual: "Validator accepts a missing required field",
          compensation: "Manually inspected the result",
          outcome: "Invalid publication was prevented",
          "source-boundary": "validator",
        }),
        "--execute",
      ]),
    );
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo]),
    );
    assert.equal(triage.proposals[0].classification, "repair_candidate");
    assert.equal(triage.proposals[0].handoff_ready, true);
    assert.ok(
      triage.proposals[0].rationale.includes(
        "direct_structural_contract_evidence",
      ),
    );
  } finally {
    cleanup(repo);
  }
});

test("untyped evidence and likely secrets are rejected", () => {
  const repo = createRepo();
  try {
    const untyped = run(
      recordArgs(repo, { evidence: ["looked at audit output"] }),
    );
    assert.notEqual(untyped.status, 0);
    assert.match(untyped.stderr, /not a capability-auditor-compatible typed reference/);

    const secret = run(
      recordArgs(repo, {
        actual: `Provider echoed sk-${"A".repeat(32)}`,
      }),
    );
    assert.notEqual(secret.status, 0);
    assert.match(secret.stderr, /likely credential/);
    assert.equal(fs.existsSync(path.join(repo, ".capability-improvements")), false);
  } finally {
    cleanup(repo);
  }
});

test("tracked .capability-improvements state is refused", () => {
  const repo = createRepo();
  try {
    const stateDir = path.join(repo, ".capability-improvements");
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(path.join(stateDir, "task.md"), "# tracked\n", "utf8");
    git(repo, ["add", ".capability-improvements/task.md"]);
    const result = run(recordArgs(repo));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Refusing to use tracked .capability-improvements/);
  } finally {
    cleanup(repo);
  }
});

test("passive commands never launch a worker or create runner state", () => {
  const repo = createRepo();
  const fakeBin = fs.mkdtempSync(
    path.join(os.tmpdir(), "capability-improvement-bin-"),
  );
  const marker = path.join(repo, "worker-launched");
  const fakeCodex = path.join(fakeBin, "codex");
  fs.writeFileSync(
    fakeCodex,
    `#!/bin/sh\nprintf launched > "${marker}"\n`,
    { encoding: "utf8", mode: 0o755 },
  );
  const env = { PATH: `${fakeBin}:${process.env.PATH}` };
  try {
    parseStdout(run([...recordArgs(repo), "--execute"], { env }));
    parseStdout(run(["doctor", "--target-cwd", repo], { env }));
    parseStdout(run(["validate", "--target-cwd", repo], { env }));
    parseStdout(run(["triage", "--target-cwd", repo], { env }));
    parseStdout(run(["schema"], { env }));
    assert.equal(fs.existsSync(marker), false);
    assert.equal(
      fs.existsSync(path.join(repo, ".capability-improvements", "runner.md")),
      false,
    );
  } finally {
    cleanup(repo);
    cleanup(fakeBin);
  }
});

test("thread-flags extracts one deduplicated fixed block without persisting transcript content", () => {
  const repo = createRepo();
  const codexHome = codexHomeFor(repo);
  const eventId = "event-20260718114026760-045a6149";
  const artifactRef = `artifact:.capability-improvements/${eventId}.json`;
  const validFlag = [
    "CAPABILITY_FRICTION_DETECTED  ",
    `session_id: ${THREAD_ID}  `,
    `event_id: ${eventId}  `,
    "capability: sample-skill  ",
    `source_repo: ${repo}  `,
    `artifact: ${artifactRef}  `,
    "state: pending",
  ].join("\n");
  const otherThreadFlag = [
    "CAPABILITY_FRICTION_DETECTED",
    `session_id: ${SECOND_THREAD_ID}`,
    "event_id: event-20260718114026761-045a6150",
    "capability: other-skill",
    `source_repo: ${repo}`,
    "artifact: artifact:.capability-improvements/event-20260718114026761-045a6150.json",
    "state: pending",
  ].join("\n");
  const rolloutDirectory = path.join(codexHome, "sessions", "2026", "07", "18");
  const rolloutPath = path.join(
    rolloutDirectory,
    `rollout-2026-07-18T08-56-38-${THREAD_ID}.jsonl`,
  );
  try {
    fs.mkdirSync(rolloutDirectory, { recursive: true });
    fs.writeFileSync(
      rolloutPath,
      [
        JSON.stringify({
          type: "response_item",
          payload: { content: [{ text: validFlag }] },
        }),
        JSON.stringify({
          type: "duplicate_tool_output",
          payload: [validFlag, "CAPABILITY_FRICTION_DETECTED without fields"],
        }),
        JSON.stringify({
          type: "different_thread",
          payload: { text: otherThreadFlag },
        }),
        "",
      ].join("\n"),
      "utf8",
    );
    const beforeMtime = fs.statSync(rolloutPath).mtimeMs;

    const extracted = parseStdout(
      run([
        "thread-flags",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
      ]),
    );
    assert.equal(extracted.mode, "read_only");
    assert.equal(extracted.flag_count, 1);
    assert.equal(extracted.transcript_persisted, false);
    assert.equal(extracted.dispatched, false);
    assert.equal(extracted.rollout_path, rolloutPath);
    assert.deepEqual(extracted.flags, [
      {
        session_id: THREAD_ID,
        event_id: eventId,
        capability: "sample-skill",
        source_repo: repo,
        artifact: artifactRef,
        artifact_path: path.join(
          repo,
          ".capability-improvements",
          `${eventId}.json`,
        ),
        state: "pending",
      },
    ]);
    assert.equal(fs.statSync(rolloutPath).mtimeMs, beforeMtime);
    assert.equal(
      fs.existsSync(path.join(codexHome, "capability-friction-index")),
      false,
    );

    const missing = run([
      "thread-flags",
      "--thread-id",
      SECOND_THREAD_ID,
      "--codex-home",
      codexHome,
    ]);
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /No Codex rollout found for thread/);
  } finally {
    cleanup(repo);
  }
});

test("thread-flags streams a rollout larger than the former 256 MiB cap", () => {
  const repo = createRepo();
  const codexHome = codexHomeFor(repo);
  const eventId = "event-20260727000000000-045a6149";
  const validFlag = [
    "CAPABILITY_FRICTION_DETECTED",
    `session_id: ${THREAD_ID}`,
    `event_id: ${eventId}`,
    "capability: sample-skill",
    `source_repo: ${repo}`,
    `artifact: artifact:.capability-improvements/${eventId}.json`,
    "state: pending",
  ].join("\n");
  const rolloutDirectory = path.join(codexHome, "sessions", "2026", "07", "27");
  const rolloutPath = path.join(
    rolloutDirectory,
    `rollout-2026-07-27T00-00-00-${THREAD_ID}.jsonl`,
  );
  const padding = Buffer.alloc(30 * 1024 * 1024, 0x20);
  try {
    fs.mkdirSync(rolloutDirectory, { recursive: true });
    const descriptor = fs.openSync(rolloutPath, "w");
    try {
      fs.writeSync(
        descriptor,
        `${JSON.stringify({ payload: { text: validFlag } })}\n`,
      );
      for (let index = 0; index < 9; index += 1) {
        fs.writeSync(descriptor, padding);
        fs.writeSync(descriptor, "\n");
      }
    } finally {
      fs.closeSync(descriptor);
    }
    assert.ok(fs.statSync(rolloutPath).size > 256 * 1024 * 1024);

    const extracted = parseStdout(
      run([
        "thread-flags",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
      ]),
    );
    assert.equal(extracted.flag_count, 1);
    assert.equal(extracted.rollout_bytes, fs.statSync(rolloutPath).size);
    assert.equal(extracted.transcript_persisted, false);
  } finally {
    cleanup(repo);
  }
});

test("thread-flags preserves exact malformed JSONL line errors", () => {
  const repo = createRepo();
  const codexHome = codexHomeFor(repo);
  try {
    writeThreadRollout(codexHome, THREAD_ID, [], [
      JSON.stringify({ type: "valid" }),
      "{malformed",
    ]);
    const result = run([
      "thread-flags",
      "--thread-id",
      THREAD_ID,
      "--codex-home",
      codexHome,
    ]);
    assert.notEqual(result.status, 0);
    const error = JSON.parse(result.stderr);
    assert.match(error.error, /line 2$/);
    assert.equal(error.details.rollout_path.endsWith(`${THREAD_ID}.jsonl`), true);
  } finally {
    cleanup(repo);
  }
});

test("thread-flags enforces the documented per-line byte cap with an exact line number", () => {
  const repo = createRepo();
  const codexHome = codexHomeFor(repo);
  const rolloutDirectory = path.join(codexHome, "sessions", "2026", "07", "27");
  const rolloutPath = path.join(
    rolloutDirectory,
    `rollout-2026-07-27T00-00-00-${THREAD_ID}.jsonl`,
  );
  try {
    fs.mkdirSync(rolloutDirectory, { recursive: true });
    const descriptor = fs.openSync(rolloutPath, "w");
    try {
      fs.writeSync(descriptor, "{}\n");
      fs.writeSync(descriptor, Buffer.alloc(32 * 1024 * 1024 + 1, 0x20));
    } finally {
      fs.closeSync(descriptor);
    }
    const result = run([
      "thread-flags",
      "--thread-id",
      THREAD_ID,
      "--codex-home",
      codexHome,
    ]);
    assert.notEqual(result.status, 0);
    const error = JSON.parse(result.stderr);
    assert.match(error.error, /line 2 exceeds 33554432 bytes/);
    assert.equal(error.details.line, 2);
    assert.ok(error.details.bytes > 32 * 1024 * 1024);
  } finally {
    cleanup(repo);
  }
});

test("index-audit classifies a finite read-only snapshot and groups next actions by repo", () => {
  const closeRepo = createRepo();
  const repairRepo = createRepo();
  const monitorRepo = createRepo();
  const codexHome = codexHomeFor(closeRepo);
  const blockedMarker = path.join(
    codexHome,
    "capability-friction-index",
    "pending",
    FOURTH_THREAD_ID,
  );
  try {
    const closeEvent = parseStdout(
      run([
        ...recordArgs(closeRepo, {
          "thread-id": THREAD_ID,
          "codex-home": codexHome,
        }),
        "--execute",
      ]),
    );
    const closePlan = parseStdout(
      run(["triage", "--target-cwd", closeRepo, "--execute"]),
    ).proposals[0];
    assert.equal(closePlan.classification, "monitor");
    parseStdout(
      run([
        "monitor-dispose",
        "--target-cwd",
        closeRepo,
        "--proposal-ref",
        closePlan.artifact_ref,
        "--execute",
      ]),
    );
    writeThreadRollout(codexHome, THREAD_ID, [closeEvent.session_flag]);

    const repairEvent = parseStdout(
      run([
        ...recordArgs(repairRepo, {
          "thread-id": SECOND_THREAD_ID,
          "codex-home": codexHome,
          category: "route_mismatch",
          summary: "The dedicated route was bypassed",
          expected: "The capability route is selected",
          actual: "A generic route was selected",
          compensation: "The dedicated route was selected manually",
          outcome: "The requested result completed after route correction",
          "source-boundary": "route",
        }),
        "--execute",
      ]),
    );
    writeThreadRollout(codexHome, SECOND_THREAD_ID, [
      repairEvent.session_flag,
    ]);

    const monitorEvent = parseStdout(
      run([
        ...recordArgs(monitorRepo, {
          "thread-id": THIRD_THREAD_ID,
          "codex-home": codexHome,
        }),
        "--execute",
      ]),
    );
    writeThreadRollout(codexHome, THIRD_THREAD_ID, [
      monitorEvent.session_flag,
    ]);

    fs.mkdirSync(path.dirname(blockedMarker), { recursive: true });
    fs.writeFileSync(blockedMarker, "", { mode: 0o600 });
    const markerMtimes = new Map(
      [THREAD_ID, SECOND_THREAD_ID, THIRD_THREAD_ID, FOURTH_THREAD_ID].map(
        (threadId) => {
          const marker = path.join(
            codexHome,
            "capability-friction-index",
            "pending",
            threadId,
          );
          return [threadId, fs.statSync(marker).mtimeMs];
        },
      ),
    );
    const repairDocumentsBefore = fs
      .readdirSync(path.join(repairRepo, ".capability-improvements"))
      .sort();
    const monitorDocumentsBefore = fs
      .readdirSync(path.join(monitorRepo, ".capability-improvements"))
      .sort();

    const audited = parseStdout(
      run(["index-audit", "--codex-home", codexHome]),
    );
    assert.equal(audited.mode, "read_only");
    assert.equal(audited.finite_snapshot, true);
    assert.deepEqual(audited.summary, {
      audited: 4,
      close_ready: 1,
      repair_required: 1,
      monitor_required: 1,
      blocked: 1,
    });
    const classifications = Object.fromEntries(
      audited.threads.map((thread) => [
        thread.thread_id,
        thread.classification,
      ]),
    );
    assert.deepEqual(classifications, {
      [THREAD_ID]: "close_ready",
      [SECOND_THREAD_ID]: "repair_required",
      [THIRD_THREAD_ID]: "monitor_required",
      [FOURTH_THREAD_ID]: "blocked",
    });
    for (const thread of audited.threads) {
      assert.equal(thread.official_thread_read_required, true);
      assert.equal(thread.next_actions[0].type, "official_thread_read");
      assert.equal(thread.next_actions[0].required, true);
    }
    const threadsById = new Map(
      audited.threads.map((thread) => [thread.thread_id, thread]),
    );
    assert.equal(
      threadsById.get(THREAD_ID).next_actions[1].type,
      "index_close",
    );
    assert.deepEqual(
      threadsById.get(SECOND_THREAD_ID).next_actions[1].required_sequence,
      [
        "triage_execute",
        "authorized_source_repair",
        "terminal_resolution",
        "index_close",
      ],
    );
    assert.deepEqual(
      threadsById.get(THIRD_THREAD_ID).next_actions[1].required_sequence,
      ["triage_execute", "monitor_dispose", "index_close"],
    );
    assert.deepEqual(
      audited.source_repo_groups.map((group) => group.source_repo).sort(),
      [closeRepo, repairRepo, monitorRepo]
        .map((repo) => fs.realpathSync(repo))
        .sort(),
    );
    assert.equal(audited.marker_mutated, false);
    assert.equal(audited.proposals_written, false);
    assert.equal(audited.transcript_persisted, false);
    assert.equal(audited.dispatched, false);

    const selected = parseStdout(
      run([
        "index-audit",
        "--thread-id",
        SECOND_THREAD_ID,
        "--codex-home",
        codexHome,
      ]),
    );
    assert.equal(selected.selected_thread_count, 1);
    assert.equal(selected.threads[0].classification, "repair_required");

    const executeRejected = run([
      "index-audit",
      "--codex-home",
      codexHome,
      "--execute",
    ]);
    assert.notEqual(executeRejected.status, 0);
    assert.match(executeRejected.stderr, /read-only/);
    for (const [threadId, mtime] of markerMtimes) {
      const marker = path.join(
        codexHome,
        "capability-friction-index",
        "pending",
        threadId,
      );
      assert.equal(fs.statSync(marker).mtimeMs, mtime);
    }
    assert.deepEqual(
      fs
        .readdirSync(path.join(repairRepo, ".capability-improvements"))
        .sort(),
      repairDocumentsBefore,
    );
    assert.deepEqual(
      fs
        .readdirSync(path.join(monitorRepo, ".capability-improvements"))
        .sort(),
      monitorDocumentsBefore,
    );
  } finally {
    cleanup(closeRepo);
    cleanup(repairRepo);
    cleanup(monitorRepo);
    fs.rmSync(codexHome, { recursive: true, force: true });
  }
});

test("retirement isolates a cohabiting blocked repo and prevents partial marker deletion", () => {
  const retiredRepo = createRepo();
  const blockedRepo = createRepo();
  const codexHome = codexHomeFor(retiredRepo);
  const retirementReason =
    "The retired capability no longer meets the active requirements.";
  try {
    const terminalEvent = parseStdout(
      run([
        ...recordArgs(retiredRepo, {
          "thread-id": THREAD_ID,
          "codex-home": codexHome,
          "capability-id": "agentic-structciv",
          "capability-kind": "plugin",
        }),
        "--execute",
      ]),
    );
    const terminalProposal = parseStdout(
      run(["triage", "--target-cwd", retiredRepo, "--execute"]),
    ).proposals[0];
    assert.equal(terminalProposal.classification, "monitor");
    parseStdout(
      run([
        "monitor-dispose",
        "--target-cwd",
        retiredRepo,
        "--proposal-ref",
        terminalProposal.artifact_ref,
        "--execute",
      ]),
    );
    const retiredEvent = parseStdout(
      run([
        ...recordArgs(retiredRepo, {
          "thread-id": THREAD_ID,
          "codex-home": codexHome,
          "capability-id": "agentic-structciv",
          "capability-kind": "plugin",
          "repeat-key": "retired-open-event",
        }),
        "--execute",
      ]),
    );
    const missingEventId = "event-12345678901234567-acde1234";
    const blockedRoot = fs.realpathSync(blockedRepo);
    const missingArtifactRef =
      `artifact:.capability-improvements/${missingEventId}.json`;
    const missingFlag = [
      "CAPABILITY_FRICTION_DETECTED",
      `session_id: ${THREAD_ID}`,
      `event_id: ${missingEventId}`,
      "capability: generation-design-gate",
      `source_repo: ${blockedRoot}`,
      `artifact: ${missingArtifactRef}`,
      "state: pending",
    ].join("\n");
    writeThreadRollout(codexHome, THREAD_ID, [
      terminalEvent.session_flag,
      retiredEvent.session_flag,
      missingFlag,
    ]);

    const wrongCapability = run([
      "retire-dispose",
      "--target-cwd",
      retiredRepo,
      "--capability-id",
      "another-capability",
      "--event-artifact",
      retiredEvent.artifact_path,
      "--reason",
      retirementReason,
    ]);
    assert.notEqual(wrongCapability.status, 0);
    assert.match(wrongCapability.stderr, /does not belong to capability/);

    const retireArgs = [
      "retire-dispose",
      "--target-cwd",
      retiredRepo,
      "--capability-id",
      "agentic-structciv",
      "--event-artifact",
      retiredEvent.artifact_path,
      "--reason",
      retirementReason,
      "--replacement",
      "relaypress@local-plugins",
    ];
    const dryRun = parseStdout(run(retireArgs));
    assert.equal(dryRun.write_state, "planned");
    assert.equal(fs.existsSync(dryRun.artifact_path), false);

    const retired = parseStdout(run([...retireArgs, "--execute"]));
    assert.equal(retired.write_state, "created");
    assert.equal(
      retired.disposition.schema_version,
      "capability-improvement-retirement-disposition/v1",
    );
    assert.equal(
      retired.disposition.status,
      "closed_due_to_capability_retirement",
    );
    assert.equal(retired.disposition.source_changed, false);
    assert.equal(retired.disposition.repair_dispatched, false);
    assert.equal(
      parseStdout(run([...retireArgs, "--execute"])).write_state,
      "existing",
    );

    const validation = parseStdout(
      run(["validate", "--target-cwd", retiredRepo]),
    );
    assert.equal(validation.retirement_disposition_count, 1);
    const terminalTriage = parseStdout(
      run(["triage", "--target-cwd", retiredRepo]),
    );
    assert.equal(terminalTriage.all_resolved, false);
    assert.equal(terminalTriage.all_terminal, true);
    assert.deepEqual(terminalTriage.proposals, []);

    const audited = parseStdout(
      run([
        "index-audit",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
      ]),
    );
    assert.deepEqual(audited.summary, {
      audited: 1,
      close_ready: 0,
      repair_required: 0,
      monitor_required: 0,
      blocked: 1,
    });
    const thread = audited.threads[0];
    assert.equal(thread.classification, "blocked");
    assert.deepEqual(thread.active_source_repos, [blockedRoot]);
    const repositories = new Map(
      thread.repositories.map((repository) => [
        repository.source_repo,
        repository,
      ]),
    );
    const retiredRoot = fs.realpathSync(retiredRepo);
    assert.equal(repositories.get(retiredRoot).classification, "close_ready");
    assert.equal(repositories.get(retiredRoot).retirement_terminal, true);
    assert.deepEqual(repositories.get(retiredRoot).retired_event_ids, [
      retiredEvent.event.event_id,
    ]);
    assert.equal(repositories.get(blockedRoot).classification, "blocked");
    assert.match(
      repositories.get(blockedRoot).blocker.errors[0].error,
      /regular file/,
    );
    assert.deepEqual(
      audited.source_repo_groups.map((group) => group.source_repo),
      [blockedRoot],
    );

    const partialClose = run([
      "index-close",
      "--thread-id",
      THREAD_ID,
      "--event-artifact",
      retiredEvent.artifact_path,
      "--codex-home",
      codexHome,
      "--execute",
    ]);
    assert.notEqual(partialClose.status, 0);
    assert.match(partialClose.stderr, /do not exactly cover indexed thread/);
    assert.equal(
      parseStdout(
        run([
          "index-status",
          "--thread-id",
          THREAD_ID,
          "--codex-home",
          codexHome,
        ]),
      ).pending.exists,
      true,
    );
  } finally {
    cleanup(retiredRepo);
    cleanup(blockedRepo);
    fs.rmSync(codexHome, { recursive: true, force: true });
  }
});

test("central index claim and release preserve a discoverable zero-byte thread marker", () => {
  const repo = createRepo();
  try {
    parseStdout(run([...recordArgs(repo), "--execute"]));
    const codexHome = codexHomeFor(repo);

    const listed = parseStdout(
      run(["index-list", "--codex-home", codexHome]),
    );
    assert.deepEqual(listed.thread_ids, [THREAD_ID]);
    assert.equal(listed.entries[0].pending, true);
    assert.equal(listed.entries[0].processing, false);

    const claim = parseStdout(
      run([
        "index-claim",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
        "--execute",
      ]),
    );
    assert.equal(claim.claimed, true);
    assert.equal(claim.state, "claimed");

    const busy = parseStdout(
      run([
        "index-claim",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
        "--execute",
      ]),
    );
    assert.equal(busy.claimed, false);
    assert.equal(busy.state, "busy");

    parseStdout(run([...recordArgs(repo), "--execute"]));
    const duringProcessing = parseStdout(
      run(["index-status", "--thread-id", THREAD_ID, "--codex-home", codexHome]),
    );
    assert.equal(duringProcessing.pending.exists, true);
    assert.equal(duringProcessing.processing.exists, true);

    const released = parseStdout(
      run([
        "index-release",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHome,
        "--execute",
      ]),
    );
    assert.equal(released.state, "merged_to_pending");
    const afterRelease = parseStdout(
      run(["index-status", "--thread-id", THREAD_ID, "--codex-home", codexHome]),
    );
    assert.equal(afterRelease.pending.exists, true);
    assert.equal(afterRelease.processing.exists, false);
  } finally {
    cleanup(repo);
  }
});

test("legacy v1 event remains valid and triages into a thread-bound v2 proposal", () => {
  const repo = createRepo();
  try {
    const dryRun = parseStdout(run(recordArgs(repo)));
    const legacy = {
      ...dryRun.event,
      schema_version: "capability-improvement-evidence/v1",
      session_ref: THREAD_ID,
    };
    delete legacy.origin;
    const directory = path.join(repo, ".capability-improvements");
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(
      path.join(directory, `${legacy.event_id}.json`),
      `${JSON.stringify(legacy, null, 2)}\n`,
      "utf8",
    );

    const validation = parseStdout(
      run(["validate", "--target-cwd", repo]),
    );
    assert.equal(validation.event_count, 1);
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo]),
    );
    assert.equal(
      triage.proposals[0].schema_version,
      "capability-improvement-repair-plan/v2",
    );
    assert.deepEqual(triage.proposals[0].thread_ids, [THREAD_ID]);
  } finally {
    cleanup(repo);
  }
});

test("central index rejects nonzero or non-UUID durable entries", () => {
  const repo = createRepo();
  try {
    const pending = path.join(
      codexHomeFor(repo),
      "capability-friction-index",
      "pending",
    );
    fs.mkdirSync(pending, { recursive: true });
    fs.writeFileSync(path.join(pending, THREAD_ID), "details are forbidden", "utf8");
    const nonzero = run(["index-list", "--codex-home", codexHomeFor(repo)]);
    assert.notEqual(nonzero.status, 0);
    assert.match(nonzero.stderr, /zero-byte regular file/);

    fs.rmSync(path.join(pending, THREAD_ID));
    fs.writeFileSync(path.join(pending, "not-a-thread-id"), "", "utf8");
    const invalidName = run(["index-list", "--codex-home", codexHomeFor(repo)]);
    assert.notEqual(invalidName.status, 0);
    assert.match(invalidName.stderr, /Unexpected central index entry/);
  } finally {
    cleanup(repo);
  }
});

test("app-state-resolve creates immutable terminal evidence and index-close accepts it", () => {
  const fixture = createAppStateRepairFixture();
  try {
    const originalState = fs.readFileSync(fixture.absoluteStatePath, "utf8");
    const dryRun = parseStdout(run(appStateResolveArgs(fixture)));
    assert.equal(dryRun.write_state, "planned");
    assert.equal(dryRun.state_mutated, false);
    assert.equal(fs.existsSync(dryRun.artifact_path), false);
    assert.equal(
      fs.readFileSync(fixture.absoluteStatePath, "utf8"),
      originalState,
    );

    const resolveArgs = [...appStateResolveArgs(fixture), "--execute"];
    const resolved = parseStdout(run(resolveArgs));
    assert.equal(resolved.write_state, "created");
    assert.equal(
      resolved.resolution.schema_version,
      "capability-improvement-app-state-resolution/v1",
    );
    assert.equal(
      resolved.resolution.status,
      "closed_after_app_state_repair",
    );
    assert.equal(resolved.resolution.state.surface, "codex_automation");
    assert.equal(resolved.resolution.state.path, fixture.statePath);
    assert.equal(
      resolved.resolution.state.after_sha256,
      fixture.afterSha256,
    );
    assert.deepEqual(resolved.resolution.source_control, {
      required: false,
      reason: "app_managed_ignored_untracked_state",
    });
    assert.deepEqual(resolved.resolution.repair_execution, {
      route: "direct",
      execution_id: fixture.executionId,
      authority_ref: "role:user-request:repair-authorized",
      evidence_refs: ["test:repair-execution-automation result:pass"],
    });
    assert.equal(resolved.state_mutated, false);
    assert.equal(resolved.marker_deleted, false);
    assert.equal(parseStdout(run(resolveArgs)).write_state, "existing");
    assert.equal(
      fs.readFileSync(fixture.absoluteStatePath, "utf8"),
      originalState,
    );

    fs.writeFileSync(
      fixture.absoluteStatePath,
      `${originalState}last_readback = "later"\n`,
      "utf8",
    );
    const validated = parseStdout(
      run(["validate", "--target-cwd", fixture.repo]),
    );
    assert.equal(validated.app_state_resolution_count, 1);
    const doctor = parseStdout(
      run(["doctor", "--target-cwd", fixture.repo]),
    );
    assert.equal(doctor.app_state_resolution_count, 1);
    const terminalTriage = parseStdout(
      run(["triage", "--target-cwd", fixture.repo]),
    );
    assert.equal(terminalTriage.all_resolved, true);
    assert.equal(terminalTriage.all_terminal, true);
    assert.deepEqual(terminalTriage.proposals, []);
    writeThreadRollout(codexHomeFor(fixture.repo), THREAD_ID, [
      fixture.recorded.session_flag,
    ]);

    const close = parseStdout(
      run([
        "index-close",
        "--thread-id",
        THREAD_ID,
        "--event-artifact",
        fixture.recorded.artifact_path,
        "--codex-home",
        codexHomeFor(fixture.repo),
        "--execute",
      ]),
    );
    assert.equal(close.state, "closed");
  } finally {
    cleanup(fixture.repo);
  }
});

test("app-state-resolve rejects tracked and nonignored state", () => {
  const trackedFixture = createAppStateRepairFixture();
  try {
    git(trackedFixture.repo, ["add", "-f", trackedFixture.statePath]);
    const tracked = run(appStateResolveArgs(trackedFixture));
    assert.notEqual(tracked.status, 0);
    assert.match(tracked.stderr, /must be untracked by Git/);
  } finally {
    cleanup(trackedFixture.repo);
  }

  const nonignoredFixture = createAppStateRepairFixture({ ignored: false });
  try {
    const nonignored = run(appStateResolveArgs(nonignoredFixture));
    assert.notEqual(nonignored.status, 0);
    assert.match(nonignored.stderr, /must be Git-ignored/);
  } finally {
    cleanup(nonignoredFixture.repo);
  }
});

test("app-state-resolve requires app or workflow lineage and valid repair execution evidence", () => {
  const wrongKindFixture = createAppStateRepairFixture({
    capabilityKind: "skill",
  });
  try {
    const wrongKind = run(appStateResolveArgs(wrongKindFixture));
    assert.notEqual(wrongKind.status, 0);
    assert.match(wrongKind.stderr, /workflow or app capability kind/);
  } finally {
    cleanup(wrongKindFixture.repo);
  }

  const invalidRouteFixture = createAppStateRepairFixture();
  try {
    const missingEvidence = run(
      appStateResolveArgs(invalidRouteFixture, {
        "execution-evidence": [],
      }),
    );
    assert.notEqual(missingEvidence.status, 0);
    assert.match(missingEvidence.stderr, /execution-evidence must contain between 1 and 64 items/);

    const implicitCao = run(
      appStateResolveArgs(invalidRouteFixture, {
        "execution-route": "coding-agent-orchestrator",
        "execution-authority": "role:user-request:repair-authorized",
      }),
    );
    assert.notEqual(implicitCao.status, 0);
    assert.match(implicitCao.stderr, /explicit CAO authority evidence/);

    const explicitCao = parseStdout(
      run(
        appStateResolveArgs(invalidRouteFixture, {
          "execution-route": "coding-agent-orchestrator",
          "execution-authority": "role:user-request:CAO-explicitly-selected",
        }),
      ),
    );
    assert.equal(
      explicitCao.resolution.repair_execution.route,
      "coding-agent-orchestrator",
    );
  } finally {
    cleanup(invalidRouteFixture.repo);
  }
});

test("app-state-resolve rejects malformed, mismatched, traversal, and symlink paths", () => {
  const fixture = createAppStateRepairFixture();
  try {
    const invalidSurface = run(
      appStateResolveArgs(fixture, { "state-surface": "other" }),
    );
    assert.notEqual(invalidSurface.status, 0);
    assert.match(invalidSurface.stderr, /state-surface must be codex_automation/);

    const malformedResource = run(
      appStateResolveArgs(fixture, {
        "resource-id": "../automation-123",
        "state-path": "automations/../automation-123/automation.toml",
      }),
    );
    assert.notEqual(malformedResource.status, 0);
    assert.match(malformedResource.stderr, /safe automation path segment/);

    const mismatched = run(
      appStateResolveArgs(fixture, {
        "state-path": "automations/other/automation.toml",
      }),
    );
    assert.notEqual(mismatched.status, 0);
    assert.match(mismatched.stderr, /state-path must be exactly/);

    const traversal = run(
      appStateResolveArgs(fixture, {
        "state-path":
          `automations/${fixture.resourceId}/../automation.toml`,
      }),
    );
    assert.notEqual(traversal.status, 0);
    assert.match(traversal.stderr, /state-path must be exactly/);

    const outside = path.join(fixture.repo, "outside-automation.toml");
    fs.writeFileSync(outside, fixture.afterContent, "utf8");
    fs.unlinkSync(fixture.absoluteStatePath);
    fs.symlinkSync(
      path.relative(path.dirname(fixture.absoluteStatePath), outside),
      fixture.absoluteStatePath,
    );
    const symlink = run(appStateResolveArgs(fixture));
    assert.notEqual(symlink.status, 0);
    assert.match(symlink.stderr, /must not contain a symlink component/);
  } finally {
    cleanup(fixture.repo);
  }
});

test("app-state-resolve rejects extra candidates, stale observations, and invalid hashes", () => {
  const extraCandidateFixture = createAppStateRepairFixture({
    extraCandidates: ["src/unrelated.js"],
  });
  try {
    const extraCandidate = run(appStateResolveArgs(extraCandidateFixture));
    assert.notEqual(extraCandidate.status, 0);
    assert.match(extraCandidate.stderr, /candidate_files must contain exactly/);
  } finally {
    cleanup(extraCandidateFixture.repo);
  }

  const fixture = createAppStateRepairFixture();
  try {
    const staleObservation = run(
      appStateResolveArgs(fixture, {
        "observed-at": new Date(
          Date.parse(fixture.proposalCreatedAt) - 1,
        ).toISOString(),
      }),
    );
    assert.notEqual(staleObservation.status, 0);
    assert.match(staleObservation.stderr, /must not predate/);

    const equalHashes = run(
      appStateResolveArgs(fixture, {
        "before-sha256": fixture.afterSha256,
      }),
    );
    assert.notEqual(equalHashes.status, 0);
    assert.match(equalHashes.stderr, /must differ/);

    const wrongHash = run(
      appStateResolveArgs(fixture, {
        "after-sha256": "f".repeat(64),
      }),
    );
    assert.notEqual(wrongHash.status, 0);
    assert.match(wrongHash.stderr, /must equal the current/);

    const malformedHash = run(
      appStateResolveArgs(fixture, {
        "after-sha256": "not-a-sha",
      }),
    );
    assert.notEqual(malformedHash.status, 0);
    assert.match(malformedHash.stderr, /64-hex SHA-256/);
  } finally {
    cleanup(fixture.repo);
  }
});

test("app-state-resolve requires successful operation and complete typed evidence", () => {
  const fixture = createAppStateRepairFixture();
  try {
    const invalidOperation = run(
      appStateResolveArgs(fixture, {
        "operation-evidence": "test:other-operation result:pass",
      }),
    );
    assert.notEqual(invalidOperation.status, 0);
    assert.match(invalidOperation.stderr, /must name codex_app\.automation_update/);

    const failedOperation = run(
      appStateResolveArgs(fixture, {
        "operation-evidence":
          "test:codex_app.automation_update result:fail",
      }),
    );
    assert.notEqual(failedOperation.status, 0);
    assert.match(failedOperation.stderr, /must prove a successful/);

    for (const missing of [
      "changed-field",
      "preserved-field",
      "readback-evidence",
      "invariant-evidence",
      "verification",
    ]) {
      const result = run(appStateResolveArgs(fixture, { [missing]: [] }));
      assert.notEqual(result.status, 0, `missing --${missing} must fail`);
      assert.match(result.stderr, /must contain between 1 and 64 items/);
    }

    const missingOperation = run(
      appStateResolveArgs(fixture, { "operation-evidence": "" }),
    );
    assert.notEqual(missingOperation.status, 0);
    assert.match(missingOperation.stderr, /must be a non-empty string/);

    const untypedReadback = run(
      appStateResolveArgs(fixture, {
        "readback-evidence": ["read it back"],
      }),
    );
    assert.notEqual(untypedReadback.status, 0);
    assert.match(untypedReadback.stderr, /not a capability-auditor-compatible/);
  } finally {
    cleanup(fixture.repo);
  }
});

test("handoff, large immutable resolution, and index-close form one evidence-gated lifecycle", () => {
  const repo = createRepo();
  const executionId = "repair-sample-skill";
  try {
    const recorded = parseStdout(
      run([
        ...recordArgs(repo, {
          category: "validator_gap",
          summary: "Validator omitted a required contract check",
          expected: "Validator rejects the invalid shape",
          actual: "Validator accepted the invalid shape",
          compensation: "Inspected the result manually",
          outcome: "The invalid result was stopped before use",
          "source-boundary": "validator",
        }),
        "--execute",
      ]),
    );
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    const proposalRef = triage.proposals[0].artifact_ref;

    const handoff = parseStdout(
      run([
        "handoff-check",
        "--target-cwd",
        repo,
        "--proposal-ref",
        proposalRef,
        ...repairExecutionArgs(null, { includeEvidence: false }),
      ]),
    );
    assert.equal(handoff.handoff_ready, true);
    assert.equal(handoff.dispatched, false);
    assert.equal(handoff.repair_handoff.route, "direct");
    writeThreadRollout(codexHomeFor(repo), THREAD_ID, [
      recorded.session_flag,
    ]);

    const closeBeforeResolution = run([
      "index-close",
      "--thread-id",
      THREAD_ID,
      "--event-artifact",
      recorded.artifact_path,
      "--codex-home",
      codexHomeFor(repo),
      "--execute",
    ]);
    assert.notEqual(closeBeforeResolution.status, 0);
    assert.match(
      closeBeforeResolution.stderr,
      /unresolved or undisposed events/,
    );
    assert.equal(
      parseStdout(
        run([
          "index-status",
          "--thread-id",
          THREAD_ID,
          "--codex-home",
          codexHomeFor(repo),
        ]),
      ).pending.exists,
      true,
    );

    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    const repairFiles = [
      "src/parser.js",
      ...Array.from(
        { length: 64 },
        (_, index) => `src/contract-${String(index + 1).padStart(2, "0")}.js`,
      ),
    ];
    for (const repairFile of repairFiles) {
      fs.writeFileSync(
        path.join(repo, repairFile),
        "export const contractIsEnforced = true;\n",
        "utf8",
      );
    }
    git(repo, ["config", "user.name", "Capability Test"]);
    git(repo, ["config", "user.email", "capability-test@example.invalid"]);
    git(repo, ["add", ...repairFiles]);
    git(repo, ["commit", "--quiet", "-m", "Repair parser contract"]);
    const commit = git(repo, ["rev-parse", "HEAD"]);

    const resolveWithoutExecutionEvidence = run([
      "resolve",
      "--target-cwd",
      repo,
      "--proposal-ref",
      proposalRef,
      ...repairExecutionArgs(executionId, { includeEvidence: false }),
      "--root-cause",
      "The validator omitted the declared shape check.",
      "--commit",
      commit,
      ...repairFiles.flatMap((repairFile) => ["--changed-file", repairFile]),
      "--verification",
      "test:parser-contract result:pass",
      "--refresh-status",
      "not_applicable",
      "--execute",
    ]);
    assert.notEqual(resolveWithoutExecutionEvidence.status, 0);
    assert.match(
      resolveWithoutExecutionEvidence.stderr,
      /execution-evidence must contain between 1 and 64 items/,
    );

    const resolveArgs = [
      "resolve",
      "--target-cwd",
      repo,
      "--proposal-ref",
      proposalRef,
      ...repairExecutionArgs(executionId),
      "--root-cause",
      "The validator omitted the declared shape check.",
      "--commit",
      commit,
      ...repairFiles.flatMap((repairFile) => ["--changed-file", repairFile]),
      "--verification",
      "test:parser-contract result:pass",
      "--refresh-status",
      "not_applicable",
      "--execute",
    ];
    const resolved = parseStdout(run(resolveArgs));
    assert.equal(resolved.resolution.status, "closed");
    assert.deepEqual(resolved.resolution.source_control, {
      commit,
      commit_mode: "head",
      head_verified: true,
      verified_head: commit,
    });
    assert.deepEqual(resolved.resolution.changed_files, [...repairFiles].sort());
    assert.deepEqual(resolved.resolution.refresh, {
      status: "not_applicable",
      evidence_ref: null,
    });
    assert.equal(resolved.write_state, "created");
    assert.equal(resolved.marker_deleted, false);
    assert.equal(parseStdout(run(resolveArgs)).write_state, "existing");

    const validated = parseStdout(
      run(["validate", "--target-cwd", repo]),
    );
    assert.equal(validated.resolution_count, 1);
    const afterResolutionTriage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    assert.equal(afterResolutionTriage.all_resolved, true);
    assert.deepEqual(afterResolutionTriage.proposals, []);

    const close = parseStdout(
      run([
        "index-close",
        "--thread-id",
        THREAD_ID,
        "--event-artifact",
        recorded.artifact_path,
        "--codex-home",
        codexHomeFor(repo),
        "--execute",
      ]),
    );
    assert.equal(close.state, "closed");
    const status = parseStdout(
      run([
        "index-status",
        "--thread-id",
        THREAD_ID,
        "--codex-home",
        codexHomeFor(repo),
      ]),
    );
    assert.equal(status.pending.exists, false);
    assert.equal(status.processing.exists, false);

    const closeAgain = parseStdout(
      run([
        "index-close",
        "--thread-id",
        THREAD_ID,
        "--event-artifact",
        recorded.artifact_path,
        "--codex-home",
        codexHomeFor(repo),
        "--execute",
      ]),
    );
    assert.equal(closeAgain.state, "already_absent");
  } finally {
    cleanup(repo);
  }
});

test("resolve reconciles an already-landed ancestor repair without binding an unrelated HEAD", () => {
  const repo = createRepo();
  const executionId = "repair-already-landed-sample-skill";
  try {
    const recorded = parseStdout(
      run([
        ...recordArgs(repo, {
          category: "contract_mismatch",
          summary: "A source contract mismatch was repaired before its thorn was closed",
          expected: "The repaired source and thorn lifecycle close together",
          actual: "The repair landed, but a later commit became HEAD before resolution",
          compensation: "Revalidated the exact historical repair and current HEAD",
          outcome: "The repaired behavior remains current and needs terminal evidence",
          repeatability: "reproduced",
          severity: "high",
          "source-boundary": "source",
        }),
        "--execute",
      ]),
    );
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    const proposalRef = triage.proposals[0].artifact_ref;

    git(repo, ["config", "user.name", "Capability Test"]);
    git(repo, ["config", "user.email", "capability-test@example.invalid"]);
    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(repo, "src", "parser.js"),
      "export const repairedContract = true;\n",
      "utf8",
    );
    git(repo, ["add", "src/parser.js"]);
    git(repo, ["commit", "--quiet", "-m", "Repair the reported contract"]);
    const repairCommit = git(repo, ["rev-parse", "HEAD"]);

    fs.mkdirSync(path.join(repo, "docs"), { recursive: true });
    fs.writeFileSync(
      path.join(repo, "docs", "later.txt"),
      "A later, unrelated committed change.\n",
      "utf8",
    );
    git(repo, ["add", "docs/later.txt"]);
    git(repo, ["commit", "--quiet", "-m", "Add later documentation"]);
    const verifiedHead = git(repo, ["rev-parse", "HEAD"]);

    const commonResolveArgs = [
      "resolve",
      "--target-cwd",
      repo,
      "--proposal-ref",
      proposalRef,
      ...repairExecutionArgs(executionId),
      "--root-cause",
      "The repair completed before the evidence lifecycle reached resolution.",
      "--commit",
      repairCommit,
      "--changed-file",
      "src/parser.js",
      "--verification",
      "test:parser-contract result:pass",
      "--refresh-status",
      "passed",
      "--refresh-evidence",
      "command:official-discovery exit:0",
      "--execute",
    ];
    const strictHead = run(commonResolveArgs);
    assert.notEqual(strictHead.status, 0);
    assert.match(strictHead.stderr, /--commit-mode ancestor is explicit/);

    const commitIndex = commonResolveArgs.indexOf("--commit");
    const ancestorResolveArgs = [...commonResolveArgs];
    ancestorResolveArgs.splice(
      commitIndex + 2,
      0,
      "--commit-mode",
      "ancestor",
    );
    const resolved = parseStdout(run(ancestorResolveArgs));
    assert.deepEqual(resolved.resolution.source_control, {
      commit: repairCommit,
      commit_mode: "ancestor",
      head_verified: true,
      verified_head: verifiedHead,
    });
    assert.deepEqual(resolved.resolution.changed_files, ["src/parser.js"]);

    const validated = parseStdout(
      run(["validate", "--target-cwd", repo]),
    );
    assert.equal(validated.resolution_count, 1);
    writeThreadRollout(codexHomeFor(repo), THREAD_ID, [
      recorded.session_flag,
    ]);
    const close = parseStdout(
      run([
        "index-close",
        "--thread-id",
        THREAD_ID,
        "--event-artifact",
        recorded.artifact_path,
        "--codex-home",
        codexHomeFor(repo),
        "--execute",
      ]),
    );
    assert.equal(close.state, "closed");
  } finally {
    cleanup(repo);
  }
});

test("resolve terminalizes legacy evidence recorded after its repair already landed", () => {
  const repo = createRepo();
  const executionId = "terminalize-preexisting-repair";
  try {
    git(repo, ["config", "user.name", "Capability Test"]);
    git(repo, ["config", "user.email", "capability-test@example.invalid"]);
    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    fs.writeFileSync(
      path.join(repo, "src", "controller.js"),
      "export const terminalActionIsVisible = true;\n",
      "utf8",
    );
    git(repo, ["add", "src/controller.js"]);
    gitWithEnv(
      repo,
      ["commit", "--quiet", "-m", "Repair terminal continuation"],
      {
        GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z",
        GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
      },
    );
    const repairCommit = git(repo, ["rev-parse", "HEAD"]);

    const recorded = parseStdout(
      run([
        ...recordArgs(repo, {
          category: "repeated_manual_repair",
          summary: "The terminal repair completed before its thorn was recorded",
          expected: "A completed repair receives terminal evidence",
          actual: "The source was fixed but the evidence lifecycle remained open",
          compensation: "Revalidated the landed repair and recorded its exact root cause",
          outcome: "The intended terminal path is complete",
          "root-cause":
            "The controller classified expected pre-completion receipts as failures.",
          repeatability: "reproduced",
          severity: "high",
          "source-boundary": "source",
          "candidate-file": ["src/controller.js"],
          verification: ["test:terminal-controller result:pass"],
        }),
        "--execute",
      ]),
    );
    const triage = parseStdout(
      run(["triage", "--target-cwd", repo, "--execute"]),
    );
    const proposalRef = triage.proposals[0].artifact_ref;

    const commonArgs = [
      "resolve",
      "--target-cwd",
      repo,
      "--proposal-ref",
      proposalRef,
      ...repairExecutionArgs(executionId),
      "--root-cause",
      "The repair was committed before the legacy evidence record was created.",
      "--commit",
      repairCommit,
      "--changed-file",
      "src/controller.js",
      "--verification",
      "test:terminal-controller result:pass",
      "--refresh-status",
      "passed",
      "--refresh-evidence",
      "command:official-discovery exit:0",
      "--execute",
    ];
    const defaultMode = run(commonArgs);
    assert.notEqual(defaultMode.status, 0);
    assert.match(defaultMode.stderr, /Repair commit predates/);

    const commitIndex = commonArgs.indexOf("--commit");
    const preexistingArgs = [...commonArgs];
    preexistingArgs.splice(
      commitIndex + 2,
      0,
      "--commit-mode",
      "preexisting",
    );
    const resolved = parseStdout(run(preexistingArgs));
    assert.equal(resolved.resolution.source_control.commit_mode, "preexisting");
    assert.equal(
      resolved.resolution.source_control.verified_head,
      repairCommit,
    );
    assert.equal(
      resolved.resolution.resolved_at,
      triage.proposals[0].created_at,
    );
    assert.equal(
      parseStdout(run(["validate", "--target-cwd", repo])).resolution_count,
      1,
    );
    writeThreadRollout(codexHomeFor(repo), THREAD_ID, [
      recorded.session_flag,
    ]);
    assert.equal(
      parseStdout(
        run([
          "index-close",
          "--thread-id",
          THREAD_ID,
          "--event-artifact",
          recorded.artifact_path,
          "--codex-home",
          codexHomeFor(repo),
          "--execute",
        ]),
      ).state,
      "closed",
    );
  } finally {
    cleanup(repo);
  }
});

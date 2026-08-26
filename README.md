# audit-capability-improvements-public

## 日本語

### 何をするか

中央の capability-friction index にある観測済みの実行摩擦を、リポジトリ単位で監査し、修復候補、監視、廃止、終端処理、クローズを分類します。判定は同梱CLIとスキーマが担当します。

### 発火・経路・境界

- 発火: 「capability frictionを監査」「中央インデックスを巡回」「修復候補やobsolete capabilityを整理」など。
- 主経路: `scripts/capability-improvement.mjs` を使い、`index-audit`、必要時に `triage` / `monitor-dispose` / `retire-dispose` / `index-close` を明示的に実行します。
- 非使用: 通常のコードレビュー、想像上の不具合、未承認の修復、ログやセッション本文の保存、キャッシュを正本とする操作。
- 不明なthread identity、壊れたartifact、曖昧なsource root、検証不能な証拠では停止し、markerを勝手に削除しません。

### 入出力・使用例

入力は、観測済みの固定形式イベント、対象source repository、読み取り専用のthread evidenceです。出力は構造化された監査結果、repository group、次の許可された操作、またはblockerです。実行前にCLIの `--help` とホストのCodex thread-read機能を確認してください。

```bash
node scripts/capability-improvement.mjs index-audit
```

skillディレクトリをCodexのユーザーskill領域へ配置し、新しいタスクで次を呼び出します。

```text
Use $audit-capability-improvements-public to audit the capability-friction index.
```

### 制限とidentity

内部版の完全なバイト互換ではない別identityの公開adaptationです。ユーザー固有の正本パス、内部ポリシー、session本文、認証情報、runtime/cache artifactsは公開物に含めません。CLIはNode.jsとホスト側のCodex thread-read境界に依存し、外部公開・commit・install・activationを自動で行いません。

### License

MIT License。詳細は `LICENSE` を参照してください。

## English

### What it does

`audit-capability-improvements-public` audits observed capability friction from a central index, groups it by repository, and classifies repair, monitoring, retirement, terminal disposition, or closure. The bundled CLI and schemas own executable decisions.

### Triggers, route, and boundaries

- Triggers: “audit capability friction,” “inspect the central index,” or “organize repair candidates and obsolete capabilities.”
- Primary route: run `scripts/capability-improvement.mjs` with `index-audit`, then explicitly use `triage`, `monitor-dispose`, `retire-dispose`, or `index-close` when authorized.
- Do not use it for ordinary code review, hypothetical failures, unauthorized repairs, transcript storage, or treating cache as source.
- Stop on unknown thread identity, malformed artifacts, ambiguous source roots, or unverifiable evidence; never delete a marker by inference.

### Inputs, outputs, and use

Inputs are fixed-format observed events, an affected source repository, and read-only thread evidence. Outputs are structured audit results, repository groups, authorized next actions, or blockers. Check the CLI `--help` and the host's official thread-read capability before running it.

```bash
node scripts/capability-improvement.mjs index-audit
```

Install the skill in the host's user skill directory and start a fresh task:

```text
Use $audit-capability-improvements-public to audit the capability-friction index.
```

### Limitations and identity

This is a separately named public adaptation, not a byte-identical copy of the private implementation. Maintainer-specific source paths, internal policy text, session bodies, credentials, and runtime/cache artifacts are excluded. The CLI requires Node.js and the host's official Codex thread-read boundary; it does not publish, commit, install, or activate anything automatically.

### License

MIT License; see `LICENSE`.

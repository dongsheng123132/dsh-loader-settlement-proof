# dsh-loader-settlement-proof

**Maintainer / Author：He Fangsheng (贺方升 / 贺去病; Dosen) · [hequbing.com](https://www.hequbing.com)**

An offline evidence layer for recorded DeepSeek Harness Loader settlement. It verifies a fixed, body-free receipt for:

- subject DSH revision and Loader contract binding;
- the ordered `declared → resolved → loaded → activated` lifecycle;
- enabled/required entry activation and classified failures;
- requested versus resolved injections;
- required tool names and their schema SHA-256 receipts;
- duplicate entries, phases, tools, and cross-entry tool collisions.

It emits deterministic, content-addressed JSON. The DSH tools/CLI can publish only beneath an explicit `artifactDir` and verify the bytes after publication. MCP is inline-only.

## Deliberate boundary

This is not another Loader. DSH `app-boot` already enforces live `assertEntriesLoaded` and `assertEntriesActivated`; `dsh-reloader` restarts a surface, `dsh-builtin-toggles` changes an allowlisted UI subset, `dsh-profile-lock-proof` proves installed composition, and the Awesome runtime matrix performs real cross-platform boots. This plugin verifies a producer-supplied, revision-bound settlement receipt for later audit. It never imports, runs, reloads, or toggles a recorded plugin and never accepts raw logs, stack traces, output, business bodies, or secrets.

## Usage

```sh
dsh plugin --profile web add github:dongsheng123132/dsh-loader-settlement-proof#<commit>
dsh-loader-settlement-proof inspect examples/settlement.json
dsh-loader-settlement-proof verify examples/settlement.json artifacts
```

DSH tools: `dsh_loader_settlement_inspect`, `dsh_loader_settlement_verify`.

MCP tools: `loader_settlement_inspect_inline`, `loader_settlement_verify_inline`.

## Verification

```sh
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

`verified` means the receipt is internally consistent with its explicit policy. It is not a security certification and cannot prove that the receipt producer observed the live Loader honestly.

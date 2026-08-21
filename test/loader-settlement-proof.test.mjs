import assert from 'node:assert/strict'
import test from 'node:test'
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { inspectSettlementInline, verifySettlementInline, verifySettlement } from '../lib/loader-settlement-proof.mjs'

const source = await readFile(new URL('../examples/settlement.json', import.meta.url), 'utf8')
const fixture = () => JSON.parse(source)
const codes = report => report.findings.map(finding => finding.code)

test('verifies a complete settlement and produces deterministic hashes', () => {
  const first = verifySettlementInline({ settlementJson: source }), second = verifySettlementInline({ settlementJson: source })
  assert.equal(first.status, 'verified'); assert.equal(first.summary.activated, 1); assert.equal(first.summary.tools, 1)
  assert.equal(first.reportSha256, second.reportSha256); assert.equal(first.executesPlugins, false)
})

test('rejects incomplete phase chains and non-monotonic sequence', () => {
  const value = fixture(); value.entries[0].events.splice(2, 1); value.entries[0].events[2].seq = 1
  const report = verifySettlementInline({ settlementJson: JSON.stringify(value) })
  assert.equal(report.status, 'rejected'); assert.ok(codes(report).includes('PHASE_CHAIN_INCOMPLETE')); assert.ok(codes(report).includes('EVENT_ORDER_INVALID'))
})

test('rejects unresolved requested injections', () => {
  const value = fixture(); value.entries[0].injectResolved = []
  const report = verifySettlementInline({ settlementJson: JSON.stringify(value) })
  assert.ok(codes(report).includes('INJECTION_UNRESOLVED')); assert.equal(report.entries[0].unresolvedInject[0], 'tools')
})

test('rejects stale DSH revision and tool schema mismatch', () => {
  const value = fixture(); value.policy.expectedDshRevisionSha256 = 'a'.repeat(64); value.policy.requiredTools[0].schemaSha256 = 'c'.repeat(64)
  const report = verifySettlementInline({ settlementJson: JSON.stringify(value) })
  assert.ok(codes(report).includes('DSH_REVISION_MISMATCH')); assert.ok(codes(report).includes('TOOL_SCHEMA_MISMATCH'))
})

test('requires classified non-activated terminal states', () => {
  const value = fixture(); value.entries[0].terminal.status = 'failed'; value.entries[0].terminal.failureClass = 'none'; value.entries[0].tools = []
  const report = verifySettlementInline({ settlementJson: JSON.stringify(value) })
  assert.ok(codes(report).includes('ENTRY_NOT_ACTIVATED')); assert.ok(codes(report).includes('FAILURE_CLASS_MISSING')); assert.ok(codes(report).includes('REQUIRED_TOOL_MISSING'))
})

test('rejects raw output and secret-shaped fields recursively', () => {
  const output = fixture(); output.entries[0].terminal.stdout = 'raw'
  assert.throws(() => verifySettlementInline({ settlementJson: JSON.stringify(output) }), error => error.code === 'FORBIDDEN_FIELD')
  const secret = fixture(); secret.entries[0].token = 'hidden'
  assert.throws(() => verifySettlementInline({ settlementJson: JSON.stringify(secret) }), error => error.code === 'FORBIDDEN_FIELD')
})

test('inspection is proof-only and body-free', () => {
  const result = inspectSettlementInline({ settlementJson: source })
  assert.equal(result.entries, 1); assert.equal(result.readsBusinessBodies, false); assert.equal(result.executesPlugins, false); assert.equal(result.filesystemAccess, false)
})

test('file verifier publishes a replay-safe read-back-verified artifact', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-loader-proof-'))
  try { await cp(new URL('../examples/', import.meta.url), root, { recursive: true }); const first = await verifySettlement({ workspaceRoot: root, settlementPath: 'settlement.json', artifactDir: 'artifacts' }), second = await verifySettlement({ workspaceRoot: root, settlementPath: 'settlement.json', artifactDir: 'artifacts' }); assert.equal(first.status, 'verified'); assert.equal(first.artifact.verifiedByReadBack, true); assert.equal(first.artifact.path, second.artifact.path); assert.match(await readFile(path.join(root, first.artifact.path), 'utf8'), /"status": "verified"/) } finally { await rm(root, { recursive: true, force: true }) }
})

test('rejects workspace traversal', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'dsh-loader-proof-'))
  try { await assert.rejects(verifySettlement({ workspaceRoot: root, settlementPath: '../outside.json', artifactDir: 'artifacts' }), error => error.code === 'UNSAFE_PATH') } finally { await rm(root, { recursive: true, force: true }) }
})

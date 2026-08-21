import { createHash, randomUUID } from 'node:crypto'
import { lstat, realpath, readFile, mkdir, writeFile, link, unlink } from 'node:fs/promises'
import path from 'node:path'

const MAX_BYTES = 262_144
const MAX_ITEMS = 128
const HASH = /^[a-f0-9]{64}$/
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/
const FORBIDDEN_KEYS = /^(authorization|secret|token|password|credential|content|text|prompt|message|payload|body|output|stdout|stderr|stack|error)$/i
const PHASES = ['declared', 'resolved', 'loaded', 'activated']

export class LoaderSettlementError extends Error {
  constructor(code, message) { super(message); this.name = 'LoaderSettlementError'; this.code = code }
}

const digest = value => createHash('sha256').update(value).digest('hex')
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value
const stableJson = value => `${JSON.stringify(canonical(value), null, 2)}\n`
const plain = value => value && typeof value === 'object' && !Array.isArray(value)

function object(value, label, allowed, required = allowed) {
  if (!plain(value)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label} must be an object`)
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.${key} is not allowed`)
  for (const key of required) if (!(key in value)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.${key} is required`)
}
function identifier(value, label) { if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label} must be a bounded identifier`) }
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label} must be a lowercase SHA-256`) }
function list(value, label) { if (!Array.isArray(value) || value.length > MAX_ITEMS) throw new LoaderSettlementError('INVALID_MANIFEST', `${label} must be a bounded array`) }
function identifierList(value, label) { list(value, label); for (let i = 0; i < value.length; i++) identifier(value[i], `${label}[${i}]`) }
function scan(value, location = '$') {
  if (Array.isArray(value)) return value.forEach((item, index) => scan(item, `${location}[${index}]`))
  if (!plain(value)) return
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.test(key)) throw new LoaderSettlementError('FORBIDDEN_FIELD', `${location}.${key} may contain business data or secrets`)
    scan(child, `${location}.${key}`)
  }
}

function validate(value) {
  scan(value)
  object(value, '$', ['schemaVersion', 'subject', 'policy', 'entries'])
  if (value.schemaVersion !== 1) throw new LoaderSettlementError('INVALID_MANIFEST', 'schemaVersion must be 1')
  object(value.subject, 'subject', ['profileId', 'dshRevisionSha256', 'loaderContractVersion'])
  identifier(value.subject.profileId, 'subject.profileId'); hash(value.subject.dshRevisionSha256, 'subject.dshRevisionSha256'); identifier(value.subject.loaderContractVersion, 'subject.loaderContractVersion')
  object(value.policy, 'policy', ['expectedDshRevisionSha256', 'requiredEntryIds', 'requiredTools', 'requireAllEnabledActivated'])
  hash(value.policy.expectedDshRevisionSha256, 'policy.expectedDshRevisionSha256'); identifierList(value.policy.requiredEntryIds, 'policy.requiredEntryIds')
  if (typeof value.policy.requireAllEnabledActivated !== 'boolean') throw new LoaderSettlementError('INVALID_MANIFEST', 'policy.requireAllEnabledActivated must be boolean')
  list(value.policy.requiredTools, 'policy.requiredTools')
  for (let i = 0; i < value.policy.requiredTools.length; i++) { const tool = value.policy.requiredTools[i]; object(tool, `policy.requiredTools[${i}]`, ['name', 'schemaSha256']); identifier(tool.name, `policy.requiredTools[${i}].name`); hash(tool.schemaSha256, `policy.requiredTools[${i}].schemaSha256`) }
  list(value.entries, 'entries'); if (!value.entries.length) throw new LoaderSettlementError('INVALID_MANIFEST', 'entries must not be empty')
  for (let i = 0; i < value.entries.length; i++) {
    const entry = value.entries[i], label = `entries[${i}]`
    object(entry, label, ['entryId', 'moduleName', 'enabled', 'injectRequested', 'injectResolved', 'events', 'terminal', 'tools'])
    identifier(entry.entryId, `${label}.entryId`); identifier(entry.moduleName, `${label}.moduleName`)
    if (typeof entry.enabled !== 'boolean') throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.enabled must be boolean`)
    identifierList(entry.injectRequested, `${label}.injectRequested`); identifierList(entry.injectResolved, `${label}.injectResolved`)
    list(entry.events, `${label}.events`)
    for (let j = 0; j < entry.events.length; j++) { const event = entry.events[j]; object(event, `${label}.events[${j}]`, ['phase', 'seq', 'evidenceSha256']); if (!PHASES.includes(event.phase)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.events[${j}].phase is unknown`); if (!Number.isSafeInteger(event.seq) || event.seq < 0) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.events[${j}].seq must be a non-negative integer`); hash(event.evidenceSha256, `${label}.events[${j}].evidenceSha256`) }
    object(entry.terminal, `${label}.terminal`, ['status', 'failureClass', 'evidenceSha256'])
    if (!['activated', 'failed', 'pending', 'disabled', 'unresolved'].includes(entry.terminal.status)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.terminal.status is unknown`)
    if (!['none', 'import', 'lifecycle', 'injection', 'unresolved'].includes(entry.terminal.failureClass)) throw new LoaderSettlementError('INVALID_MANIFEST', `${label}.terminal.failureClass is unknown`)
    hash(entry.terminal.evidenceSha256, `${label}.terminal.evidenceSha256`)
    list(entry.tools, `${label}.tools`)
    for (let j = 0; j < entry.tools.length; j++) { const tool = entry.tools[j]; object(tool, `${label}.tools[${j}]`, ['name', 'schemaSha256', 'evidenceSha256']); identifier(tool.name, `${label}.tools[${j}].name`); hash(tool.schemaSha256, `${label}.tools[${j}].schemaSha256`); hash(tool.evidenceSha256, `${label}.tools[${j}].evidenceSha256`) }
  }
  return value
}

function parse(input) {
  if (typeof input !== 'string' || !input || Buffer.byteLength(input) > MAX_BYTES) throw new LoaderSettlementError('INPUT_LIMIT', 'settlementJson must be non-empty and at most 262144 bytes')
  let value; try { value = JSON.parse(input) } catch { throw new LoaderSettlementError('INVALID_JSON', 'settlementJson is not valid JSON') }
  return validate(value)
}
function add(findings, code, entryId, detail) { findings.push({ code, entryId: entryId ?? null, detail }) }
function duplicates(values) { return [...new Set(values.filter((value, index) => values.indexOf(value) !== index))].sort() }

function evaluate(manifest) {
  const findings = [], byEntry = new Map(), observedTools = new Map()
  if (manifest.subject.dshRevisionSha256 !== manifest.policy.expectedDshRevisionSha256) add(findings, 'DSH_REVISION_MISMATCH', null, manifest.subject.profileId)
  for (const duplicate of duplicates(manifest.policy.requiredEntryIds)) add(findings, 'DUPLICATE_REQUIRED_ENTRY', duplicate, duplicate)
  for (const duplicate of duplicates(manifest.policy.requiredTools.map(tool => tool.name))) add(findings, 'DUPLICATE_REQUIRED_TOOL', null, duplicate)
  for (const entry of manifest.entries) {
    if (byEntry.has(entry.entryId)) { add(findings, 'DUPLICATE_ENTRY', entry.entryId, entry.entryId); continue }
    byEntry.set(entry.entryId, entry)
    const phases = entry.events.map(event => event.phase)
    if (duplicates(phases).length) add(findings, 'DUPLICATE_PHASE', entry.entryId, duplicates(phases).join(','))
    if (entry.events.some((event, index) => index && event.seq <= entry.events[index - 1].seq)) add(findings, 'EVENT_ORDER_INVALID', entry.entryId, 'seq')
    if (entry.enabled && phases.join('>') !== PHASES.join('>')) add(findings, 'PHASE_CHAIN_INCOMPLETE', entry.entryId, phases.join('>') || 'unobserved')
    const mustActivate = entry.enabled && (manifest.policy.requireAllEnabledActivated || manifest.policy.requiredEntryIds.includes(entry.entryId))
    if (mustActivate && entry.terminal.status !== 'activated') add(findings, 'ENTRY_NOT_ACTIVATED', entry.entryId, entry.terminal.status)
    if (entry.terminal.status === 'activated' && entry.terminal.failureClass !== 'none') add(findings, 'TERMINAL_CLASS_CONFLICT', entry.entryId, entry.terminal.failureClass)
    if (entry.terminal.status !== 'activated' && entry.terminal.status !== 'disabled' && entry.terminal.failureClass === 'none') add(findings, 'FAILURE_CLASS_MISSING', entry.entryId, entry.terminal.status)
    const unresolved = [...new Set(entry.injectRequested)].filter(service => !entry.injectResolved.includes(service)).sort()
    for (const service of unresolved) add(findings, 'INJECTION_UNRESOLVED', entry.entryId, service)
    if (entry.terminal.status !== 'activated' && entry.tools.length) add(findings, 'TOOLS_FROM_INACTIVE_ENTRY', entry.entryId, String(entry.tools.length))
    for (const duplicate of duplicates(entry.tools.map(tool => tool.name))) add(findings, 'DUPLICATE_TOOL', entry.entryId, duplicate)
    for (const tool of entry.tools) {
      const seen = observedTools.get(tool.name)
      if (seen && seen.entryId !== entry.entryId) add(findings, 'TOOL_COLLISION', entry.entryId, tool.name)
      else if (!seen) observedTools.set(tool.name, { entryId: entry.entryId, schemaSha256: tool.schemaSha256 })
    }
  }
  for (const required of manifest.policy.requiredEntryIds) {
    const entry = byEntry.get(required)
    if (!entry) add(findings, 'REQUIRED_ENTRY_MISSING', required, required)
    else if (!entry.enabled) add(findings, 'REQUIRED_ENTRY_DISABLED', required, required)
  }
  for (const required of manifest.policy.requiredTools) {
    const observed = observedTools.get(required.name)
    if (!observed) add(findings, 'REQUIRED_TOOL_MISSING', null, required.name)
    else if (observed.schemaSha256 !== required.schemaSha256) add(findings, 'TOOL_SCHEMA_MISMATCH', observed.entryId, required.name)
  }
  findings.sort((a, b) => `${a.code}:${a.entryId ?? ''}:${a.detail}`.localeCompare(`${b.code}:${b.entryId ?? ''}:${b.detail}`))
  const summary = { entries: byEntry.size, enabled: [...byEntry.values()].filter(entry => entry.enabled).length, activated: [...byEntry.values()].filter(entry => entry.terminal.status === 'activated').length, tools: observedTools.size, findings: findings.length }
  const base = { schemaVersion: 1, verifierVersion: '0.1.0', subject: manifest.subject, manifestSha256: digest(stableJson(manifest)), status: findings.length ? 'rejected' : 'verified', summary, entries: [...byEntry.values()].map(entry => ({ entryId: entry.entryId, moduleName: entry.moduleName, enabled: entry.enabled, terminalStatus: entry.terminal.status, phases: entry.events.map(event => event.phase), unresolvedInject: [...new Set(entry.injectRequested)].filter(service => !entry.injectResolved.includes(service)).sort(), tools: entry.tools.map(tool => tool.name).sort() })).sort((a, b) => a.entryId.localeCompare(b.entryId)), findings }
  return { ...base, reportSha256: digest(stableJson(base)) }
}

function inspectParsed(manifest) {
  return { schemaVersion: 1, operation: 'inspect', proofOnly: true, subject: manifest.subject, manifestSha256: digest(stableJson(manifest)), entries: manifest.entries.length, enabledEntries: manifest.entries.filter(entry => entry.enabled).length, requiredEntries: manifest.policy.requiredEntryIds.length, requiredTools: manifest.policy.requiredTools.length, readsBusinessBodies: false, executesPlugins: false }
}
async function safeRoot(rootValue) { const root = await realpath(path.resolve(rootValue)); const info = await lstat(root); if (!info.isDirectory() || info.isSymbolicLink()) throw new LoaderSettlementError('UNSAFE_PATH', 'workspaceRoot must be a real directory'); return root }
async function safeFile(rootValue, relative) { if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) throw new LoaderSettlementError('UNSAFE_PATH', 'settlementPath must be workspace-relative'); const root = await safeRoot(rootValue), target = path.resolve(root, relative), rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new LoaderSettlementError('UNSAFE_PATH', 'settlementPath escapes workspaceRoot'); const info = await lstat(target); if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BYTES) throw new LoaderSettlementError('UNSAFE_PATH', 'settlementPath must be a bounded regular non-symlink file'); const resolvedTarget = await realpath(target), resolvedRel = path.relative(root, resolvedTarget); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new LoaderSettlementError('UNSAFE_PATH', 'settlementPath resolves outside workspaceRoot'); return { root, target: resolvedTarget } }
async function directory(rootValue, relative) { if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) throw new LoaderSettlementError('UNSAFE_PATH', 'artifactDir must be workspace-relative'); const root = await safeRoot(rootValue), target = path.resolve(root, relative), rel = path.relative(root, target); if (rel.startsWith('..') || path.isAbsolute(rel)) throw new LoaderSettlementError('UNSAFE_PATH', 'artifactDir escapes workspaceRoot'); await mkdir(target, { recursive: true }); const info = await lstat(target); if (!info.isDirectory() || info.isSymbolicLink()) throw new LoaderSettlementError('UNSAFE_PATH', 'artifactDir must be a real directory'); const resolvedTarget = await realpath(target), resolvedRel = path.relative(root, resolvedTarget); if (resolvedRel.startsWith('..') || path.isAbsolute(resolvedRel)) throw new LoaderSettlementError('UNSAFE_PATH', 'artifactDir resolves outside workspaceRoot'); return { root, target: resolvedTarget } }
async function publish(root, relative, report) { const dir = await directory(root, relative), body = stableJson(report), sha256 = digest(body), filename = `loader-settlement-${sha256}.json`, target = path.join(dir.target, filename), temp = path.join(dir.target, `.${filename}.${randomUUID()}.tmp`); try { await writeFile(temp, body, { flag: 'wx' }); try { await link(temp, target) } catch (error) { if (error.code !== 'EEXIST') throw error } const reread = await readFile(target, 'utf8'); if (reread !== body || digest(reread) !== sha256) throw new LoaderSettlementError('WRITE_VERIFY_FAILED', 'artifact read-back failed'); return { path: path.relative(dir.root, target).replaceAll(path.sep, '/'), sha256, bytes: Buffer.byteLength(body), verifiedByReadBack: true } } finally { try { await unlink(temp) } catch {} } }

export function inspectSettlementInline({ settlementJson }) { return { ...inspectParsed(parse(settlementJson)), operation: 'inspect-inline', filesystemAccess: false, networkAccess: false } }
export function verifySettlementInline({ settlementJson }) { return { ...evaluate(parse(settlementJson)), operation: 'verify-inline', proofOnly: true, filesystemAccess: false, networkAccess: false, executesPlugins: false } }
export async function inspectSettlement({ workspaceRoot = process.cwd(), settlementPath }) { const { target } = await safeFile(workspaceRoot, settlementPath); return inspectParsed(parse(await readFile(target, 'utf8'))) }
export async function verifySettlement({ workspaceRoot = process.cwd(), settlementPath, artifactDir }) { const { target } = await safeFile(workspaceRoot, settlementPath), report = evaluate(parse(await readFile(target, 'utf8'))); return { ...report, artifact: await publish(workspaceRoot, artifactDir, report) } }

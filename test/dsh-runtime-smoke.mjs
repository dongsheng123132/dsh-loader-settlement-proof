import assert from 'node:assert/strict'
import { cp, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
const plugin = process.env.PLUGIN_ENTRY ? await import(pathToFileURL(resolve(process.env.PLUGIN_ENTRY)).href) : await import('../index.js'), checkout = process.env.DSH_CHECKOUT
if (!checkout) throw new Error('DSH_CHECKOUT required')
const built = relative => import(pathToFileURL(resolve(checkout, relative)).href), { Context } = await built('vendor/cordis/lib/index.js'), { default: SystemPrompt } = await built('packages/core/system-prompt/lib/index.js'), { default: ToolRuntime } = await built('packages/core/tools/lib/index.js'), root = await mkdtemp(join(tmpdir(), 'dsh-loader-runtime-'))
await cp(new URL('../examples/', import.meta.url), root, { recursive: true })
const ctx = new Context()
try { await ctx.plugin(SystemPrompt); await ctx.plugin(ToolRuntime); await ctx.plugin(plugin, { workspaceRoot: root }); const tools = ctx.get('tools'), names = tools.schemas().filter(({ name }) => name.startsWith('dsh_loader_settlement_')).map(({ name }) => name); assert.deepEqual(names, ['dsh_loader_settlement_inspect', 'dsh_loader_settlement_verify']); const result = await tools.execute({ signal: new AbortController().signal, callId: 'verify', name: names[1], arguments: { settlementPath: 'settlement.json', artifactDir: 'artifacts' } }); assert.equal(result.isError, false); assert.equal(result.value.status, 'verified'); assert.equal(result.value.summary.activated, 1); assert.equal(result.value.summary.tools, 1); console.log(JSON.stringify({ ok: true, tools: names, status: result.value.status, activated: 1, registeredTools: 1 })) } finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }

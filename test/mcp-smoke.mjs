import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { readFile } from 'node:fs/promises'
const settlementJson = await readFile(new URL('../examples/settlement.json', import.meta.url), 'utf8')
const child = spawn(process.execPath, ['mcp-server.mjs'], { cwd: new URL('../', import.meta.url), shell: false, stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot } })
let buffer = ''; const responses = []
child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => { buffer += chunk; let index; while ((index = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, index); buffer = buffer.slice(index + 1); if (line) responses.push(JSON.parse(line)) } })
for (const request of [{ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'loader_settlement_verify_inline', arguments: { settlementJson } } }]) child.stdin.write(`${JSON.stringify(request)}\n`)
const deadline = Date.now() + 5000; while (responses.length < 3 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20)); child.kill()
assert.equal(responses.length, 3); assert.deepEqual(responses[1].result.tools.map(({ name }) => name), ['loader_settlement_inspect_inline', 'loader_settlement_verify_inline']); assert.equal(responses[2].result.structuredContent.status, 'verified'); assert.equal(responses[2].result.structuredContent.executesPlugins, false); assert.equal(JSON.stringify(responses).includes('workspaceRoot'), false); console.log(JSON.stringify({ ok: true, tools: 2, proofOnly: true, executesPlugins: false }))

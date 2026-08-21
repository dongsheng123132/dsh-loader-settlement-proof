#!/usr/bin/env node
import readline from 'node:readline'
import { inspectSettlementInline, verifySettlementInline } from './lib/loader-settlement-proof.mjs'
const textSchema = { type: 'string', maxLength: 262144 }
const schemas = [
  { name: 'loader_settlement_inspect_inline', description: 'Inspect bounded inline Loader settlement evidence.', inputSchema: { type: 'object', required: ['settlementJson'], properties: { settlementJson: textSchema }, additionalProperties: false } },
  { name: 'loader_settlement_verify_inline', description: 'Verify inline Loader settlement evidence without executing a plugin.', inputSchema: { type: 'object', required: ['settlementJson'], properties: { settlementJson: textSchema }, additionalProperties: false } }
]
const call = (name, args) => name === schemas[0].name ? inspectSettlementInline(args) : name === schemas[1].name ? verifySettlementInline(args) : (() => { throw Object.assign(new Error(`Unknown tool: ${name}`), { code: 'METHOD_NOT_FOUND' }) })()
const send = value => process.stdout.write(`${JSON.stringify(value)}\n`)
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  if (!line.trim() || Buffer.byteLength(line) > 300000) continue
  let request; try { request = JSON.parse(line) } catch { continue }
  if (request.id === undefined) continue
  try {
    if (request.method === 'initialize') send({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: request.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dsh-loader-settlement-proof', version: '0.1.0' } } })
    else if (request.method === 'tools/list') send({ jsonrpc: '2.0', id: request.id, result: { tools: schemas } })
    else if (request.method === 'tools/call') { const result = call(request.params?.name, request.params?.arguments ?? {}); send({ jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result } }) }
    else send({ jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found' } })
  } catch (error) { send({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: error.message, data: { code: error.code ?? 'ERROR' } } }) }
}

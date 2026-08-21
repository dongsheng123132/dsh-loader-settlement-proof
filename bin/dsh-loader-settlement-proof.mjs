#!/usr/bin/env node
import { inspectSettlement, verifySettlement } from '../lib/loader-settlement-proof.mjs'
const [, , command, settlementPath, artifactDir] = process.argv
const usage = 'usage: dsh-loader-settlement-proof inspect <settlement.json> | verify <settlement.json> <artifact-dir>'
try {
  let result
  if (command === 'inspect' && settlementPath && !artifactDir) result = await inspectSettlement({ settlementPath })
  else if (command === 'verify' && settlementPath && artifactDir) result = await verifySettlement({ settlementPath, artifactDir })
  else throw Object.assign(new Error(usage), { code: 'USAGE' })
  process.stdout.write(`${JSON.stringify(result)}\n`)
  if (result.status === 'rejected') process.exitCode = 2
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, code: error.code ?? 'ERROR', message: error.message })}\n`)
  process.exitCode = error.code === 'USAGE' ? 1 : 2
}

# Security

Report vulnerabilities privately through GitHub Security Advisories.

The verifier is proof-only. It does not import, start, reload, enable, disable, or inspect the code of a recorded plugin. MCP accepts only bounded inline JSON and has no filesystem, network, or subprocess capability. DSH tools and the CLI read one explicit workspace-relative regular file and write only to an explicit workspace-relative artifact directory using create-only content-addressed publication plus read-back verification.

Receipts must contain hashes, identifiers, phases, classifications, and schema digests only. Keys that can carry secrets, raw logs, business bodies, prompts, stack traces, or command output are rejected recursively. Paths are checked before and after realpath resolution; symlink escape is rejected.

A `verified` result proves only internal consistency against the manifest policy. It does not prove that the producer observed the real Loader honestly, that plugin code is safe, or that a plugin will remain compatible with another DSH revision.

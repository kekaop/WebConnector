# Changelog

## 2.0.0 — 2026-09-19

- Added a public Java API registered through Bukkit ServicesManager and a shared action service for HTTP and Java callers.
- Added typed payload schemas, scoped and expiring API keys, CIDR rules, bounded queues, timeouts, rate limits and dangerous-action exclusion.
- Added persistent operations, request IDs, status polling and durable idempotency reservations with recovery after restart.
- Added signed webhook envelopes, per-route endpoints, filters, bounded delivery queues and exponential retries.
- Restricted file deletion to explicitly allowed regular files and protected plugin data, links and directories.
- Added administrative commands, live action/key/route reload, OpenAPI, integration examples, English/Russian documentation and a Paper testbed.
- Lowered the baseline to Java 17/Bukkit 1.20.1; added API/runtime verification through 26.2 and experimental 26.3.

### Upgrade notes

Version 2 requires a reviewed version 2 configuration. Empty secrets no longer disable production authentication. Unknown payload fields and unsafe command values are rejected. Success responses use `success` and asynchronous work can return `202`. See [migration](docs/MIGRATION.md) before replacing a 1.x installation.

## 1.0.2

Previous release of the configurable HTTP action bridge. Version 2 retains the configurable action routes and provides an explicit migration path for authentication, payload validation and outgoing event formats.

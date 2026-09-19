# WebConnector 2.0.0

WebConnector 2.0 adds a public Java API and a shared action service, persistent operations with idempotency keys, scoped authentication, typed validation, and signed webhook delivery with retries.

- One Java 17-compatible JAR targets Paper 1.20.1–26.2; 26.3 compatibility is experimental.
- API keys support names, expiry, action scopes and permissions, with IP/CIDR rules and bounded request/operation limits.
- HTTP clients can submit actions, retain request/operation IDs and poll asynchronous results.
- Idempotency reservations survive restarts. Interrupted work is recorded for reconciliation instead of being automatically repeated.
- Java plugins can register private actions, explicitly publish HTTP endpoints and emit webhook events through Bukkit ServicesManager.
- English documentation, Russian guides, OpenAPI, Java/Skript examples and a Paper smoke-test harness are included.

## Upgrade

**Version 1 configuration requires migration.** Empty secrets, unrestricted JSON interpolation and unrestricted file deletion are no longer accepted. The old configuration is left unchanged. Read the [migration guide](https://github.com/kekaop/WebConnector/blob/v2.0.0/docs/MIGRATION.md).

The default configuration binds to localhost, generates a private secret and enables only `ping`. Shutdown and file deletion remain opt-in. Timeouts and command failures can leave partial external effects; retain the original idempotency key and reconcile before creating a new operation.

## Downloads

- `WebConnector-2.0.0.jar`: server plugin.
- `WebConnector-2.0.0-api.jar`: compile-only dependency for Java plugins; do not install or shade it.
- `WebConnector-2.0.0-sources.jar` and `WebConnector-2.0.0-javadoc.jar`: developer references.
- `WebConnector-2.0.0-docs.zip`: English/Russian documentation and integration examples.
- `SHA256SUMS`: checksums for release assets.

The automated suite uses real HTTP requests and mock webhook receivers across the 1.20.1/1.20.6/1.21.11/26.2/26.3 API matrix. API/runtime tests do not certify every live Paper or third-party Skript addon combination; see [testing](https://github.com/kekaop/WebConnector/blob/v2.0.0/docs/TESTING.md).

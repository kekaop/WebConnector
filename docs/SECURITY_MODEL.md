# Security model

[Home](../README.md) · [Reporting vulnerabilities](../SECURITY.md)

Administrators and installed Java plugins are trusted. External HTTP callers are not. A key grants only explicitly scoped HTTP actions, action permissions and optional dangerous-action rights. Keys authenticate through the configured header; secret hashes are compared in constant time. Expired and disabled keys are rejected. The default listener binds to localhost and grants only a harmless ping action.

Use HTTPS through a reverse proxy or a private authenticated tunnel when requests leave the host. WebConnector's embedded listener is HTTP, not a TLS endpoint. Block direct access to it from untrusted networks. Restrict request/header sizes, connection counts and slow clients at the proxy. IP rules use the direct TCP peer and do not trust forwarded headers. CORS, browser authentication, cookies and an administrative web UI are not provided; keep API secrets in server-side applications.

Action definitions are executable policy: administrators choose console commands, schemas, permissions and file roots. JSON cannot define commands or paths. Avoid broad command templates and unrestricted regex patterns. No file deletion is enabled by default, and only dedicated allowlisted regular files can be removed. File checks prevent path traversal and existing symlink/junction redirects; an actor who can concurrently replace server files or install Java plugins is already inside the trust boundary.

WebConnector limits request bodies, nesting, queues, identities tracked by rate limiting, workers, webhook attempts and operation records. Rate limits use fixed minute windows, so bursts across a window boundary are possible. A stopped server thread cannot be recovered by this plugin: queued work expires, while an already running command can outlive its deadline. Do not configure actions that block the server thread.

The journal stores operation metadata, safe result messages, hashed idempotency identities and hashed canonical request fingerprints. It does not store raw API keys, raw idempotency keys or request payloads. Back up the entire `operations/` directory consistently while the server is stopped. Keep it on a filesystem supporting atomic file replacement. Retain it across upgrades and secret rotations; removing records weakens replay protection. The journal provides durable reservations, not exactly-once external effects or distributed transactions.

Runtime configuration and webhook headers contain secrets. Restrict filesystem permissions, redact them before sharing, and exclude them from public repositories and backups with wider access. WebConnector logs operation IDs, request IDs, action names and terminal states. It does not log request bodies, headers, secret values or raw handler exceptions. Custom handlers must return safe public messages and avoid leaking secrets through their own logging.

Webhook destinations are administrator-controlled outbound integrations. Use HTTPS for remote receivers, independent signing secrets, a bounded replay window and durable receiver-side deduplication. In-memory webhook delivery may be lost on shutdown. Never use delivery success alone as evidence that an external payment was completed.

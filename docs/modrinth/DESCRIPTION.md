# WebConnector

Connect your Minecraft server to websites, shops, Discord bots and other plugins through a controlled HTTP API, a public Java API and signed webhooks.

Define exactly which actions an integration may run. WebConnector validates incoming JSON, checks the client's permissions, tracks each operation, and remembers idempotency keys across server restarts.

## What you can build

- A store that grants a configured rank or pass using a stable order ID.
- A Discord bot or website that receives player join and first-join events.
- A NodeDashboard integration with scoped access to individual server actions.
- A Java plugin that registers private actions or explicitly exposes them over HTTP.
- Skript integrations using an existing HTTP addon.

## Features

- Named API keys with expiry, action scopes and permissions.
- IP/CIDR allowlists, request size limits, timeouts and rate limits.
- Typed validation for player names, UUIDs, strings, integers, booleans, enums and regex rules.
- Asynchronous operations with request IDs, status polling and durable retry protection.
- Signed webhook requests with filters, per-route destinations and exponential retries.
- Optional file deletion restricted to allowlisted regular files, and explicit dangerous-action controls.
- Live reload of actions, keys and event routes.

## Compatibility

One server-side JAR targets **Paper 1.20.1–26.2**, with **experimental 26.3 support**. Use Java 17 for Minecraft 1.20.1–1.20.4, Java 21 for 1.20.5–1.21.11, and Java 25 for 26.1+. No client installation is required. Folia and proxy servers are not supported.

WebConnector uses the common Bukkit API without NMS. See the [compatibility matrix](https://github.com/kekaop/WebConnector/blob/main/docs/COMPATIBILITY.md) for verification scope. Skript and HTTP addons are optional and have their own version requirements.

## Getting started

1. Install the main WebConnector JAR in `plugins/` and start the server.
2. Open the generated `plugins/WebConnector/config.yml`. A private API secret is generated automatically.
3. Define your actions and give each integration a scoped key.
4. Use `/webconnector reload` after changing actions, keys or event routes.

The default API binds to localhost and exposes only a harmless ping action. For remote integrations, your hosting plan must provide a reachable additional port or reverse proxy. Use HTTPS at the proxy when traffic crosses a network.

Use the same `Idempotency-Key` when retrying a reward or order. Completed or interrupted operations are not automatically executed again for that key. External commands are not transactional: after a timeout or failure, inspect the operation and server state before creating a new key.

WebConnector provides the integration gateway; it does not include a dashboard or payment processor. File deletion and shutdown are disabled by default.

[Documentation](https://github.com/kekaop/WebConnector#documentation) · [HTTP API](https://github.com/kekaop/WebConnector/blob/main/docs/HTTP_API.md) · [Java API](https://github.com/kekaop/WebConnector/blob/main/docs/JAVA_API.md) · [Русская документация](https://github.com/kekaop/WebConnector/blob/main/README.ru.md) · [Issues](https://github.com/kekaop/WebConnector/issues)

**Upgrading from 1.x?** Read the [migration guide](https://github.com/kekaop/WebConnector/blob/main/docs/MIGRATION.md) before replacing the plugin.

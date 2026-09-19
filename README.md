# WebConnector

[English](README.md) · [Русский](README.ru.md) · [Downloads](https://github.com/kekaop/WebConnector/releases) · [HTTP reference](docs/HTTP_API.md) · [Java API](docs/JAVA_API.md)

WebConnector connects a Minecraft server to websites, shops, Discord bots and other plugins. Define allowed actions in YAML or Java, call them through an authenticated HTTP API, and send signed game events to your services.

One JAR targets Paper **1.20.1–26.2**, with **experimental 26.3 compatibility**. It uses Java 17 bytecode and the common Bukkit API, without NMS. Use the Java version required by your server: Java 17 for 1.20.1–1.20.4, Java 21 for 1.20.5–1.21.11, and Java 25 for 26.1+. See [compatibility and verification](docs/COMPATIBILITY.md). Folia, proxy servers and client mod loaders are not supported.

## Features

- Authenticated `POST /api/<action>` endpoints with named API keys, expiry, action scopes, permissions and IP/CIDR allowlists.
- A public Java API registered with Bukkit `ServicesManager`. Java actions stay private unless explicitly exposed to HTTP.
- Shared parameter validation, bounded queues, request deadlines and rate limits by IP, key and action.
- Persistent operation status and `Idempotency-Key` reservations, including across restarts.
- Console commands with validated placeholders, optional restricted file deletion and controlled server shutdown.
- Signed webhook events, filters, per-route endpoints and retries with exponential backoff.
- Live reload of actions, authentication and event routes; English and Russian documentation.

WebConnector is a gateway for one Minecraft server. It does not provide a dashboard, execute arbitrary commands supplied by HTTP clients, or manage Docker. NodeDashboard and ServerBootstrap integrate as clients. Skript uses a third-party HTTP addon; WebConnector does not require or ship a Skript addon.

## Install

1. Download `WebConnector-2.0.0.jar` from [GitHub Releases](https://github.com/kekaop/WebConnector/releases/latest) and place it in `plugins/`.
2. Start the server. WebConnector creates `plugins/WebConnector/config.yml` and generates a random API secret.
3. Keep the secret private. Configure allowed actions and give each external service its own scoped key.
4. Run `/webconnector reload` for action/key/event changes. Restart for bind address, port, worker or journal-capacity changes.

The default listener is `127.0.0.1:25575`, and the default key can call only `ping`. Shutdown and file deletion are disabled. A remote client needs a reachable port or reverse proxy; plugin-only hosting works when the host allows an additional listening port.

Existing 1.x installations must follow the [migration guide](docs/MIGRATION.md). Version 2 deliberately rejects unversioned configuration instead of enabling old unsafe defaults.

## First request

Set `WEBCONNECTOR_SECRET` privately to the generated value, then run:

```sh
curl --fail-with-body http://127.0.0.1:25575/api/ping \
  -H "X-Shared-Secret: $WEBCONNECTOR_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{}'
```

The response includes `status`, `request_id` and `operation_id`. Reward and payment actions should require an `Idempotency-Key` derived from the external order ID. Reuse that key when retrying; do not generate a new key for the same business operation.

## Documentation

| Topic | Reference |
| --- | --- |
| Configuration, validation, commands and permissions | [Configuration](docs/CONFIGURATION.md) |
| Endpoints, errors, operations and idempotency | [HTTP API](docs/HTTP_API.md), [OpenAPI](docs/openapi.yml) |
| Plugin integration | [Java API](docs/JAVA_API.md), [compilable example](examples/java/) |
| Outgoing events and signature verification | [Webhooks](docs/WEBHOOKS.md) |
| Skript HTTP clients | [Skript](docs/SKRIPT.md), [examples](examples/skript/) |
| NodeDashboard, ServerBootstrap and upgrades | [Migration and integrations](docs/MIGRATION.md) |
| Deployment and trust boundaries | [Security model](docs/SECURITY_MODEL.md), [security policy](SECURITY.md) |
| Operations and development | [Troubleshooting](docs/TROUBLESHOOTING.md), [testing](docs/TESTING.md), [changelog](CHANGELOG.md) |
| Russian documentation | [Руководство](docs/ru/GUIDE.md), [HTTP и Java API](docs/ru/API.md) |

## Build

```sh
./gradlew build
```

On Windows use `gradlew.bat build`. Run Gradle with Java 17 or 21. Artifacts are in `build/libs/`: the server plugin, a compile-only API JAR, sources, Javadoc, and a separate example plugin for the testbed. Install only the main JAR on production servers. Dependencies supplied by Bukkit, including Gson, are not bundled into the release.

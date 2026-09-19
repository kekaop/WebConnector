# Migration and integrations

[Home](../README.md) · [Русский](ru/GUIDE.md#обновление-с-1x)

## Upgrade from 1.x

Stop the server and back up the old JAR and `plugins/WebConnector/`. Version 2 rejects unversioned/older configuration with a migration message and leaves the original file intact. Create a version 2 configuration from the bundled sample, then move reviewed actions and routes into it. There is no automatic migration of unrestricted command interpolation or file deletion.

| Version 1 | Version 2 |
| --- | --- |
| `plugin-host`, `plugin-port`, `plugin-path` | `server.host`, `server.port`, `server.path` |
| `allowed-methods` | `server.allowed-methods` (mutating verbs only) |
| `shared-secret-header`, `shared-secret` | Same fields under `security`; use a random secret of at least 32 characters |
| Any authenticated key could call every action | Explicit `shared-secret-actions` or named key `actions` |
| Empty secret disabled authentication | Production rejects missing working credentials |
| Arbitrary JSON placeholders | Per-action `validation`, unknown fields rejected, command values restricted to safe tokens |
| `payload.player-name-keys`, `payload.player-uuid-keys` | Retained for canonical validated `player`/`uuid` fields |
| Unrestricted `delete-files` | `files.enabled`, dedicated `files.allowed-roots`, no links/directories/WebConnector files |
| `shutdown` | Explicit dangerous rights and action permission; default example requires idempotency |
| `event-dispatch` and `event-routes` | Retained with signing secret, retries, filters and per-route endpoints |
| Flat event payload | Use `legacy-payload: true` per route, or migrate receiver to envelope `data` |
| `200 {"status":"ok"}` | `200` with `status: success`; `202` while asynchronous work is pending |

Enable one action at a time and verify it with a scoped key. Update clients to retain `Idempotency-Key`, handle 202/polling, and read result/state rather than assuming any 2xx response means completion. Keep reward order identifiers stable during client upgrades.

## NodeDashboard

Action names and URLs remain configurable, including `/api/shutdownNode`, `/api/gradientApply`, `/api/passApply` and `/api/updateSeason`. Recreate only the actions the node needs, with schemas matching NodeDashboard's payload. Extra metadata fields must either be removed from the client request or explicitly validated. Player aliases can preserve `player_name`/`player_uuid` payloads.

```yaml
security:
  shared-secret: "<same private random secret as the NodeDashboard node>"
  shared-secret-actions: [shutdownNode]
  shared-secret-permissions: [webconnector.shutdown]
  shared-secret-allow-dangerous: true
actions:
  shutdownNode:
    enabled: true
    expose-http: true
    permission: webconnector.shutdown
    dangerous: true
    require-idempotency: true
    shutdown: true
    shutdown-delay-ticks: 20
```

Configure the node's host, plugin port/path and shared secret to match. Send `{}` with `Content-Type: application/json` and a stable `Idempotency-Key` for each requested shutdown. A legacy client can deliberately set `require-idempotency: false` for a reviewed shutdown-only action, but then retry protection requires the client to send a key voluntarily. Do not remove the requirement from reward/payment actions.

NodeDashboard remains a separate deployment. Use TLS and network controls when the node endpoint crosses a network. For legacy outgoing events, retain the expected custom header and `legacy-payload: true`; add HMAC verification to the receiver.

## ServerBootstrap

ServerBootstrap can use the same authenticated API as any other controller. A reviewed YAML action may dispatch a fixed ServerBootstrap command, with only validated scalar arguments. Select the actual command supported by the installed ServerBootstrap version; WebConnector does not assume or call an undocumented internal API.

Mark backup/restore/world-reset actions dangerous and require idempotency. All prerequisites and confirmations required by ServerBootstrap still apply. Keep world replacement in ServerBootstrap's startup/offline lifecycle; an HTTP request to a running server must not replace an already loaded world. The response describes command dispatch, not completion of asynchronous work launched by another plugin. For end-to-end status, register a Java action that integrates with the other plugin's supported API and reports the real result.

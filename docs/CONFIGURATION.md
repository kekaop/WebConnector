# Configuration

[Home](../README.md) · [Русский](ru/GUIDE.md)

The bundled [config.yml](../src/main/resources/config.yml) is the complete starting configuration. Configuration version is `2`. A new installation generates a random 64-character secret; an existing empty or placeholder secret does not enable a production listener.

## Listener and authentication

`server.host`, `server.port` and `server.path` select the listener. The path consists of simple non-empty segments such as `/api` or `/minecraft/api`. Only `POST`, `PUT` and `PATCH` may be enabled for actions; operation polling uses `GET` independently. Defaults are localhost, port 25575, path `/api`, and `POST` only.

`security.shared-secret-header` defaults to `X-Shared-Secret`. The compatibility key uses `shared-secret`, `shared-secret-actions`, `shared-secret-permissions`, and `shared-secret-allow-dangerous` under `security`. Its stable identity is `key:shared`. Remove the secret by setting it to an empty string when using named keys exclusively.

```yaml
security:
  require-authentication: true
  shared-secret: ""
  ip-allowlist: ["127.0.0.1/32", "10.20.0.0/16", "::1/128"]
  api-keys:
    shop:
      enabled: true
      secret: "<generate a private random secret of at least 32 characters>"
      expires-at: "2027-01-01T00:00:00Z"
      actions: [grant-pass]
      permissions: []
      allow-dangerous: false
```

Generate secrets with a password manager or `openssl rand -hex 32`. Omit `expires-at` for a key without expiry. An empty action list grants nothing; `['*']` grants every HTTP-exposed action. Permissions are exact names or `*`, independently of action scopes. Disabled and expired keys cannot authenticate. Key names and active secret values must be unique. Keep the key **name** stable when rotating its secret so previous operations and idempotency reservations remain accessible.

An empty IP allowlist accepts any direct peer. Forwarded headers are never trusted. Behind a reverse proxy, WebConnector sees the proxy's IP; enforce client IP restrictions at the proxy too.

For isolated development, explicitly set `development-mode: true`, `allow-unauthenticated-localhost: true` and a loopback bind address. This permits missing authentication only from loopback, without dangerous-action rights or custom permissions. Production should retain the defaults.

## Actions

```yaml
actions:
  grant-pass:
    enabled: true
    description: "Grant a configured LuckPerms group"
    expose-http: true
    permission: "shop.grant"
    dangerous: false
    require-idempotency: true
    async: true
    timeout-seconds: 10
    validation:
      player: {type: player_name, max-length: 16}
      pass: {type: enum, allowed: [vip, premium]}
    commands:
      - "lp user {player} parent add {pass}"
```

The key must list `grant-pass` in `actions` and `shop.grant` in `permissions`. Install LuckPerms for this example. Action names are case-sensitive, at most 64 characters, using letters, digits, `_`, `-` and, in Java registrations, `.`. Use simple names without dots in YAML because Bukkit treats dots as section separators. `operations` is reserved.

YAML actions expose HTTP by default; set `expose-http: false` to restrict an action to Java/administrative invocation. Java actions default to private. A disabled action is absent from the registry. Unknown payload fields are rejected. `required` defaults to true on each validation rule.

| Type | Rules |
| --- | --- |
| `string` | JSON string; `max-length` defaults to 256; control characters forbidden |
| `integer` | JSON number with an exact signed 64-bit integer value; optional `min` and `max` |
| `boolean` | JSON `true` or `false`, not a quoted string |
| `uuid` | Full hyphenated UUID string |
| `player_name` | 1–16 ASCII letters, digits or underscores |
| `enum` | Exact string from a non-empty `allowed` list |
| `regex` | Full match against `pattern`, with `max-length` applied first |

Only administrators should define regex patterns. Keep them simple and bounded; enum rules are preferable for finite choices. `max-length` may be 1–8192, but substituted command tokens have a stricter 256-character limit.

Every `{parameter}` used in a command needs a validation rule. `{action}` is supplied by the service. Values substituted into commands must match `[A-Za-z0-9_.:-]{1,256}`: spaces, selectors, braces, newlines and extra arguments cannot enter through placeholders. Write fixed command arguments in YAML. All commands and file targets are checked before the first side effect; a false command dispatch result stops the action. Earlier completed commands cannot be rolled back.

Player aliases default to `player_name`, `player`, `name`; UUID aliases to `player_uuid`, `uuid`. They apply only when the action defines canonical `player` or `uuid` validation. Supplying an alias together with its canonical parameter is an error. Idempotency fingerprints use canonical validated parameters.

## Dangerous actions and files

`shutdown: true` schedules server shutdown after `shutdown-delay-ticks` (default 20). `delete-files` lists static paths, relative to the server directory. These features automatically mark an action dangerous. Mark other sensitive command actions explicitly with `dangerous: true`.

File deletion additionally requires `files.enabled: true` and a matching entry in `files.allowed-roots`. Roots must be dedicated subdirectories of the server directory and cannot overlap WebConnector's JAR or data folder. Only individual regular files are deleted. Directory trees, the allowed root itself, symlinks, junctions, traversal outside the roots, and WebConnector files are rejected. Missing files are harmless. No payload substitution is performed in file paths.

For HTTP, both the action permission and `allow-dangerous: true` are required. Administrative players need `webconnector.execute`, the action-specific permission and the separate `webconnector.dangerous` permission. Console execution is allowed. One dangerous operation runs at a time, including a timed-out handler that is still finishing.

## Limits and storage

`limits` controls maximum body size, HTTP deadline, thread counts, queue capacity, and fixed one-minute rate windows. `rate-limit-per-minute` is the fallback for `ip-per-minute`, `key-per-minute` and `action-per-minute`. IP limiting includes failed authentication; key limits include operation polling. Action limits are shared across callers. Java calls use the same key/action limits and action queue.

`operations.max-records` bounds the journal. Completed operations without idempotency keys can be evicted. Idempotency records are never automatically evicted; when they fill the journal, new work receives `429 journal_full`. See [maintenance](TROUBLESHOOTING.md). Runtime operations use bounded workers and must finish within their action deadline. A timeout cannot forcibly undo or terminate a third-party command.

## Commands and permissions

| Command | Permission | Behavior |
| --- | --- | --- |
| `/webconnector status` | `webconnector.status` | Listener and service health |
| `/webconnector reload` | `webconnector.reload` | Validate and replace actions, keys and routes |
| `/webconnector actions` | `webconnector.status` | List actions |
| `/webconnector action <name>` | `webconnector.status` | Action metadata |
| `/webconnector operations [id]` | `webconnector.status` | Latest ten operations or a specific operation |
| `/webconnector test <action> [JSON] [--key=<id>]` | `webconnector.execute` | Execute a real action; this is not a dry run |
| `/webconnector events` | `webconnector.status` | Active routes and delivery counters |
| `/webconnector diagnostics` | `webconnector.diagnostics` | Java/API version, journal and service health |

Alias: `/wc`. `webconnector.admin` includes the standard management permissions and defaults to operators. It does **not** include dangerous-action permission. `webconnector.dangerous` and `webconnector.shutdown` default to false.

Reload validates a candidate before replacing active configuration. Registered Java actions remain in place; name conflicts reject the reload. Bind/path/header/method/HTTP-limit changes, worker limits, journal capacity, server name and global webhook delivery tuning require restart. Active operations retain their original action definition. Disabling a webhook route drops its queued retries, but an HTTP delivery already in flight may complete.

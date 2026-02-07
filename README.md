## WebConnector

HTTP bridge plugin that executes server actions based on incoming requests.  
All accepted actions, headers, payload keys, and side effects are configured in `config.yml`.

### Features
- Configurable API host, port, and base path.
- Shared secret header for authentication (optional by leaving secret empty).
- Action routing via URL path segments.
- Per-action commands, file deletions, and optional shutdown.
- Placeholder expansion using any JSON payload key.
- Optional event dispatch to external webhooks.

### Building
From the project root, run:
- **Windows:** `gradlew.bat build`
- **Linux / macOS:** `./gradlew build`

The jar is produced in `build/libs/`. The project uses the Gradle wrapper (Gradle 9.3) so no local Gradle install is required.

### Installation
1. Drop the jar into your server `plugins/` folder.
2. Start the server once to generate `plugins/WebConnector/config.yml`.
3. Edit the config.
4. Restart or reload the server.

### Configuration
Key options in `config.yml`:
- `shared-secret`: value required in the header defined by `shared-secret-header`.
- `shared-secret-header`: header name used for auth (default `X-Shared-Secret`).
- `plugin-host`, `plugin-port`, `plugin-path`: HTTP bind address and base path.
- `allowed-methods`: list of allowed HTTP methods (default `POST`).
- `payload.player-name-keys`, `payload.player-uuid-keys`: keys used to resolve `{player}` and `{uuid}` placeholders.
- `actions`: map of action names with their behavior.
- `event-dispatch`: global settings for outgoing webhooks.
- `event-routes`: per-event webhook configuration and payload mapping.

Action options:
- `enabled`: turn an action on/off.
- `commands`: list of console commands to execute.
- `delete-files`: list of file paths to delete.
- `shutdown`: whether to stop the server after action.
- `shutdown-delay-ticks`: delay before shutdown (1 tick = 50ms).

### API
Endpoint:
```
POST http://<host>:<port><plugin-path>/<action>
```

Auth:
- Provide the shared secret in header `X-Shared-Secret` (or your configured header).
- If `shared-secret` is empty, auth is skipped.

Payload:
- JSON object (any keys allowed).
- Special placeholders:
  - `{action}`: current action name.
  - `{player}`: resolved from keys in `payload.player-name-keys`.
  - `{uuid}`: resolved from keys in `payload.player-uuid-keys`.
- Any JSON key becomes a placeholder, e.g. payload `{ "season": "7" }` lets you use `{season}`.

Responses:
- `200 {"status":"ok"}` on success.
- `400 {"status":"invalid_json"}` on invalid JSON.
- `401 {"status":"unauthorized"}` on missing/wrong secret.
- `404 {"status":"not_found"}` on unknown action.
- `405 {"status":"method_not_allowed"}` if method not allowed.

### Event Dispatch (Outgoing)
Enable in config:
```
event-dispatch:
  enabled: true
  base-url: "http://127.0.0.1:3000/webhook"
  method: POST
  event-name-field: "event"
  headers:
    X-Shared-Secret: "replace-me"
```

Add event routes:
```
event-routes:
  PlayerJoinEvent:
    enabled: true
    payload:
      player: "{event.player.name}"
      uuid: "{event.player.uniqueId}"
      world: "{event.player.world.name}"
  PlayerFirstJoinEvent:
    enabled: false
    payload:
      player: "{event.player.name}"
      uuid: "{event.player.uniqueId}"
```

Payload template notes:
- Use `{event.<path>}` to access event data via getters.
- Example `{event.player.getNickName}` or `{event.player.nickname}`.
- Each payload entry is sent as JSON to the configured endpoint.

Custom events:
- `PlayerFirstJoinEvent` fires on a player's first join.
- Available fields: `{event.player.*}` (same as `PlayerJoinEvent`).

### Example
Config action:
```
actions:
  gradientApply:
    commands:
      - "lp user {player} meta set gradient {value}"
```

Request:
```
POST /api/gradientApply
Header: X-Shared-Secret: your-secret
Body: {"player":"Steve","value":"gold"}
```

Executed command:
```
lp user Steve meta set gradient gold
```

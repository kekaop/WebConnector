# Webhooks

[Home](../README.md) · [Receiver example](../examples/webhook_receiver.py) · [Русский](ru/API.md)

Enable `event-dispatch`, set a private `signing-secret`, and configure event routes. Each route can override `endpoint`, `signing-secret` and `headers`. Delivery uses POST, no redirects, a bounded in-memory queue, and a configured timeout. Events are snapshots; network I/O never runs on the Minecraft event thread.

```yaml
event-dispatch:
  enabled: true
  base-url: "https://integration.example.com/minecraft"
  signing-secret: "<private random secret of at least 32 characters>"
  max-attempts: 5
  backoff-millis: 1000
  timeout-seconds: 5
  queue-capacity: 512
event-routes:
  PlayerJoinEvent:
    enabled: true
    type: player.join
    priority: MONITOR
    ignore-cancelled: true
    endpoint: "https://integration.example.com/join"
    filters:
      world: lobby
    payload:
      player: "{event.player.name}"
      uuid: "{event.player.uniqueId}"
      world: "{event.player.world.name}"
```

`filters` require exact string equality against the mapped payload. Routes match their exact `type`. The default mappings translate `PlayerJoinEvent`, `PlayerQuitEvent` and `PlayerFirstJoinEvent` to `player.join`, `player.quit` and `player.first_join`. `PlayerFirstJoinEvent` remains available in `com.eldryn.webconnector` for compatibility.

For another Bukkit event, use a simple route name and `event-class: fully.qualified.EventClass`. Event payload templates traverse public `getX`/`isX` getters, up to eight levels; `getClass`, methods with arguments and arbitrary methods are not available. Snapshot data suitable for that event's thread. Prefer low-volume events; publishing every movement/block event can fill the queue.

```json
{
  "id":"557a1b07-2066-4c73-bad2-e777ac8bfa66",
  "type":"player.join",
  "timestamp":"2026-09-19T10:20:00Z",
  "server":"lobby-01",
  "data":{"player":"Steve","uuid":"...","world":"lobby"}
}
```

For older NodeDashboard receivers, set `legacy-payload: true`. Fields then remain at the top level, with `event` (or `event-dispatch.event-name-field`), `id` and `timestamp`. Existing custom headers can be retained. Signatures are added in both formats.

## Verify signatures

Each request carries:

- `X-WebConnector-Id`: event UUID.
- `X-WebConnector-Timestamp`: ISO-8601 event timestamp.
- `X-WebConnector-Signature`: `sha256=<lowercase HMAC-SHA256 hex>`.

The HMAC input is UTF-8 `timestamp + "." + raw_request_body`. Verify the original bytes before parsing JSON, compare in constant time, reject stale timestamps using a window longer than your configured retry horizon, and deduplicate by event ID. The sample receiver uses a ten-minute window. A receiver should durably reserve the event ID before non-repeatable work and return a 2xx response only after it has safely accepted the event.

## Delivery behavior

Responses 2xx succeed. Network errors, timeouts, 408, 429 and 5xx retry; other HTTP responses, including redirects, fail without retry. Attempts use delays `backoff-millis × 2^(attempt−1)`, capped at 60 seconds. The event ID, timestamp, body and signature remain unchanged across retries. Ordering is not guaranteed.

The queue includes queued, in-flight and retrying deliveries. A full queue or payload over 64 KiB increments `dropped`; exhausted/permanent failures increment `failed`. Inspect `/webconnector events`. Events are not persisted across shutdowns, and WebConnector is not a guaranteed-delivery payment ledger. Route changes discard queued deliveries belonging to the previous route definition; requests already sent can still finish.

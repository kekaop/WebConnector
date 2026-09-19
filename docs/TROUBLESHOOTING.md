# Troubleshooting and maintenance

[Home](../README.md) · [Русский](ru/GUIDE.md)

| Symptom | Check |
| --- | --- |
| Plugin disabled at startup | Configuration version 2, a valid enabled secret, unique keys, free listener port, valid YAML/action schemas, writable journal |
| Explicit version 2 migration message | Follow [migration](MIGRATION.md); the old file is unchanged |
| Connection refused from a remote host | Default bind is localhost; check host port allocation, firewall and reverse proxy |
| 401 | Header name/value, key enabled flag and expiry |
| 403 | Direct-peer CIDR, action scope, action permission and dangerous flag |
| 400 on a previously accepted payload | Unknown fields, alias conflict, typed validation, missing JSON content type, required idempotency key |
| 409 | Same key with a different payload/action, or another dangerous handler still executing |
| 429 | Per-minute limits, bounded action queue, or full persistent journal |
| 500 / failed operation | Inspect the operation ID, downstream plugin state and storage; do not blindly issue a new key |
| Webhooks not received | Enabled route, matching type/filter, endpoint, signing secret and `/webconnector events` counters |
| Reload rejected | Invalid candidate, Java action name conflict, unavailable event class or restart-only setting changed |
| Command succeeded but external work still pending | Console dispatch only confirms dispatch; use a Java integration to track another plugin's asynchronous work |

`/webconnector diagnostics` reports the running Java/Bukkit version, service health, journal size and webhook counters without revealing credentials. HTTP errors include request IDs; operation logs include both request and operation IDs for correlation.

## Journal maintenance

Idempotent operations are retained without automatic expiry. Set `operations.max-records` for the expected workload. Before reaching the limit, increase capacity and restart, or archive old records according to the external application's retention policy.

For archiving, stop the server, take a consistent backup of the entire `operations/` directory, and coordinate a cutoff with clients. Only remove terminal records whose business identifiers can never be retried. Removing a record allows that idempotency key to execute again. Do not delete a journal just to clear a failure. A corrupt JSON record or locked/unwritable store prevents startup; restore from a consistent backup and reconcile externally before reopening the API. `.tmp` files left by an interrupted write are not accepted as reservations; the committed `.json` is authoritative.

## Timeout and shutdown recovery

A queued action that expires never executes later. A running action can have partial effects and may finish after its public timeout. Dangerous-action exclusion stays held until the actual handler returns. Plugin shutdown marks unfinished operations cancelled; a process crash leaves them to recover as failed/interrupted on next startup. The same key replays the recorded outcome. Explicitly reconcile any uncertain reward, payment, file or shutdown action before creating a new operation.

## Rollback

Stop the server, restore the previous plugin and its matching configuration, and retain an untouched backup of the 2.x journal. Version 1 does not understand durable idempotency, so do not keep automatic reward retries enabled during rollback. Never overwrite the game world as part of a WebConnector rollback.

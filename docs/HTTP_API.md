# HTTP API

[Home](../README.md) · [OpenAPI 3.0](openapi.yml) · [Русский](ru/API.md)

All endpoints require the configured authentication header. Bodies and responses are JSON, and all responses include a generated `request_id`, also returned in `X-Request-ID`. Payloads are never logged by WebConnector.

## Execute an action

```http
POST /api/grant-pass
X-Shared-Secret: <private API key>
Content-Type: application/json
Idempotency-Key: order-10452
Prefer: respond-async

{"player":"Steve","pass":"premium"}
```

`Prefer: respond-async` is optional. Actions configured with `async: true` behave the same way. Empty bodies mean `{}` for compatibility; non-empty bodies require `application/json`. Duplicate JSON fields, malformed JSON, excessive nesting, extra payload fields and oversized bodies are rejected. Requests with a query string or encoded path segments are not action endpoints.

Synchronous completion:

```json
{"status":"success","request_id":"...","operation_id":"...","operation_request_id":"...","replayed":false,"result":{"successful":true,"code":"success","message":"Completed"}}
```

Pending work returns `202`:

```json
{"status":"accepted","request_id":"...","operation_id":"...","operation_request_id":"...","replayed":false}
```

The `Location` header points to `/api/operations/<id>`. A completed replay may return `200` even when asynchronous handling was requested. If the synchronous wait expires while work is pending, the server returns `202` when the connection is still open. Clients should use an HTTP timeout longer than the configured request timeout and retain their idempotency key after a disconnect.

## Poll an operation

```http
GET /api/operations/4d229d42-b471-4816-acbb-e3f374e7e53b
X-Shared-Secret: <the same named API key>
```

```json
{
  "status":"completed",
  "request_id":"...",
  "operation": {
    "id":"4d229d42-b471-4816-acbb-e3f374e7e53b",
    "action":"grant-pass",
    "created_at":"2026-09-19T10:20:00Z",
    "completed_at":"2026-09-19T10:20:01Z",
    "state":"COMPLETED",
    "result":{"successful":true,"code":"success","message":"Completed"},
    "initiator":"key:shop",
    "request_id":"..."
  }
}
```

States are `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` and `CANCELLED`. `result` and `completed_at` are omitted until terminal. A valid status lookup returns `200` even for a failed operation; inspect `operation.state`. Only the original key identity, still scoped to the action, can read its operation. Other callers receive `404`.

## Idempotency

An `Idempotency-Key` is 1–128 characters from `[A-Za-z0-9._:-]`. Its scope is the stable caller identity across all actions. The same key with the same action and validated payload returns the same operation; a changed action or payload returns `409`. Keep key names stable across secret rotation.

Reservations are atomically persisted and flushed before executing any handler. They survive normal restarts. Interrupted operations become `FAILED` with `interrupted` and are never automatically re-executed. This prevents automatic duplicate execution, but does not provide a distributed transaction or rollback. A process crash, timeout, disk failure, command failure or downstream plugin failure can leave partial side effects. Reconcile the external order and server state before deliberately creating a new key. Keep and back up the journal; deleting it removes duplicate protection.

`request_id` identifies the current HTTP request. `operation_request_id` identifies the original request that created the operation. Retries have a new request ID and the original operation ID. There is no public arbitrary-command, filesystem, action-registration or operation-list endpoint.

## Response codes

| Code | Meaning | Client behavior |
| --- | --- | --- |
| 200 | Completed action or retrieved operation | Read result/state |
| 202 | Accepted, pending operation | Poll `Location` with the same key |
| 400 | Invalid JSON/schema/header/body/key | Fix the request |
| 401 | Missing, invalid, disabled or expired key | Check credentials |
| 403 | IP/action/permission/dangerous policy denied | Check scopes and server policy |
| 404 | Unknown/private action or inaccessible operation | Check path and caller identity |
| 405 | Method not enabled | Read `Allow` |
| 409 | Idempotency conflict or dangerous operation active | Preserve the key; inspect conflict |
| 429 | Rate limit, queue or journal full | Respect `Retry-After`; journal-full needs maintenance |
| 500 | Handler/storage/internal failure | Inspect operation before retrying |

Rejected requests use `{"status":"error","request_id":"...","code":"...","message":"..."}`. A handler failure also includes `operation_id` and `result`; its details are safe public messages. Raw exception messages and secrets are not returned.

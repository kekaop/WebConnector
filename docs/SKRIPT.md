# Skript integration

[Home](../README.md) · [Examples](../examples/skript/) · [Русский](ru/API.md)

WebConnector uses standard HTTP/JSON. No dedicated Skript addon is required. Install Skript and **one** suitable HTTP addon, then load its example. Addon versions support different Minecraft/Skript ranges; WebConnector's own 1.20.1–26.3 target does not extend an addon's compatibility.

| Addon | Example/reference version | Notes |
| --- | --- | --- |
| [SkJson](https://github.com/cooffeeRequired/skJson) | [6.0.0 example](../examples/skript/skjson.sk) | Request-scoped response; explicit JSON support. Its plugin API baseline is 1.21, so use an appropriate older release on 1.20.x. |
| [SkriptWebAPI](https://github.com/faketunaPrivateCamp/SkriptWebAPI) | [v0.1.2 example](../examples/skript/skriptwebapi.sk) | Use async requests and the response event; upstream documents official support starting at 1.20.2. |
| [SkHttp](https://github.com/Fusezion/SkHttp) | [1.5 example](../examples/skript/skhttp.sk) | Header/JSON transport works through the standard API; this version's `last response` is global. Serialize diagnostics and prefer request-scoped clients for concurrent business work. |

The examples are checked against the corresponding upstream syntax/source: [SkJson HTTP registration](https://github.com/cooffeeRequired/skJson/blob/6.0.0/src/main/java/cz/coffeerequired/modules/HttpModule.java), [SkriptWebAPI example](https://github.com/faketunaPrivateCamp/SkriptWebAPI/blob/v0.1.2/example.sk), [SkHttp request builder](https://github.com/Fusezion/SkHttp/blob/1.5/src/main/java/lol/aabss/skhttp/elements/http/sections/SecRequestBuilder.java). The HTTP contract is tested with real requests. Validate addon loading and script parsing on the chosen server/Skript combination before deploying; source review alone is not a live-addon certification.

## Workflow

1. Enable and configure `grant-pass`, install its command provider, and grant the client key access to that action.
2. Store the API secret in a private server-side variable/configuration loader, setting `{webconnector.secret}`. Do not commit secrets in public `.sk` files, print them, broadcast them or pass them through player-visible commands.
3. Run the example's console-only grant command with the external order ID, such as `wc-json-grant order-10452`. The sample player/pass are fixed; change them in a reviewed integration.
4. On `202`, retain `operation_id` and call the example's poll command with that UUID. Polling uses GET with the same named key.
5. Read `operation.state` and `result`. `200` for a status lookup does not imply success.

The examples print operation responses only to the server console. They demonstrate JSON POST, authenticated GET, idempotency and error handling without a custom addon. Business integrations should parse the returned JSON and store their order-to-operation mapping durably.

Do not synchronously block the Minecraft main thread while calling an action that needs that same thread. SkJson's `execute` effect in the referenced version waits on an asynchronous worker; SkriptWebAPI and SkHttp examples use explicit async sending. For 400/401/403/404/405, fix configuration/request errors. For 409, inspect the conflict. For 429, respect backoff. After 500 or a network timeout, inspect/retry the **same** key; a new key can repeat partial effects.

SkHttp 1.5 shares response state across scripts. The example's guard serializes only its own calls; unrelated SkHttp traffic can still replace the global response. Do not use that mechanism to confirm payments. Prefer the request-scoped SkJson example or a Java/HTTP integration for concurrent transactions.

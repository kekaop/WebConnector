# Java API

[Home](../README.md) · [Example plugin](../examples/java/) · [Русский](ru/API.md)

Compile against `WebConnector-2.0.0-api.jar` from the release:

```groovy
dependencies {
    compileOnly files('libs/WebConnector-2.0.0-api.jar')
    compileOnly 'org.spigotmc:spigot-api:1.20.1-R0.1-SNAPSHOT'
}
```

Declare `depend: [WebConnector]` in your `plugin.yml`. Do not shade the API into your plugin; Bukkit must share the service interface's class identity. The API consists of Java 17 classes in `com.eldryn.webconnector.api` and has no NMS dependency.

```java
var registration = Bukkit.getServicesManager().getRegistration(WebConnectorAPI.class);
if (registration == null) throw new IllegalStateException("WebConnector unavailable");
WebConnectorAPI api = registration.getProvider();

api.registerAction(ActionDefinition.builder("shop.grant")
    .description("Grant a configured pass")
    .parameter("player", Parameter.required(Parameter.Type.PLAYER_NAME))
    .parameter("pass", Parameter.enumeration("vip", "premium"))
    .permission("shop.grant")
    .requireIdempotency(true)
    .exposeHttp(true)
    .handler(context -> {
        context.checkDeadline();
        // Perform your plugin's server-thread operation here.
        return ActionResult.success();
    }).build());
```

`registerAction` rejects duplicate names. `unregisterAction` removes programmatic actions; configured actions are managed through configuration. Unregister your actions in `onDisable`. Existing submitted operations retain their captured handlers, so coordinate shutdown for long-running handlers.

Handlers run on the server thread by default. `mainThread(false)` selects a bounded worker thread for pure Java/network work; do not access Bukkit world or player state there. Choose `timeout(Duration)` up to five minutes, check the context deadline between side effects, and do not block the server thread. Java actions are private unless `exposeHttp(true)` is set.

## Calling actions

```java
Caller caller = Caller.plugin(getName());
Submission submission = api.submit("shop.grant",
    Map.of("player", "Steve", "pass", "premium"), caller, "order-10452");

submission.completion().thenAccept(result -> {
    // Completion thread is not guaranteed. Schedule Bukkit work explicitly.
    getLogger().info("Operation " + submission.operationId() + ": " + result.code());
});
```

`Caller.plugin(name)` is a trusted local caller with all action and permission scopes but **without** dangerous-action rights. Construct an explicit `Caller` to allow a dangerous internal call. Java plugins run inside the trusted server process; these caller claims cannot isolate malicious plugins. Only the HTTP adapter derives caller claims from external keys.

Convenience methods `executeAsync(action, payload)` and `submit(action, payload)` use the shared `plugin:java` identity and no idempotency key. Use the explicit overload for business transactions or separate plugin identities. `execute(action, payload)` blocks and rejects calls from the server thread. Submission performs a short durable journal write before returning; completion never requires the caller to block on Bukkit work.

`getAction`, `hasAction`, `getActions`, `getOperation` and `getOperations` return immutable definitions/snapshots. `ActionException` provides a safe `code()` and HTTP-equivalent `httpStatus()` for policy or validation rejections. Execution failure is an `ActionResult` rather than a raw throwable. Cancelling a returned completion future does not cancel or re-execute the underlying operation.

`publishEvent("shop.granted", Map.of(...))` enqueues data for matching webhook routes. Define a route with `type: shop.granted` and omit `event-class` for a pure Java event. Payloads must be JSON-serializable values; snapshot Bukkit objects into scalar fields on the appropriate server thread before publishing.

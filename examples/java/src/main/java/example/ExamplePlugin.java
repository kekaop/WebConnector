package example;

import com.eldryn.webconnector.api.*;
import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Compile-only API consumer. Safe smoke-test actions with no game-world side effects. */
public final class ExamplePlugin extends JavaPlugin {
    private WebConnectorAPI api;
    private final AtomicInteger calls = new AtomicInteger();
    @Override public void onEnable() {
        var registration = Bukkit.getServicesManager().getRegistration(WebConnectorAPI.class);
        if (registration == null) throw new IllegalStateException("WebConnector service is unavailable");
        api = registration.getProvider();
        api.registerAction(ActionDefinition.builder("example.echo")
                .description("Return a player name and invocation counter")
                .parameter("player", Parameter.required(Parameter.Type.PLAYER_NAME))
                .requireIdempotency(true).exposeHttp(true)
                .handler(context -> {
                    if (!Bukkit.isPrimaryThread()) throw new IllegalStateException("Expected server thread");
                    api.publishEvent("example.echo", Map.of("player", context.payload().get("player")));
                    return new ActionResult(true, "success", "Echo " + context.payload().get("player") + " (#" + calls.incrementAndGet() + ")");
                }).build());
        api.registerAction(ActionDefinition.builder("example.private").handler(c -> ActionResult.success()).build());
        api.executeAsync("example.private", Map.of()).thenAccept(result -> {
            if (result.successful()) getLogger().info("WebConnector Java API smoke test passed");
        });
    }
    @Override public void onDisable() {
        if (api != null) { api.unregisterAction("example.echo"); api.unregisterAction("example.private"); }
    }
}

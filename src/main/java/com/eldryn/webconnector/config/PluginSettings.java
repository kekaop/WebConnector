package com.eldryn.webconnector.config;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.http.*;
import com.eldryn.webconnector.events.WebhookDispatcher;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import java.net.*;
import java.time.*;
import java.util.*;

public record PluginSettings(HttpGateway.Settings http, SecurityPolicy security, List<ConfiguredAction> actions,
                             boolean deleteEnabled, List<String> fileRoots, int workerThreads, int actionQueue,
                             int keyLimit, int actionLimit, int journalCapacity, String serverName,
                             int webhookCapacity, int webhookAttempts, int webhookTimeout, int webhookBackoff,
                             List<WebhookDispatcher.Route> routes, List<EventBinding> bindings) {
    public record ConfiguredAction(ActionDefinition.Builder builder, List<String> commands, List<String> files, boolean shutdown, long shutdownDelay) { }
    public record EventBinding(String route, String eventClass, String type, String priority, boolean ignoreCancelled, Map<String, String> payload) { }
    public static PluginSettings read(YamlConfiguration config) {
        if (config.getInt("config-version", 0) != 2) throw new IllegalArgumentException("Configuration version 2 is required. Back up config.yml and follow docs/MIGRATION.md; the original file was not changed.");
        String host = config.getString("server.host", "127.0.0.1");
        String path = config.getString("server.path", "/api");
        if (!path.matches("(/[A-Za-z0-9_-]+)+")) throw new IllegalArgumentException("server.path must contain simple non-empty path segments");
        String header = config.getString("security.shared-secret-header", "X-Shared-Secret");
        if (!header.matches("[A-Za-z][A-Za-z0-9-]{0,63}") || Set.of("host", "content-length", "content-type", "idempotency-key", "prefer").contains(header.toLowerCase(Locale.ROOT))) throw new IllegalArgumentException("Invalid authentication header");
        Set<String> methods = new HashSet<>(strings(config, "server.allowed-methods", List.of("POST")));
        if (methods.isEmpty() || !Set.of("POST", "PUT", "PATCH").containsAll(methods)) throw new IllegalArgumentException("Actions accept only POST, PUT or PATCH; operation polling always uses GET");
        boolean development = config.getBoolean("security.development-mode", false);
        boolean local = config.getBoolean("security.allow-unauthenticated-localhost", false);
        boolean require = config.getBoolean("security.require-authentication", true);
        if (!require || local) {
            try { if (!development || !local || !InetAddress.getByName(host).isLoopbackAddress()) throw new IllegalArgumentException(); }
            catch (Exception e) { throw new IllegalArgumentException("Unauthenticated development requires development-mode, allow-unauthenticated-localhost and a loopback bind address"); }
        }
        List<SecurityPolicy.Key> keys = new ArrayList<>();
        String sharedSecret = config.getString("security.shared-secret", "");
        if (!sharedSecret.isBlank()) keys.add(new SecurityPolicy.Key("shared", sharedSecret, true, null,
                Set.copyOf(strings(config, "security.shared-secret-actions", List.of())),
                Set.copyOf(strings(config, "security.shared-secret-permissions", List.of())), config.getBoolean("security.shared-secret-allow-dangerous", false)));
        ConfigurationSection keySection = config.getConfigurationSection("security.api-keys");
        if (keySection != null) for (var entry : keySection.getValues(false).entrySet()) {
            ConfigurationSection c = section(entry.getValue(), "API key");
            String expires = c.getString("expires-at", "");
            keys.add(new SecurityPolicy.Key(entry.getKey(), c.getString("secret", ""), c.getBoolean("enabled", true), expires.isBlank() ? null : Instant.parse(expires),
                    Set.copyOf(c.getStringList("actions")), Set.copyOf(c.getStringList("permissions")), c.getBoolean("allow-dangerous", false)));
        }
        SecurityPolicy policy = new SecurityPolicy(keys, config.getStringList("security.ip-allowlist"), development && local);
        int baseLimit = number(config, "limits.rate-limit-per-minute", 60, 1, 1000000);
        HttpGateway.Settings http = new HttpGateway.Settings(host, number(config, "server.port", 25575, 1, 65535), path, header,
                number(config, "limits.max-body-size-kb", 64, 1, 1024) * 1024,
                number(config, "limits.request-timeout-seconds", 10, 1, 300), number(config, "limits.ip-per-minute", baseLimit, 1, 1000000),
                number(config, "limits.http-threads", 4, 1, 32), Set.copyOf(methods));
        List<ConfiguredAction> actions = new ArrayList<>();
        ConfigurationSection actionSection = config.getConfigurationSection("actions");
        if (actionSection != null) for (var entry : actionSection.getValues(false).entrySet()) {
            ConfigurationSection c = section(entry.getValue(), "action");
            if (!c.getBoolean("enabled", true)) continue;
            boolean shutdown = c.getBoolean("shutdown", false);
            List<String> files = c.getStringList("delete-files"), commands = c.getStringList("commands");
            ActionDefinition.Builder builder = ActionDefinition.builder(entry.getKey()).description(c.getString("description", ""))
                    .timeout(Duration.ofSeconds(number(c, "timeout-seconds", 10, 1, 300)))
                    .exposeHttp(c.getBoolean("expose-http", true)).dangerous(c.getBoolean("dangerous", false) || shutdown || !files.isEmpty())
                    .asynchronous(c.getBoolean("async", false)).requireIdempotency(c.getBoolean("require-idempotency", shutdown || !files.isEmpty()))
                    .permission(c.getString("permission", ""));
            ConfigurationSection validation = c.getConfigurationSection("validation");
            Set<String> parameters = new HashSet<>();
            if (validation != null) for (var v : validation.getValues(false).entrySet()) {
                ConfigurationSection p = section(v.getValue(), "validation rule");
                Parameter.Type type = Parameter.Type.valueOf(p.getString("type", "string").toUpperCase(Locale.ROOT));
                builder.parameter(v.getKey(), new Parameter(type, p.getBoolean("required", true), number(p, "max-length", 256, 1, 8192),
                        integerBound(p, "min"), integerBound(p, "max"),
                        Set.copyOf(p.getStringList("allowed")), p.getString("pattern")));
                parameters.add(v.getKey());
            }
            if (parameters.contains("player")) for (String alias : strings(config, "payload.player-name-keys", List.of("player_name", "player", "name")))
                if (!parameters.contains(alias)) builder.alias(alias, "player");
            if (parameters.contains("uuid")) for (String alias : strings(config, "payload.player-uuid-keys", List.of("player_uuid", "uuid")))
                if (!parameters.contains(alias)) builder.alias(alias, "uuid");
            for (String command : commands) CommandTemplate.validate(command, parameters);
            actions.add(new ConfiguredAction(builder, List.copyOf(commands), List.copyOf(files), shutdown, number(c, "shutdown-delay-ticks", 20, 1, 1200)));
        }
        List<WebhookDispatcher.Route> routes = new ArrayList<>(); List<EventBinding> bindings = new ArrayList<>();
        ConfigurationSection eventRoutes = config.getConfigurationSection("event-routes");
        if (config.getBoolean("event-dispatch.enabled", false) && eventRoutes != null) for (var entry : eventRoutes.getValues(false).entrySet()) {
            ConfigurationSection c = section(entry.getValue(), "event route");
            if (!c.getBoolean("enabled", true)) continue;
            if (!c.getString("method", "POST").equals("POST") || !config.getString("event-dispatch.method", "POST").equals("POST")) throw new IllegalArgumentException("Webhook routes use POST");
            String type = c.getString("type", defaultType(entry.getKey()));
            Map<String, String> headers = mapping(config.getConfigurationSection("event-dispatch.headers"));
            headers.putAll(mapping(c.getConfigurationSection("headers")));
            routes.add(new WebhookDispatcher.Route(entry.getKey(), type, URI.create(c.getString("endpoint", config.getString("event-dispatch.base-url", ""))),
                    c.getString("signing-secret", config.getString("event-dispatch.signing-secret", "")), headers, mapping(c.getConfigurationSection("filters")),
                    c.getBoolean("legacy-payload", false), config.getString("event-dispatch.event-name-field", "event")));
            String eventClass = c.getString("event-class", entry.getKey().endsWith("Event") ? entry.getKey() : "");
            if (!eventClass.isBlank()) bindings.add(new EventBinding(entry.getKey(), eventClass, type, c.getString("priority", "MONITOR"), c.getBoolean("ignore-cancelled", true), mapping(c.getConfigurationSection("payload"))));
        }
        return new PluginSettings(http, policy, List.copyOf(actions), config.getBoolean("files.enabled", false), config.getStringList("files.allowed-roots"),
                number(config, "limits.action-threads", 2, 1, 16), number(config, "limits.action-queue", 128, 1, 10000),
                number(config, "limits.key-per-minute", baseLimit, 1, 1000000), number(config, "limits.action-per-minute", baseLimit, 1, 1000000),
                number(config, "operations.max-records", 10000, 1, 1000000), config.getString("server.name", "minecraft"),
                number(config, "event-dispatch.queue-capacity", 512, 1, 100000), number(config, "event-dispatch.max-attempts", 5, 1, 10),
                number(config, "event-dispatch.timeout-seconds", 5, 1, 60), number(config, "event-dispatch.backoff-millis", 1000, 10, 60000), List.copyOf(routes), List.copyOf(bindings));
    }
    private static String defaultType(String event) { return switch (event) { case "PlayerJoinEvent" -> "player.join"; case "PlayerQuitEvent" -> "player.quit"; case "PlayerFirstJoinEvent" -> "player.first_join"; default -> event; }; }
    private static int number(ConfigurationSection c, String key, int fallback, int min, int max) {
        if (c.contains(key) && !c.isInt(key)) throw new IllegalArgumentException("Expected integer setting: " + key);
        int value = c.getInt(key, fallback); if (value < min || value > max) throw new IllegalArgumentException("Setting out of range: " + key); return value;
    }
    private static ConfigurationSection section(Object value, String label) {
        if (!(value instanceof ConfigurationSection c)) throw new IllegalArgumentException("Expected YAML section for " + label); return c;
    }
    private static Long integerBound(ConfigurationSection section, String name) {
        if (!section.contains(name)) return null;
        Object value = section.get(name);
        if (!(value instanceof Integer) && !(value instanceof Long)) throw new IllegalArgumentException("Integer bounds must be whole JSON/YAML numbers");
        return ((Number) value).longValue();
    }
    private static List<String> strings(ConfigurationSection c, String key, List<String> fallback) { return c.contains(key) ? c.getStringList(key) : fallback; }
    private static Map<String, String> mapping(ConfigurationSection c) {
        Map<String, String> result = new LinkedHashMap<>();
        if (c != null) c.getValues(false).forEach((k, v) -> result.put(k, String.valueOf(v))); return result;
    }
    /** Settings that require restart; reload cannot discard active operations. */
    public boolean sameRuntime(PluginSettings other) {
        return http.equals(other.http) && workerThreads == other.workerThreads && actionQueue == other.actionQueue
                && keyLimit == other.keyLimit && actionLimit == other.actionLimit && journalCapacity == other.journalCapacity
                && serverName.equals(other.serverName) && webhookCapacity == other.webhookCapacity && webhookAttempts == other.webhookAttempts
                && webhookTimeout == other.webhookTimeout && webhookBackoff == other.webhookBackoff;
    }
}

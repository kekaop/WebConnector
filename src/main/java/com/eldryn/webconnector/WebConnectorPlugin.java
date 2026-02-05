package com.eldryn.webconnector;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class WebConnectorPlugin extends JavaPlugin implements Listener {
    private static final String HEADER_SHARED_SECRET = "X-Shared-Secret";

    private final Gson gson = new Gson();
    private final Type mapType = new TypeToken<Map<String, Object>>() {}.getType();

    private HttpServer server;

    private String sharedSecret;
    private String sharedSecretHeader;
    private String pluginHost;
    private int pluginPort;
    private String pluginPath;
    private boolean debugLogging;
    private List<String> allowedMethods;
    private List<String> playerNameKeys;
    private List<String> playerUuidKeys;
    private Map<String, ActionDefinition> actions = new HashMap<>();
    private EventDispatchConfig eventDispatchConfig;
    private Map<Class<?>, EventDispatchRule> eventDispatchRules = new HashMap<>();
    private HttpClient httpClient;
    private ExecutorService eventExecutor;
    private Listener eventListener;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadConfigValues();

        startHttpServer();
        startEventDispatcher();

        getServer().getPluginManager().registerEvents(this, this);
    }

    @Override
    public void onDisable() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (eventExecutor != null) {
            eventExecutor.shutdownNow();
            eventExecutor = null;
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (!event.getPlayer().hasPlayedBefore()) {
            Bukkit.getPluginManager().callEvent(new PlayerFirstJoinEvent(event.getPlayer()));
        }
    }

    private void loadConfigValues() {
        reloadConfig();
        sharedSecret = getConfig().getString("shared-secret", "");
        sharedSecretHeader = getConfig().getString("shared-secret-header", HEADER_SHARED_SECRET);
        pluginHost = getConfig().getString("plugin-host", "0.0.0.0");
        pluginPort = getConfig().getInt("plugin-port", 25575);
        pluginPath = normalizePath(getConfig().getString("plugin-path", "/api"));
        debugLogging = getConfig().getBoolean("debug-logging", false);
        allowedMethods = normalizeMethods(getConfig().getStringList("allowed-methods"));
        playerNameKeys = listOrDefault(getConfig().getStringList("payload.player-name-keys"),
                List.of("player_name", "player", "name"));
        playerUuidKeys = listOrDefault(getConfig().getStringList("payload.player-uuid-keys"),
                List.of("player_uuid", "uuid"));
        actions = loadActions();
        eventDispatchConfig = loadEventDispatchConfig();
        eventDispatchRules = loadEventDispatchRules();
    }

    private void startHttpServer() {
        try {
            server = HttpServer.create(new InetSocketAddress(pluginHost, pluginPort), 0);
            server.createContext(pluginPath, this::handleIncomingRequest);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            getLogger().info("WebConnector API listening on " + pluginHost + ":" + pluginPort + pluginPath);
        } catch (IOException exception) {
            getLogger().severe("Failed to start WebConnector API: " + exception.getMessage());
        }
    }

    private void startEventDispatcher() {
        if (eventDispatchConfig == null || !eventDispatchConfig.enabled) {
            return;
        }
        if (eventDispatchConfig.baseUrl == null || eventDispatchConfig.baseUrl.isBlank()) {
            getLogger().warning("Event dispatch enabled, but event-dispatch.base-url is empty.");
            return;
        }
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        eventExecutor = Executors.newCachedThreadPool();
        eventListener = new Listener() {};

        for (Map.Entry<Class<?>, EventDispatchRule> entry : eventDispatchRules.entrySet()) {
            Class<?> eventClass = entry.getKey();
            EventDispatchRule rule = entry.getValue();
            try {
                Bukkit.getPluginManager().registerEvent(
                        (Class<? extends org.bukkit.event.Event>) eventClass,
                        eventListener,
                        rule.priority,
                        (listener, event) -> dispatchEvent(rule, event),
                        this,
                        rule.ignoreCancelled
                );
            } catch (Exception exception) {
                getLogger().warning("Failed to register event " + eventClass.getName() + ": " + exception.getMessage());
            }
        }
    }

    private void handleIncomingRequest(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            if (!allowedMethods.contains(method.toUpperCase())) {
                sendResponse(exchange, 405, jsonStatus("method_not_allowed"));
                return;
            }

            Headers headers = exchange.getRequestHeaders();
            String incomingSecret = headers.getFirst(sharedSecretHeader);
            if (sharedSecret != null && !sharedSecret.isBlank()
                    && (incomingSecret == null || !incomingSecret.equals(sharedSecret))) {
                sendResponse(exchange, 401, jsonStatus("unauthorized"));
                return;
            }

            String path = exchange.getRequestURI().getPath();
            String action = extractAction(path);
            if (action.isEmpty()) {
                sendResponse(exchange, 404, jsonStatus("not_found"));
                return;
            }

            ActionDefinition definition = actions.get(action);
            if (definition == null || !definition.enabled) {
                sendResponse(exchange, 404, jsonStatus("not_found"));
                return;
            }

            String body = readBody(exchange.getRequestBody());
            Map<String, Object> payload = parsePayload(body);
            if (payload == null) {
                sendResponse(exchange, 400, jsonStatus("invalid_json"));
                return;
            }

            logDebug("Incoming action=" + action + " payload=" + payload);
            handleAction(exchange, action, payload, definition);
        } catch (Exception exception) {
            getLogger().warning("Incoming request error: " + exception.getMessage());
            sendResponse(exchange, 500, jsonStatus("server_error"));
        } finally {
            exchange.close();
        }
    }

    private void handleAction(HttpExchange exchange,
                              String action,
                              Map<String, Object> payload,
                              ActionDefinition definition) throws Exception {
        Map<String, String> placeholders = buildPlaceholders(action, payload);
        callSync(() -> {
            for (String raw : definition.commands) {
                String command = applyPlaceholders(raw, placeholders);
                if (!command.isBlank()) {
                    Bukkit.dispatchCommand(Bukkit.getConsoleSender(), command);
                }
            }
            for (String file : definition.deleteFiles) {
                try {
                    Path path = Path.of(file);
                    Files.deleteIfExists(path);
                    logDebug("Deleted file " + path + " due to action " + action);
                } catch (Exception exception) {
                    getLogger().warning("Failed to delete " + file + ": " + exception.getMessage());
                }
            }
            if (definition.shutdown) {
                Bukkit.getScheduler().runTaskLater(this, Bukkit::shutdown, definition.shutdownDelayTicks);
            }
            return null;
        });
        sendResponse(exchange, 200, jsonStatus("ok"));
    }

    private String readBody(InputStream input) throws IOException {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }

    private Map<String, Object> parsePayload(String body) {
        if (body == null || body.isBlank()) {
            return new HashMap<>();
        }
        try {
            Map<String, Object> payload = gson.fromJson(body, mapType);
            return payload == null ? new HashMap<>() : payload;
        } catch (Exception exception) {
            logDebug("Invalid JSON payload: " + exception.getMessage());
            return null;
        }
    }

    private void sendResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
    }

    private String jsonStatus(String status) {
        return gson.toJson(Collections.singletonMap("status", status));
    }

    private void dispatchEvent(EventDispatchRule rule, org.bukkit.event.Event event) {
        if (eventDispatchConfig == null || !eventDispatchConfig.enabled) {
            return;
        }
        String endpoint = rule.endpointOverride == null || rule.endpointOverride.isBlank()
                ? eventDispatchConfig.baseUrl
                : rule.endpointOverride;
        if (endpoint.isBlank()) {
            return;
        }

        Map<String, Object> payload = buildEventPayload(rule, event);
        String jsonBody = gson.toJson(payload);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofSeconds(eventDispatchConfig.timeoutSeconds))
                .method(rule.method, HttpRequest.BodyPublishers.ofString(jsonBody))
                .header("Content-Type", "application/json; charset=utf-8");

        for (Map.Entry<String, String> header : eventDispatchConfig.headers.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }

        httpClient.sendAsync(builder.build(), HttpResponse.BodyHandlers.discarding())
                .whenCompleteAsync((response, throwable) -> {
                    if (throwable != null) {
                        logDebug("Event dispatch failed: " + throwable.getMessage());
                        return;
                    }
                    if (response.statusCode() >= 400) {
                        logDebug("Event dispatch returned " + response.statusCode() + " for " + rule.eventName);
                    }
                }, eventExecutor);
    }

    private Map<String, Object> buildEventPayload(EventDispatchRule rule, org.bukkit.event.Event event) {
        Map<String, Object> payload = new HashMap<>();
        if (rule.includeEventName) {
            payload.put("event", rule.eventName);
        }
        if (rule.includeTimestamp) {
            payload.put("timestamp", Instant.now().toString());
        }
        if (!rule.payloadMappings.isEmpty()) {
            for (Map.Entry<String, String> entry : rule.payloadMappings.entrySet()) {
                payload.put(entry.getKey(), resolveEventTemplate(event, entry.getValue()));
            }
        }
        return payload;
    }

    private String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        if (normalized.endsWith("/") && normalized.length() > 1) {
            return normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String extractAction(String path) {
        if (!path.startsWith(pluginPath)) {
            return "";
        }
        String remainder = path.substring(pluginPath.length());
        if (remainder.startsWith("/")) {
            remainder = remainder.substring(1);
        }
        return remainder;
    }

    private PlayerRef extractPlayerRef(Map<String, Object> payload) {
        String name = stringValue(payload, playerNameKeys);
        String uuidRaw = stringValue(payload, playerUuidKeys);
        UUID uuid = null;
        if (uuidRaw != null && !uuidRaw.isBlank()) {
            try {
                uuid = UUID.fromString(uuidRaw);
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }
        if (uuid == null && (name == null || name.isBlank())) {
            return null;
        }
        return new PlayerRef(name, uuid);
    }

    private String stringValue(Map<String, Object> payload, List<String> keys) {
        for (String key : keys) {
            Object value = payload.get(key);
            if (value != null) {
                return String.valueOf(value);
            }
        }
        return null;
    }

    private Map<String, String> buildPlaceholders(String action, Map<String, Object> payload) {
        Map<String, String> placeholders = new HashMap<>();
        placeholders.put("action", action);

        PlayerRef ref = extractPlayerRef(payload);
        if (ref != null) {
            if (ref.name != null) {
                placeholders.put("player", ref.name);
            }
            if (ref.uuid != null) {
                placeholders.put("uuid", ref.uuid.toString());
            }
        }

        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            placeholders.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
        return placeholders;
    }

    private String applyPlaceholders(String command, Map<String, String> placeholders) {
        String result = command;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            result = result.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return result;
    }

    private String resolveEventTemplate(org.bukkit.event.Event event, String template) {
        if (template == null) {
            return "";
        }
        String result = template;
        int start = result.indexOf("{");
        while (start >= 0) {
            int end = result.indexOf("}", start + 1);
            if (end < 0) {
                break;
            }
            String token = result.substring(start + 1, end).trim();
            String replacement = "";
            if (token.toLowerCase(Locale.ROOT).startsWith("event.")) {
                String path = token.substring("event.".length());
                Object value = resolvePath(event, path);
                replacement = value == null ? "" : String.valueOf(value);
            }
            result = result.substring(0, start) + replacement + result.substring(end + 1);
            start = result.indexOf("{", start + replacement.length());
        }
        return result;
    }

    private Object resolvePath(Object root, String path) {
        Object current = root;
        for (String segment : path.split("\\.")) {
            if (current == null || segment.isBlank()) {
                return null;
            }
            String normalized = segment.replace("_", "");
            current = readProperty(current, normalized);
        }
        return current;
    }

    private Object readProperty(Object target, String segment) {
        Class<?> clazz = target.getClass();
        String lower = segment.toLowerCase(Locale.ROOT);
        for (var method : clazz.getMethods()) {
            if (method.getParameterCount() != 0) {
                continue;
            }
            String name = method.getName().toLowerCase(Locale.ROOT);
            String stripped = name.replace("get", "").replace("is", "");
            if (stripped.equals(lower) || name.equals(lower)) {
                try {
                    return method.invoke(target);
                } catch (Exception exception) {
                    logDebug("Event reflection failed: " + exception.getMessage());
                    return null;
                }
            }
        }
        return null;
    }

    private List<String> normalizeMethods(List<String> methods) {
        List<String> normalized = new java.util.ArrayList<>();
        for (String method : methods) {
            if (method != null && !method.isBlank()) {
                normalized.add(method.trim().toUpperCase());
            }
        }
        if (normalized.isEmpty()) {
            normalized.add("POST");
        }
        return normalized;
    }

    private List<String> listOrDefault(List<String> values, List<String> defaults) {
        return values == null || values.isEmpty() ? defaults : values;
    }

    private Map<String, ActionDefinition> loadActions() {
        Map<String, ActionDefinition> loaded = new HashMap<>();
        var section = getConfig().getConfigurationSection("actions");
        if (section == null) {
            return loaded;
        }
        for (String key : section.getKeys(false)) {
            var actionSection = section.getConfigurationSection(key);
            if (actionSection == null) {
                continue;
            }
            boolean enabled = actionSection.getBoolean("enabled", true);
            List<String> commands = actionSection.getStringList("commands");
            List<String> deleteFiles = actionSection.getStringList("delete-files");
            boolean shutdown = actionSection.getBoolean("shutdown", false);
            long shutdownDelay = actionSection.getLong("shutdown-delay-ticks", 1L);
            loaded.put(key, new ActionDefinition(
                    enabled,
                    commands == null ? List.of() : commands,
                    deleteFiles == null ? List.of() : deleteFiles,
                    shutdown,
                    shutdownDelay
            ));
        }
        return loaded;
    }

    private EventDispatchConfig loadEventDispatchConfig() {
        var section = getConfig().getConfigurationSection("event-dispatch");
        if (section == null) {
            return new EventDispatchConfig(false, "", "POST", 5, Map.of());
        }
        boolean enabled = section.getBoolean("enabled", false);
        String baseUrl = section.getString("base-url", "");
        String method = normalizeHttpMethod(section.getString("method", "POST"));
        int timeout = section.getInt("timeout-seconds", 5);
        Map<String, String> headers = new HashMap<>();
        var headerSection = section.getConfigurationSection("headers");
        if (headerSection != null) {
            for (String key : headerSection.getKeys(false)) {
                headers.put(key, String.valueOf(headerSection.get(key)));
            }
        }
        return new EventDispatchConfig(enabled, baseUrl, method, timeout, headers);
    }

    private Map<Class<?>, EventDispatchRule> loadEventDispatchRules() {
        Map<Class<?>, EventDispatchRule> rules = new HashMap<>();
        var section = getConfig().getConfigurationSection("event-routes");
        if (section == null) {
            return rules;
        }
        for (String eventKey : section.getKeys(false)) {
            var eventSection = section.getConfigurationSection(eventKey);
            if (eventSection == null) {
                continue;
            }
            Optional<Class<?>> eventClass = resolveEventClass(eventKey);
            if (eventClass.isEmpty()) {
                getLogger().warning("Unknown event class: " + eventKey);
                continue;
            }
            boolean enabled = eventSection.getBoolean("enabled", true);
            if (!enabled) {
                continue;
            }
            String endpointOverride = eventSection.getString("endpoint", "");
            String method = normalizeHttpMethod(eventSection.getString("method", eventDispatchConfig.method));
            String priorityRaw = eventSection.getString("priority", "NORMAL");
            org.bukkit.event.EventPriority priority = parsePriority(priorityRaw);
            boolean ignoreCancelled = eventSection.getBoolean("ignore-cancelled", true);
            boolean includeEventName = eventSection.getBoolean("include-event-name", true);
            boolean includeTimestamp = eventSection.getBoolean("include-timestamp", true);
            Map<String, String> payloadMappings = new HashMap<>();
            var payloadSection = eventSection.getConfigurationSection("payload");
            if (payloadSection != null) {
                for (String key : payloadSection.getKeys(false)) {
                    payloadMappings.put(key, String.valueOf(payloadSection.get(key)));
                }
            }
            EventDispatchRule rule = new EventDispatchRule(
                    eventKey,
                    endpointOverride,
                    method,
                    priority,
                    ignoreCancelled,
                    includeEventName,
                    includeTimestamp,
                    payloadMappings
            );
            rules.put(eventClass.get(), rule);
        }
        return rules;
    }

    private Optional<Class<?>> resolveEventClass(String eventKey) {
        List<String> prefixes = List.of(
                "",
                "org.bukkit.event.",
                "org.bukkit.event.player.",
                "org.bukkit.event.block.",
                "org.bukkit.event.entity.",
                "org.bukkit.event.inventory.",
                "org.bukkit.event.server.",
                "org.bukkit.event.world.",
                "io.papermc.paper.event.",
                "com.destroystokyo.paper.event."
        );
        for (String prefix : prefixes) {
            String name = prefix.isEmpty() ? eventKey : prefix + eventKey;
            try {
                Class<?> clazz = Class.forName(name);
                if (org.bukkit.event.Event.class.isAssignableFrom(clazz)) {
                    return Optional.of(clazz);
                }
            } catch (ClassNotFoundException ignored) {
                // ignore
            }
        }
        return Optional.empty();
    }

    private String normalizeHttpMethod(String raw) {
        if (raw == null || raw.isBlank()) {
            return "POST";
        }
        return raw.trim().toUpperCase(Locale.ROOT);
    }

    private org.bukkit.event.EventPriority parsePriority(String raw) {
        try {
            return org.bukkit.event.EventPriority.valueOf(raw.toUpperCase(Locale.ROOT));
        } catch (Exception exception) {
            return org.bukkit.event.EventPriority.NORMAL;
        }
    }

    private <T> T callSync(CallableTask<T> task) throws Exception {
        if (Bukkit.isPrimaryThread()) {
            return task.call();
        }
        CompletableFuture<T> future = new CompletableFuture<>();
        Bukkit.getScheduler().runTask(this, () -> {
            try {
                future.complete(task.call());
            } catch (Exception exception) {
                future.completeExceptionally(exception);
            }
        });
        return future.get(10, TimeUnit.SECONDS);
    }

    private void logDebug(String message) {
        if (debugLogging) {
            getLogger().info(message);
        }
    }

    private record ActionDefinition(
            boolean enabled,
            List<String> commands,
            List<String> deleteFiles,
            boolean shutdown,
            long shutdownDelayTicks
    ) {}

    private record EventDispatchConfig(
            boolean enabled,
            String baseUrl,
            String method,
            int timeoutSeconds,
            Map<String, String> headers
    ) {}

    private record EventDispatchRule(
            String eventName,
            String endpointOverride,
            String method,
            org.bukkit.event.EventPriority priority,
            boolean ignoreCancelled,
            boolean includeEventName,
            boolean includeTimestamp,
            Map<String, String> payloadMappings
    ) {}

    private record PlayerRef(String name, UUID uuid) {}

    private interface CallableTask<T> {
        T call() throws Exception;
    }
}

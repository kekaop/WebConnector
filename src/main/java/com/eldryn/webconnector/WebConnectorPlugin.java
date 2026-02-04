package com.eldryn.webconnector;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bukkit.Bukkit;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
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

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadConfigValues();

        startHttpServer();

        getServer().getPluginManager().registerEvents(this, this);
    }

    @Override
    public void onDisable() {
        if (server != null) {
            server.stop(0);
            server = null;
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

    private record PlayerRef(String name, UUID uuid) {}

    private interface CallableTask<T> {
        T call() throws Exception;
    }
}

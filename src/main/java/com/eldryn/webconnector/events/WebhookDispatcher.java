package com.eldryn.webconnector.events;

import com.eldryn.webconnector.core.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class WebhookDispatcher implements AutoCloseable {
    public record Route(String name, String type, URI endpoint, String secret, Map<String, String> headers,
                        Map<String, String> filters, boolean legacy, String legacyEventField) {
        public Route {
            if (!Set.of("http", "https").contains(endpoint.getScheme()) || endpoint.getHost() == null || endpoint.getUserInfo() != null || endpoint.getFragment() != null)
                throw new IllegalArgumentException("Webhook endpoint must be an HTTP(S) URL without user info or fragment");
            if (!com.eldryn.webconnector.http.SecurityPolicy.strongSecret(secret)) throw new IllegalArgumentException("Webhook signing secret must have at least 32 characters");
            headers = Map.copyOf(headers); filters = Map.copyOf(filters);
            for (var entry : headers.entrySet()) {
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if (key.startsWith("x-webconnector-") || Set.of("content-type", "content-length", "host", "connection", "expect", "upgrade").contains(key))
                    throw new IllegalArgumentException("Reserved webhook header");
                HttpRequest.newBuilder(endpoint).header(entry.getKey(), entry.getValue());
            }
        }
    }
    private volatile List<Route> routes = List.of();
    private final String serverName;
    private final Duration timeout;
    private final int attempts;
    private final long backoffMillis;
    private final Semaphore capacity;
    private final ScheduledThreadPoolExecutor queue;
    private final HttpClient client;
    private final Logger logger;
    private final AtomicLong sent = new AtomicLong(), failed = new AtomicLong(), dropped = new AtomicLong();
    private volatile boolean closed;
    public WebhookDispatcher(String serverName, int capacity, int attempts, Duration timeout, long backoffMillis, Logger logger) {
        this.serverName = serverName; this.capacity = new Semaphore(capacity); this.attempts = attempts;
        this.timeout = timeout; this.backoffMillis = backoffMillis; this.logger = logger;
        queue = new ScheduledThreadPoolExecutor(2, ActionService.factory("webhooks")); queue.setRemoveOnCancelPolicy(true);
        client = HttpClient.newBuilder().connectTimeout(timeout).followRedirects(HttpClient.Redirect.NEVER).build();
    }
    public void routes(List<Route> routes) { this.routes = List.copyOf(routes); }
    public List<Route> routes() { return routes; }
    public Map<String, Long> statistics() { return Map.of("sent", sent.get(), "failed", failed.get(), "dropped", dropped.get()); }
    public void publish(String type, Map<String, Object> data) { publish(type, data, null); }
    public void publish(String type, Map<String, Object> data, String onlyRoute) {
        if (closed) return;
        if (type == null || !type.matches("[A-Za-z0-9_.-]{1,128}")) throw new IllegalArgumentException("Invalid event type");
        String id = UUID.randomUUID().toString(), timestamp = Instant.now().toString();
        for (Route route : routes) {
            if ((onlyRoute != null && !onlyRoute.equals(route.name())) || !route.type().equals(type)
                    || route.filters().entrySet().stream().anyMatch(f -> !f.getValue().equals(String.valueOf(data.get(f.getKey()))))) continue;
            Map<String, Object> body = new LinkedHashMap<>();
            if (route.legacy()) { body.putAll(data); body.put(route.legacyEventField(), route.name()); }
            else { body.put("type", type); body.put("server", serverName); body.put("data", data); }
            body.put("id", id); body.put("timestamp", timestamp);
            String json = Json.GSON.toJson(body);
            if (json.getBytes(StandardCharsets.UTF_8).length > 65536 || !capacity.tryAcquire()) { dropped.incrementAndGet(); continue; }
            try { queue.execute(() -> deliver(route, id, timestamp, json, 1)); }
            catch (RejectedExecutionException e) { capacity.release(); dropped.incrementAndGet(); }
        }
    }
    private void deliver(Route route, String id, String timestamp, String json, int attempt) {
        if (closed || !routes.contains(route)) { capacity.release(); dropped.incrementAndGet(); return; }
        boolean retry = false;
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(route.endpoint()).timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("X-WebConnector-Id", id).header("X-WebConnector-Timestamp", timestamp)
                    .header("X-WebConnector-Signature", sign(route.secret(), timestamp, json))
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
            route.headers().forEach(builder::header);
            int status = client.send(builder.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
            if (status >= 200 && status < 300) { sent.incrementAndGet(); capacity.release(); return; }
            retry = status == 408 || status == 429 || status >= 500;
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        catch (Exception e) { retry = true; }
        if (retry && attempt < attempts && !closed) {
            long delay = Math.min(60000, backoffMillis * (1L << Math.min(attempt - 1, 16)));
            try { queue.schedule(() -> deliver(route, id, timestamp, json, attempt + 1), delay, TimeUnit.MILLISECONDS); return; }
            catch (RejectedExecutionException ignored) { }
        }
        capacity.release(); failed.incrementAndGet();
        logger.warning("Webhook delivery failed: route=" + route.name() + " event=" + id + " attempts=" + attempt);
    }
    public static String sign(String secret, String timestamp, String json) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal((timestamp + "." + json).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException("Unable to sign webhook", e); }
    }
    @Override public void close() { closed = true; queue.shutdownNow(); }
}

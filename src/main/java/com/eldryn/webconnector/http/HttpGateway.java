package com.eldryn.webconnector.http;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.core.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.util.*;
import java.util.concurrent.*;

public final class HttpGateway implements AutoCloseable {
    public record Settings(String host, int port, String path, String header, int maxBodyBytes,
                           int timeoutSeconds, int ipLimit, int threads, Set<String> methods) { }
    private final ActionService service;
    private volatile SecurityPolicy security;
    private final Settings settings;
    private final HttpServer server;
    private final ThreadPoolExecutor executor;
    private final ScheduledThreadPoolExecutor timer;
    private final RateLimiter ipLimiter = new RateLimiter(20000);
    public HttpGateway(ActionService service, SecurityPolicy security, Settings settings) throws IOException {
        this.service = service; this.security = security; this.settings = settings;
        server = HttpServer.create(new InetSocketAddress(settings.host, settings.port), 64);
        executor = new ThreadPoolExecutor(settings.threads, settings.threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(64), ActionService.factory("http"), new ThreadPoolExecutor.CallerRunsPolicy());
        timer = new ScheduledThreadPoolExecutor(1, ActionService.factory("http-timeouts")); timer.setRemoveOnCancelPolicy(true);
        server.setExecutor(executor); server.createContext("/", this::handle);
    }
    public void start() { server.start(); }
    public int port() { return server.getAddress().getPort(); }
    public Settings settings() { return settings; }
    public void security(SecurityPolicy value) { security = value; }
    private void handle(HttpExchange exchange) throws IOException {
        UUID requestId = UUID.randomUUID();
        ScheduledFuture<?> deadline = timer.schedule(exchange::close, settings.timeoutSeconds + 1L, TimeUnit.SECONDS);
        try {
            if (!ipLimiter.acquire(exchange.getRemoteAddress().getAddress().getHostAddress(), settings.ipLimit))
                throw new ActionException(429, "rate_limited", "Source address rate limit exceeded");
            Caller caller = security.authenticate(exchange.getRemoteAddress().getAddress(), singleHeader(exchange, settings.header));
            String path = exchange.getRequestURI().getRawPath();
            String prefix = settings.path + "/";
            if (!path.startsWith(prefix) || exchange.getRequestURI().getRawQuery() != null || path.contains("%")) throw new ActionException(404, "not_found", "Endpoint not found");
            String resource = path.substring(prefix.length());
            if (resource.startsWith("operations/")) {
                service.limitRead(caller);
                requireMethod(exchange, Set.of("GET"));
                UUID id;
                try { id = UUID.fromString(resource.substring("operations/".length())); }
                catch (IllegalArgumentException e) { throw new ActionException(400, "invalid_operation", "Invalid operation ID"); }
                OperationStatus operation = service.getOperation(id).orElseThrow(() -> new ActionException(404, "not_found", "Operation not found"));
                if (!operation.initiator().equals(caller.name()) || !caller.permits(operation.action())) throw new ActionException(404, "not_found", "Operation not found");
                Map<String, Object> body = envelope(operation.state().name().toLowerCase(Locale.ROOT), requestId);
                body.put("operation", operationBody(operation)); send(exchange, 200, body); return;
            }
            requireMethod(exchange, settings.methods);
            if (!resource.matches("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}")) throw new ActionException(404, "not_found", "Action not found");
            String length = singleHeader(exchange, "Content-Length");
            if (length != null) {
                try { if (Long.parseLong(length) < 0 || Long.parseLong(length) > settings.maxBodyBytes) throw new NumberFormatException(); }
                catch (NumberFormatException e) { throw new ActionException(400, "body_too_large", "Request body exceeds the configured limit"); }
            }
            byte[] bytes = exchange.getRequestBody().readNBytes(settings.maxBodyBytes + 1);
            if (bytes.length > settings.maxBodyBytes) throw new ActionException(400, "body_too_large", "Request body exceeds the configured limit");
            String contentType = singleHeader(exchange, "Content-Type");
            if (bytes.length > 0 && (contentType == null || !contentType.split(";", 2)[0].trim().equalsIgnoreCase("application/json")))
                throw new ActionException(400, "invalid_content_type", "Use Content-Type: application/json");
            Map<String, Object> payload;
            try { payload = Json.object(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()); }
            catch (IllegalArgumentException | java.nio.charset.CharacterCodingException e) { throw new ActionException(400, "invalid_json", "Expected a valid UTF-8 JSON object"); }
            // Validate all request headers before reserving or dispatching any side effect.
            String prefer = singleHeader(exchange, "Prefer");
            Submission submission = service.submit(resource, payload, caller, singleHeader(exchange, "Idempotency-Key"), requestId);
            Map<String, Object> body = envelope("accepted", requestId);
            body.put("operation_id", submission.operationId().toString()); body.put("operation_request_id", submission.requestId().toString()); body.put("replayed", submission.replayed());
            exchange.getResponseHeaders().set("Location", prefix + "operations/" + submission.operationId());
            boolean async = service.getAction(resource).map(ActionDefinition::asynchronous).orElse(true)
                    || "respond-async".equalsIgnoreCase(prefer);
            if (async && !submission.completion().isDone()) { send(exchange, 202, body); return; }
            try {
                ActionResult result = submission.completion().get(settings.timeoutSeconds, TimeUnit.SECONDS);
                body.put("status", result.successful() ? "success" : "error"); body.put("result", result);
                send(exchange, result.successful() ? 200 : 500, body);
            } catch (TimeoutException e) { send(exchange, 202, body); }
        } catch (ActionException e) {
            Map<String, Object> body = envelope("error", requestId); body.put("code", e.code()); body.put("message", e.getMessage());
            if (e.httpStatus() == 429) exchange.getResponseHeaders().set("Retry-After", "60");
            send(exchange, e.httpStatus(), body);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            Map<String, Object> body = envelope("error", requestId); body.put("code", "server_error"); body.put("message", "Unable to complete request");
            send(exchange, 500, body);
        } finally { deadline.cancel(false); exchange.close(); }
    }
    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null) return null;
        if (values.size() != 1) throw new ActionException(400, "duplicate_header", "Duplicate request header");
        return values.get(0);
    }
    private static void requireMethod(HttpExchange exchange, Set<String> allowed) {
        if (!allowed.contains(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Allow", String.join(", ", new TreeSet<>(allowed)));
            throw new ActionException(405, "method_not_allowed", "Method is not allowed on this endpoint");
        }
    }
    private static Map<String, Object> envelope(String status, UUID requestId) {
        Map<String, Object> body = new LinkedHashMap<>(); body.put("status", status); body.put("request_id", requestId.toString()); return body;
    }
    private static Map<String, Object> operationBody(OperationStatus o) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", o.id()); map.put("action", o.action()); map.put("created_at", o.createdAt()); map.put("completed_at", o.completedAt());
        map.put("state", o.state()); map.put("result", o.result()); map.put("initiator", o.initiator()); map.put("request_id", o.requestId()); return map;
    }
    private static void send(HttpExchange exchange, int code, Map<String, Object> body) throws IOException {
        byte[] bytes = Json.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Request-ID", String.valueOf(body.get("request_id")));
        exchange.sendResponseHeaders(code, bytes.length);
        exchange.getResponseBody().write(bytes);
    }
    @Override public void close() { server.stop(0); executor.shutdownNow(); timer.shutdownNow(); }
}

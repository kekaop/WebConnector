package com.eldryn.webconnector;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.core.*;
import com.eldryn.webconnector.http.*;
import com.eldryn.webconnector.events.*;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class HttpIntegrationTest {
    @TempDir Path root;
    ActionService service;
    HttpGateway gateway;
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    @BeforeEach void start() throws Exception {
        service = new ActionService(new OperationStore(root, 100), new ActionService.Scheduler() {
            public void onMainThread(Runnable task) { task.run(); }
            public boolean isMainThread() { return false; }
        }, 2, 16, 1000, 1000, CoreTest.logger(), (t,p) -> {});
        service.registerAction(CoreTest.action("ping").exposeHttp(true).build());
        service.registerAction(CoreTest.action("private").build());
        service.registerAction(CoreTest.action("danger").dangerous(true).exposeHttp(true).build());
        gateway = new HttpGateway(service, policy(), new HttpGateway.Settings("127.0.0.1", 0, "/api", "X-Shared-Secret", 1024, 2, 1000, 4, Set.of("POST")));
        gateway.start();
    }
    SecurityPolicy policy() { return new SecurityPolicy(List.of(
            new SecurityPolicy.Key("test", CoreTest.SECRET, true, null, Set.of("*"), Set.of(), false),
            new SecurityPolicy.Key("other", CoreTest.SECRET+"other", true, null, Set.of("*"), Set.of(), false)), List.of(), false); }
    @AfterEach void stop() throws Exception { gateway.close(); service.close(); }
    HttpRequest.Builder request(String path) { return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + gateway.port() + path)).timeout(Duration.ofSeconds(5)); }
    HttpResponse<String> send(String path, String method, String body, String secret, String key) throws Exception {
        HttpRequest.Builder b = request(path).header("Content-Type", "application/json");
        if (secret != null) b.header("X-Shared-Secret", secret);
        if (key != null) b.header("Idempotency-Key", key);
        return client.send(b.method(method, HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
    @Test void authorizationMethodsRoutingAndSuccess() throws Exception {
        assertEquals(401, send("/api/ping", "POST", "{}", null, null).statusCode());
        assertEquals(401, send("/api/ping", "POST", "{}", "wrong", null).statusCode());
        assertEquals(405, send("/api/ping", "GET", "", CoreTest.SECRET, null).statusCode());
        assertEquals(404, send("/api2/ping", "POST", "{}", CoreTest.SECRET, null).statusCode());
        assertEquals(404, send("/api/private", "POST", "{}", CoreTest.SECRET, null).statusCode());
        assertEquals(403, send("/api/danger", "POST", "{}", CoreTest.SECRET, null).statusCode());
        HttpResponse<String> response = send("/api/ping", "POST", "{}", CoreTest.SECRET, null);
        assertEquals(200, response.statusCode()); assertEquals("success", Json.object(response.body()).get("status"));
        assertTrue(response.headers().firstValue("X-Request-ID").isPresent());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
    }
    @Test void malformedOversizedAndUnknownPayloadsAreRejected() throws Exception {
        for (String json : List.of("[]", "null", "{\"a\":1,\"a\":2}", "{\"a\":{}}", "x".repeat(2048)))
            assertEquals(400, send("/api/ping", "POST", json, CoreTest.SECRET, null).statusCode());
        HttpResponse<String> noContentType = client.send(request("/api/ping").header("X-Shared-Secret", CoreTest.SECRET).POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(400, noContentType.statusCode());
    }
    @Test void duplicateHeadersRejected() throws Exception {
        var request = request("/api/ping").header("X-Shared-Secret", CoreTest.SECRET).header("X-Shared-Secret", "other").POST(HttpRequest.BodyPublishers.noBody()).build();
        assertEquals(400, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }
    @Test void invalidPreferHeaderCannotExecuteAnAction() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        service.registerAction(CoreTest.action("side-effect").exposeHttp(true).handler(c -> { calls.incrementAndGet(); return ActionResult.success(); }).build());
        var request = request("/api/side-effect").header("X-Shared-Secret", CoreTest.SECRET).header("Content-Type", "application/json")
                .header("Prefer", "respond-async").header("Prefer", "respond-async").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
        assertEquals(400, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(0, calls.get()); assertTrue(service.getOperations().isEmpty());
    }
    @Test void malformedUtf8IsRejectedBeforeExecution() throws Exception {
        byte[] malformed = new byte[] {'{', '"', 'x', '"', ':', '"', (byte) 0xc3, '"', '}'};
        var request = request("/api/ping").header("X-Shared-Secret", CoreTest.SECRET).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(malformed)).build();
        assertEquals(400, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()); assertTrue(service.getOperations().isEmpty());
    }
    @Test void asyncPollingOwnershipAndIdempotencyConflict() throws Exception {
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        service.registerAction(CoreTest.action("grant").parameter("player", Parameter.required(Parameter.Type.PLAYER_NAME))
                .asynchronous(true).mainThread(false).exposeHttp(true).requireIdempotency(true).handler(c -> { calls.incrementAndGet(); started.countDown(); release.await(); return ActionResult.success(); }).build());
        try {
            var response = send("/api/grant", "POST", "{\"player\":\"Steve\"}", CoreTest.SECRET, "order-1"); assertEquals(202, response.statusCode());
            String operation = String.valueOf(Json.object(response.body()).get("operation_id")); assertTrue(started.await(2, TimeUnit.SECONDS));
            var polling = send("/api/operations/" + operation, "GET", "", CoreTest.SECRET, null);
            assertEquals(200, polling.statusCode()); assertTrue(polling.body().contains("RUNNING"));
            assertEquals(404, send("/api/operations/"+operation, "GET", "", CoreTest.SECRET+"other", null).statusCode());
            assertEquals(405, send("/api/operations/"+operation, "POST", "{}", CoreTest.SECRET, null).statusCode());
            assertEquals(409, send("/api/grant", "POST", "{\"player\":\"Alex\"}", CoreTest.SECRET, "order-1").statusCode());
            var replay = send("/api/grant", "POST", "{\"player\":\"Steve\"}", CoreTest.SECRET, "order-1");
            assertEquals(operation, Json.object(replay.body()).get("operation_id")); release.countDown();
            for (int i=0; i<50 && !service.getOperation(UUID.fromString(operation)).orElseThrow().terminal(); i++) Thread.sleep(10);
            assertEquals(200, send("/api/grant", "POST", "{\"player\":\"Steve\"}", CoreTest.SECRET, "order-1").statusCode());
            assertEquals(1, calls.get());
        } finally { release.countDown(); }
    }
    @Test void failedOperationReturnsSanitized500AndRequestId() throws Exception {
        service.registerAction(CoreTest.action("fail").exposeHttp(true).handler(c -> { throw new Exception(CoreTest.SECRET); }).build());
        var response = send("/api/fail", "POST", "{}", CoreTest.SECRET, "failed");
        assertEquals(500, response.statusCode()); assertFalse(response.body().contains(CoreTest.SECRET)); assertTrue(Json.object(response.body()).containsKey("request_id"));
    }
    @Test void ipRateLimitReturns429BeforeAuth() throws Exception {
        gateway.close(); gateway = new HttpGateway(service, policy(), new HttpGateway.Settings("127.0.0.1", 0, "/api", "X-Shared-Secret", 1024, 2, 1, 2, Set.of("POST"))); gateway.start();
        assertEquals(401, send("/api/ping", "POST", "{}", "wrong", null).statusCode());
        var second = send("/api/ping", "POST", "{}", CoreTest.SECRET, null);
        assertEquals(429, second.statusCode()); assertEquals("60", second.headers().firstValue("Retry-After").orElseThrow());
    }
    @Test void keyRotationTakesEffectWithoutLosingOperations() throws Exception {
        var first = send("/api/ping", "POST", "{}", CoreTest.SECRET, "kept");
        gateway.security(new SecurityPolicy(List.of(new SecurityPolicy.Key("test", CoreTest.SECRET + "new", true, null, Set.of("*"), Set.of(), false)), List.of(), false));
        assertEquals(401, send("/api/ping", "POST", "{}", CoreTest.SECRET, "kept").statusCode());
        var replay = send("/api/ping", "POST", "{}", CoreTest.SECRET + "new", "kept");
        assertEquals(Json.object(first.body()).get("operation_id"), Json.object(replay.body()).get("operation_id"));
    }
    @Test void webhookRetriesSignedBytesAndPreservesEventIdentity() throws Exception {
        AtomicInteger attempts = new AtomicInteger(); BlockingQueue<Map<String,String>> received = new LinkedBlockingQueue<>();
        HttpServer receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        receiver.createContext("/hook", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            received.add(Map.of("body", body, "id", exchange.getRequestHeaders().getFirst("X-WebConnector-Id"),
                    "timestamp", exchange.getRequestHeaders().getFirst("X-WebConnector-Timestamp"), "signature", exchange.getRequestHeaders().getFirst("X-WebConnector-Signature")));
            exchange.sendResponseHeaders(attempts.incrementAndGet() < 3 ? 503 : 204, -1); exchange.close();
        }); receiver.start();
        try (WebhookDispatcher dispatcher = new WebhookDispatcher("test", 4, 3, Duration.ofSeconds(2), 20, CoreTest.logger())) {
            dispatcher.routes(List.of(route("join", "player.join", receiver.getAddress().getPort(), Map.of("world", "lobby"), false)));
            dispatcher.publish("player.join", Map.of("world", "other")); assertNull(received.poll(50, TimeUnit.MILLISECONDS));
            dispatcher.publish("player.join", Map.of("player", "Steve", "world", "lobby"));
            Map<String,String> first = received.poll(3, TimeUnit.SECONDS); assertNotNull(first);
            Map<String,String> second = received.poll(3, TimeUnit.SECONDS), third = received.poll(3, TimeUnit.SECONDS);
            assertEquals(first, second); assertEquals(first, third);
            assertEquals(WebhookDispatcher.sign(CoreTest.SECRET, first.get("timestamp"), first.get("body")), first.get("signature"));
            assertEquals("player.join", Json.object(first.get("body")).get("type"));
            assertEquals("test", Json.object(first.get("body")).get("server"));
        } finally { receiver.stop(0); }
    }
    @Test void webhookDoesNotRetryPermanentErrorsAndSupportsLegacyMapping() throws Exception {
        AtomicInteger calls = new AtomicInteger(); BlockingQueue<String> bodies = new LinkedBlockingQueue<>();
        HttpServer receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        receiver.createContext("/hook", e -> { bodies.add(new String(e.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); calls.incrementAndGet(); e.sendResponseHeaders(400, -1); e.close(); }); receiver.start();
        try (WebhookDispatcher dispatcher = new WebhookDispatcher("test", 4, 3, Duration.ofSeconds(1), 10, CoreTest.logger())) {
            dispatcher.routes(List.of(route("PlayerJoinEvent", "player.join", receiver.getAddress().getPort(), Map.of(), true)));
            dispatcher.publish("player.join", Map.of("player", "Steve"));
            String body = bodies.poll(2, TimeUnit.SECONDS); assertNotNull(body);
            assertEquals("Steve", Json.object(body).get("player")); assertEquals("PlayerJoinEvent", Json.object(body).get("event"));
            Thread.sleep(100); assertEquals(1, calls.get());
        } finally { receiver.stop(0); }
    }
    @Test void disablingRouteCancelsPendingRetry() throws Exception {
        CountDownLatch received = new CountDownLatch(1); AtomicInteger calls = new AtomicInteger();
        HttpServer receiver = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        receiver.createContext("/hook", e -> { e.getRequestBody().readAllBytes(); calls.incrementAndGet(); e.sendResponseHeaders(503, -1); e.close(); received.countDown(); }); receiver.start();
        try (WebhookDispatcher dispatcher = new WebhookDispatcher("test", 1, 3, Duration.ofSeconds(1), 200, CoreTest.logger())) {
            dispatcher.routes(List.of(route("join", "player.join", receiver.getAddress().getPort(), Map.of(), false)));
            dispatcher.publish("player.join", Map.of()); assertTrue(received.await(2, TimeUnit.SECONDS)); dispatcher.routes(List.of());
            Thread.sleep(400); assertEquals(1, calls.get());
        } finally { receiver.stop(0); }
    }
    static WebhookDispatcher.Route route(String name, String type, int port, Map<String,String> filters, boolean legacy) {
        return new WebhookDispatcher.Route(name, type, URI.create("http://127.0.0.1:"+port+"/hook"), CoreTest.SECRET, Map.of(), filters, legacy, "event");
    }
}

package com.eldryn.webconnector;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.config.*;
import com.eldryn.webconnector.core.*;
import com.eldryn.webconnector.http.SecurityPolicy;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import java.net.InetAddress;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;
import static org.junit.jupiter.api.Assertions.*;

class CoreTest {
    @TempDir Path root;
    ActionService service;
    static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static final Caller LOCAL = Caller.plugin("test");
    static Logger logger() { Logger l = Logger.getAnonymousLogger(); l.setLevel(Level.OFF); return l; }
    ActionService create(ActionService.Scheduler scheduler, int keyLimit, int actionLimit) throws Exception {
        return new ActionService(new OperationStore(root.resolve("operations"), 100), scheduler, 2, 4, keyLimit, actionLimit, logger(), (t,p) -> {});
    }
    @BeforeEach void setup() throws Exception {
        service = create(new ActionService.Scheduler() { public void onMainThread(Runnable task) { task.run(); } public boolean isMainThread() { return false; } }, 1000, 1000);
    }
    @AfterEach void close() throws Exception { if (service != null) service.close(); }
    static ActionDefinition.Builder action(String name) { return ActionDefinition.builder(name).handler(c -> ActionResult.success()); }
    static ActionResult await(Submission s) throws Exception { return s.completion().get(3, TimeUnit.SECONDS); }
    static ActionException reject(int status, org.junit.jupiter.api.function.Executable task) {
        ActionException e = assertThrows(ActionException.class, task); assertEquals(status, e.httpStatus()); return e;
    }
    @Test void registrationIsUniquePrivateAndRemovable() throws Exception {
        service.registerAction(action("plugin.action").build());
        assertTrue(service.hasAction("plugin.action"));
        assertThrows(IllegalArgumentException.class, () -> service.registerAction(action("plugin.action").build()));
        reject(404, () -> service.submit("plugin.action", Map.of(), new Caller("key:test", Set.of("*"), Set.of("*"), true, true), null));
        assertTrue(service.execute("plugin.action", Map.of()).successful());
        assertTrue(service.unregisterAction("plugin.action")); assertFalse(service.unregisterAction("plugin.action"));
    }
    @Test void configuredReloadPreservesPluginRegistrationsAndRejectsConflicts() {
        service.registerAction(action("custom").build()); service.replaceConfigured(List.of(action("one").build()));
        assertThrows(IllegalArgumentException.class, () -> service.replaceConfigured(List.of(action("custom").build())));
        assertTrue(service.hasAction("one"));
        service.replaceConfigured(List.of(action("two").build()));
        assertTrue(service.hasAction("custom")); assertFalse(service.hasAction("one")); assertFalse(service.unregisterAction("two"));
    }
    @Test void permissionDangerousAndActionScopesApplyToJavaToo() throws Exception {
        service.registerAction(action("stop").dangerous(true).permission("node.stop").build());
        reject(403, () -> service.submit("stop", Map.of(), LOCAL, null));
        reject(403, () -> service.submit("stop", Map.of(), new Caller("x", Set.of("stop"), Set.of(), true, false), null));
        reject(403, () -> service.submit("stop", Map.of(), new Caller("x", Set.of("other"), Set.of("node.stop"), true, false), null));
        assertTrue(await(service.submit("stop", Map.of(), new Caller("x", Set.of("stop"), Set.of("node.stop"), true, false), null)).successful());
    }
    @Test void idempotencyIsDurableAndPayloadConflictsAreRejected() throws Exception {
        AtomicInteger executed = new AtomicInteger();
        ActionDefinition definition = action("grant").parameter("player", Parameter.required(Parameter.Type.PLAYER_NAME)).requireIdempotency(true)
                .handler(c -> { executed.incrementAndGet(); return ActionResult.success(); }).build();
        service.registerAction(definition);
        reject(400, () -> service.submit("grant", Map.of("player", "Steve"), LOCAL, null));
        Submission first = service.submit("grant", Map.of("player", "Steve"), LOCAL, "order-1"); assertTrue(await(first).successful());
        Submission replay = service.submit("grant", Map.of("player", "Steve"), LOCAL, "order-1");
        assertEquals(first.operationId(), replay.operationId()); assertTrue(replay.replayed());
        reject(409, () -> service.submit("grant", Map.of("player", "Alex"), LOCAL, "order-1"));
        service.close(); service = null;
        service = create(new ActionService.Scheduler() { public void onMainThread(Runnable task) { task.run(); } public boolean isMainThread() { return false; } }, 1000, 1000);
        service.registerAction(definition);
        assertTrue(await(service.submit("grant", Map.of("player", "Steve"), LOCAL, "order-1")).successful());
        assertEquals(1, executed.get());
    }
    @Test void concurrentRetriesExecuteOnce() throws Exception {
        AtomicInteger calls = new AtomicInteger(); CountDownLatch release = new CountDownLatch(1);
        service.registerAction(action("grant").mainThread(false).handler(c -> { calls.incrementAndGet(); release.await(); return ActionResult.success(); }).build());
        ExecutorService requests = Executors.newFixedThreadPool(8);
        try {
            List<Future<Submission>> submissions = new ArrayList<>();
            for (int i=0; i<20; i++) submissions.add(requests.submit(() -> service.submit("grant", Map.of(), LOCAL, "same-order")));
            Set<UUID> ids = new HashSet<>(); for (Future<Submission> f : submissions) ids.add(f.get(2, TimeUnit.SECONDS).operationId());
            assertEquals(1, ids.size()); release.countDown();
            assertTrue(await(submissions.get(0).get()).successful()); assertEquals(1, calls.get());
        } finally { release.countDown(); requests.shutdownNow(); }
    }
    @Test void aliasHasIdenticalIdempotencyFingerprint() throws Exception {
        service.registerAction(action("grant").parameter("player", Parameter.required(Parameter.Type.PLAYER_NAME)).alias("player_name", "player").build());
        Submission a = service.submit("grant", Map.of("player_name", "Steve"), LOCAL, "alias"); await(a);
        assertEquals(a.operationId(), service.submit("grant", Map.of("player", "Steve"), LOCAL, "alias").operationId());
        reject(400, () -> service.submit("grant", Map.of("player", "Steve", "player_name", "Alex"), LOCAL, null));
    }
    @Test void deadlinesPreventLateQueuedSideEffects() throws Exception {
        service.close(); service = null;
        BlockingQueue<Runnable> queue = new LinkedBlockingQueue<>(); AtomicInteger calls = new AtomicInteger();
        service = create(new ActionService.Scheduler() { public void onMainThread(Runnable task) { queue.add(task); } public boolean isMainThread() { return false; } }, 1000, 1000);
        service.registerAction(action("slow").timeout(Duration.ofMillis(80)).handler(c -> { calls.incrementAndGet(); return ActionResult.success(); }).build());
        Submission submission = service.submit("slow", Map.of(), LOCAL, "deadline");
        Runnable task = queue.poll(2, TimeUnit.SECONDS); assertNotNull(task);
        assertEquals("timeout", await(submission).code()); task.run();
        assertEquals(0, calls.get()); assertEquals(OperationStatus.State.FAILED, service.getOperation(submission.operationId()).orElseThrow().state());
    }
    @Test void dangerousMutexRemainsHeldAfterRunningTimeout() throws Exception {
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        Caller caller = new Caller("admin", Set.of("*"), Set.of("*"), true, false);
        service.registerAction(action("danger").mainThread(false).dangerous(true).timeout(Duration.ofMillis(500)).handler(c -> { started.countDown(); release.await(); return ActionResult.success(); }).build());
        Submission first = service.submit("danger", Map.of(), caller, "first");
        try {
            assertTrue(started.await(2, TimeUnit.SECONDS)); assertEquals("timeout", await(first).code());
            assertEquals("dangerous_action_running", reject(409, () -> service.submit("danger", Map.of(), caller, "second")).code());
        } finally { release.countDown(); }
    }
    @Test void queuedAndRunningStatesAndCancellationAreRecorded() throws Exception {
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        service.registerAction(action("wait").mainThread(false).handler(c -> { started.countDown(); release.await(); return ActionResult.success(); }).build());
        Submission s = service.submit("wait", Map.of(), LOCAL, "state");
        assertTrue(started.await(2, TimeUnit.SECONDS)); assertEquals(OperationStatus.State.RUNNING, service.getOperation(s.operationId()).orElseThrow().state());
        service.close(); service = null;
        assertEquals("cancelled", await(s).code()); release.countDown();
        try (OperationStore store = new OperationStore(root.resolve("operations"), 100)) {
            assertEquals(OperationStatus.State.CANCELLED, store.get(s.operationId()).orElseThrow().state());
        }
    }
    @Test void backgroundHandlerFailureIsSanitizedAndNotRetried() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        service.registerAction(action("bad").handler(c -> { calls.incrementAndGet(); throw new RuntimeException(SECRET); }).build());
        Submission first = service.submit("bad", Map.of(), LOCAL, "failure");
        assertEquals("handler_failed", await(first).code()); assertFalse(await(first).message().contains(SECRET));
        await(service.submit("bad", Map.of(), LOCAL, "failure")); assertEquals(1, calls.get());
    }
    @Test void rateLimitAppliesToJavaAndActionAcrossCallers() throws Exception {
        service.close(); service = null;
        service = create(new ActionService.Scheduler() { public void onMainThread(Runnable task) { task.run(); } public boolean isMainThread() { return false; } }, 2, 2);
        service.registerAction(action("limited").build());
        await(service.submit("limited", Map.of(), LOCAL, null)); await(service.submit("limited", Map.of(), Caller.plugin("second"), null));
        reject(429, () -> service.submit("limited", Map.of(), Caller.plugin("third"), null));
    }
    @ParameterizedTest @ValueSource(strings={"", "operations", "../stop", "with space", "with/slash"})
    void invalidActionNames(String name) { assertThrows(IllegalArgumentException.class, () -> action(name).build()); }
    @ParameterizedTest @ValueSource(strings={"@a", "Steve Bob", "Steve\nstop", "12345678901234567", ""})
    void playerNamesRejectCommandInjection(String name) { assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.PLAYER_NAME).validate(name)); }
    @Test void allParameterTypesEnforceSchema() {
        assertEquals("hello", Parameter.required(Parameter.Type.STRING).validate("hello"));
        assertEquals(10L, new Parameter(Parameter.Type.INTEGER, true, 16, 1L, 10L, Set.of(), null).validate(10));
        assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.INTEGER).validate(1.5));
        assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.INTEGER).validate("1"));
        assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.INTEGER).validate(Double.NaN));
        assertEquals(true, Parameter.required(Parameter.Type.BOOLEAN).validate(true));
        assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.BOOLEAN).validate("true"));
        String uuid = UUID.randomUUID().toString(); assertEquals(uuid, Parameter.required(Parameter.Type.UUID).validate(uuid));
        assertThrows(IllegalArgumentException.class, () -> Parameter.required(Parameter.Type.UUID).validate("1-1-1-1-1"));
        assertEquals("vip", Parameter.enumeration("vip", "premium").validate("vip"));
        assertThrows(IllegalArgumentException.class, () -> Parameter.enumeration("vip").validate("op"));
        Parameter regex = new Parameter(Parameter.Type.REGEX, true, 8, null, null, Set.of(), "[a-z]+");
        assertEquals("test", regex.validate("test")); assertThrows(IllegalArgumentException.class, () -> regex.validate("Test"));
        assertThrows(IllegalArgumentException.class, () -> regex.validate("toolongvalue"));
        assertThrows(IllegalArgumentException.class, () -> regex.validate(null));
    }
    @Test void payloadRejectsUnknownAndStructuredValues() {
        service.registerAction(action("validated").required("value").build());
        reject(400, () -> service.submit("validated", Map.of("value", "x", "extra", "oops"), LOCAL, null));
        reject(400, () -> service.submit("validated", Map.of("value", List.of("x")), LOCAL, null));
    }
    @ParameterizedTest @ValueSource(strings={"[]", "null", "{x:1}", "{\"x\":1,\"x\":2}", "{}{}", "{\"a\":NaN}", "{\"a\":1,}"})
    void strictJsonRejectsAmbiguousInput(String json) { assertThrows(IllegalArgumentException.class, () -> Json.object(json)); }
    @Test void templatesRequireSchemasAndSingleSafeTokens() {
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.validate("op {player}", Set.of()));
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.render("say {value}", "say", Map.of("value", "hi\nstop")));
        assertThrows(IllegalArgumentException.class, () -> CommandTemplate.render("lp user {player} parent add {pass}", "grant", Map.of("player", "Steve", "pass", "vip extra")));
        assertEquals("lp user Steve parent add vip", CommandTemplate.render("lp user {player} parent add {pass}", "grant", Map.of("player", "Steve", "pass", "vip")));
    }
    @Test void authenticationChecksExpiryEnablementAclAndCidrs() throws Exception {
        SecurityPolicy policy = new SecurityPolicy(List.of(new SecurityPolicy.Key("active", SECRET, true, null, Set.of("ping"), Set.of(), false),
                new SecurityPolicy.Key("expired", SECRET + "x", true, Instant.now().minusSeconds(1), Set.of("*"), Set.of(), false),
                new SecurityPolicy.Key("disabled", SECRET + "y", false, null, Set.of("*"), Set.of(), false)), List.of("127.0.0.0/8", "::1/128"), false);
        Caller caller = policy.authenticate(InetAddress.getByName("127.0.0.1"), SECRET); assertTrue(caller.permits("ping")); assertFalse(caller.permits("other"));
        policy.authenticate(InetAddress.getByName("::1"), SECRET);
        reject(401, () -> policy.authenticate(InetAddress.getLoopbackAddress(), SECRET + "x"));
        reject(401, () -> policy.authenticate(InetAddress.getLoopbackAddress(), SECRET + "y"));
        reject(401, () -> policy.authenticate(InetAddress.getLoopbackAddress(), null));
        reject(403, () -> policy.authenticate(InetAddress.getByName("192.0.2.1"), SECRET));
    }
    @ParameterizedTest @ValueSource(strings={"", "change-me", "replace-with-node-dashboard-secret"})
    void insecureSecretsRejected(String secret) { assertThrows(IllegalArgumentException.class, () -> new SecurityPolicy.Key("x", secret, true, null, Set.of(), Set.of(), false)); }
    @Test void fileGuardOnlyDeletesAllowedRegularFiles() throws Exception {
        Path allowed = Files.createDirectories(root.resolve("exports")), plugin = Files.createDirectories(root.resolve("plugins/WebConnector"));
        Path file = Files.writeString(allowed.resolve("season.txt"), "old");
        FileGuard guard = new FileGuard(root, List.of("exports"), List.of(plugin), true);
        assertThrows(java.io.IOException.class, () -> guard.delete("exports/../plugins/WebConnector/config.yml"));
        assertThrows(java.io.IOException.class, () -> guard.delete("exports"));
        assertThrows(java.io.IOException.class, () -> guard.delete("exports/.."));
        assertThrows(java.io.IOException.class, () -> new FileGuard(root, List.of("plugins"), List.of(plugin), true));
        assertThrows(java.io.IOException.class, () -> new FileGuard(root, List.of("exports"), List.of(plugin), false).delete("exports/season.txt"));
        guard.delete("exports/season.txt"); assertFalse(Files.exists(file));
    }
    @Test void incompleteJournalIsNotExecutedOnRestart() throws Exception {
        Path dir = root.resolve("recovery"); UUID id = UUID.randomUUID();
        try (OperationStore store = new OperationStore(dir, 10)) {
            store.reserve(new OperationStore.Entry(new OperationStatus(id, "grant", Instant.now().toString(), null, OperationStatus.State.RUNNING, null, "key:shop", UUID.randomUUID()), "identity", "fingerprint"));
        }
        try (OperationStore store = new OperationStore(dir, 10)) {
            assertEquals(OperationStatus.State.FAILED, store.get(id).orElseThrow().state());
            assertEquals("interrupted", store.get(id).orElseThrow().result().code()); assertTrue(store.byIdentity("identity").isPresent());
        }
    }
    @Test void corruptStoreFailsClosedAndReleasesLock() throws Exception {
        Path dir = Files.createDirectories(root.resolve("corrupt")); Files.writeString(dir.resolve(UUID.randomUUID()+".json"), "broken");
        assertThrows(java.io.IOException.class, () -> new OperationStore(dir, 10));
        assertThrows(java.io.IOException.class, () -> new OperationStore(dir, 10));
    }
    @Test void journalCapacityDoesNotEvictIdempotencyRecords() throws Exception {
        try (OperationStore store = new OperationStore(root.resolve("bounded"), 1)) {
            store.reserve(entry(UUID.randomUUID(), "first"));
            reject(429, () -> store.reserve(entry(UUID.randomUUID(), "second")));
            assertTrue(store.byIdentity("first").isPresent());
        }
    }
    static OperationStore.Entry entry(UUID id, String identity) { return new OperationStore.Entry(new OperationStatus(id, "ping", Instant.now().toString(), Instant.now().toString(), OperationStatus.State.COMPLETED, ActionResult.success(), "test", UUID.randomUUID()), identity, "fingerprint"); }
    @Test void defaultConfigWorksWithGeneratedSecretAndVersion1RequiresMigration() throws Exception {
        YamlConfiguration yaml = new YamlConfiguration();
        try (var input = getClass().getResourceAsStream("/config.yml")) { yaml.load(new java.io.InputStreamReader(Objects.requireNonNull(input), java.nio.charset.StandardCharsets.UTF_8)); }
        assertThrows(IllegalArgumentException.class, () -> PluginSettings.read(yaml));
        yaml.set("security.shared-secret", SECRET);
        PluginSettings settings = PluginSettings.read(yaml); assertEquals("127.0.0.1", settings.http().host()); assertEquals(1, settings.actions().size());
        yaml.set("config-version", 1);
        assertTrue(assertThrows(IllegalArgumentException.class, () -> PluginSettings.read(yaml)).getMessage().contains("MIGRATION"));
    }
    @Test void unsafeDevelopmentModeAndMutationGetRejected() throws Exception {
        YamlConfiguration y = new YamlConfiguration(); y.loadFromString("config-version: 2\nsecurity:\n  require-authentication: false\nserver:\n  host: 0.0.0.0\n");
        assertThrows(IllegalArgumentException.class, () -> PluginSettings.read(y));
        y.set("server.host", "127.0.0.1"); y.set("security.development-mode", true); y.set("security.allow-unauthenticated-localhost", true);
        PluginSettings.read(y);
        y.set("server.allowed-methods", List.of("GET")); assertThrows(IllegalArgumentException.class, () -> PluginSettings.read(y));
    }
}

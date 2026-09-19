package com.eldryn.webconnector;

import com.eldryn.webconnector.api.*;
import com.eldryn.webconnector.config.*;
import com.eldryn.webconnector.core.*;
import com.eldryn.webconnector.events.*;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class EdgeCasesTest {
    @TempDir Path root;
    @Test void boundedActionQueueRejectsBeforeReservation() throws Exception {
        BlockingQueue<Runnable> scheduled = new LinkedBlockingQueue<>();
        try (ActionService service = new ActionService(new OperationStore(root, 20), new ActionService.Scheduler() {
            public void onMainThread(Runnable task) { scheduled.add(task); }
            public boolean isMainThread() { return false; }
        }, 1, 1, 100, 100, CoreTest.logger(), (t,p)->{})) {
            service.registerAction(CoreTest.action("queued").build());
            Submission first = service.submit("queued", Map.of(), CoreTest.LOCAL, "first");
            Runnable task = scheduled.poll(1, TimeUnit.SECONDS); assertNotNull(task);
            Submission second = service.submit("queued", Map.of(), CoreTest.LOCAL, "second");
            CoreTest.reject(429, () -> service.submit("queued", Map.of(), CoreTest.LOCAL, "third"));
            assertEquals(2, service.getOperations().size());
            assertEquals(OperationStatus.State.QUEUED, service.getOperation(second.operationId()).orElseThrow().state());
            task.run(); assertTrue(CoreTest.await(first).successful());
        }
    }
    @Test void blockingApiRejectsServerThreadWithoutSubmitting() throws Exception {
        try (ActionService service = new ActionService(new OperationStore(root, 20), new ActionService.Scheduler() {
            public void onMainThread(Runnable task) { task.run(); }
            public boolean isMainThread() { return true; }
        }, 1, 1, 100, 100, CoreTest.logger(), (t,p)->{})) {
            service.registerAction(CoreTest.action("ping").build());
            assertThrows(IllegalStateException.class, () -> service.execute("ping", Map.of()));
            assertTrue(service.getOperations().isEmpty());
            assertTrue(service.executeAsync("ping", Map.of()).get(1, TimeUnit.SECONDS).successful());
        }
    }
    @Test void rateLimiterBoundsIdentityMemoryAndExpiresCounters() {
        class MutableClock extends Clock {
            Instant time = Instant.parse("2026-09-19T00:00:00Z");
            public ZoneId getZone() { return ZoneOffset.UTC; } public Clock withZone(ZoneId zone) { return this; } public Instant instant() { return time; }
        }
        MutableClock clock = new MutableClock(); RateLimiter limiter = new RateLimiter(1, clock);
        assertTrue(limiter.acquire("a", 2)); assertTrue(limiter.acquire("a", 2)); assertFalse(limiter.acquire("a", 2)); assertFalse(limiter.acquire("b", 2));
        clock.time = clock.time.plusSeconds(61); assertTrue(limiter.acquire("b", 2));
    }
    @Test void simultaneousStoresCannotShareJournal() throws Exception {
        try (OperationStore store = new OperationStore(root, 10)) { assertThrows(java.io.IOException.class, () -> new OperationStore(root, 10)); }
        try (OperationStore reopened = new OperationStore(root, 10)) { assertTrue(reopened.all().isEmpty()); }
    }
    @Test void nonIdempotentTerminalRecordsCanBeEvicted() throws Exception {
        try (OperationStore store = new OperationStore(root, 1)) {
            UUID first = UUID.randomUUID(), second = UUID.randomUUID(); store.reserve(CoreTest.entry(first, null)); store.reserve(CoreTest.entry(second, "saved"));
            assertTrue(store.get(first).isEmpty()); assertTrue(store.get(second).isPresent());
        }
    }
    @Test void fileGuardRejectsSymbolicLinkOrWindowsJunction() throws Exception {
        Path allowed = Files.createDirectory(root.resolve("allowed")), outside = Files.createDirectory(root.resolve("outside"));
        Files.writeString(outside.resolve("important.txt"), "keep"); Path link = allowed.resolve("link");
        directoryLink(link, outside);
        try {
            FileGuard guard = new FileGuard(root, List.of("allowed"), List.of(root.resolve("plugin")), true);
            assertThrows(java.io.IOException.class, () -> guard.delete("allowed/link/important.txt"));
            assertTrue(Files.exists(outside.resolve("important.txt")));
        } finally { Files.deleteIfExists(link); }
    }
    @Test void protectedPathsAreCanonicalizedIncludingMissingChildren() throws Exception {
        Path privateDirectory = Files.createDirectories(root.resolve("private/WebConnector"));
        Path alias = root.resolve("alias"); directoryLink(alias, root.resolve("private"));
        try {
            assertThrows(java.io.IOException.class, () -> new FileGuard(root, List.of("private"), List.of(alias.resolve("WebConnector")), true));
            assertThrows(java.io.IOException.class, () -> new FileGuard(root, List.of("private"), List.of(alias.resolve("WebConnector/security.yml")), true));
            assertTrue(Files.isDirectory(privateDirectory));
        } finally { Files.deleteIfExists(alias); }
    }
    private static void directoryLink(Path link, Path target) throws Exception {
        if (System.getProperty("os.name").startsWith("Windows")) {
            Process process = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "New-Item -ItemType Junction -Path '" + link.toString().replace("'", "''") + "' -Target '" + target.toString().replace("'", "''") + "' | Out-Null").start();
            assertEquals(0, process.waitFor());
        } else Files.createSymbolicLink(link, target);
    }
    @Test void eventBridgeReadsGettersWithoutInvokingArbitraryMethods() {
        class TestEvent extends org.bukkit.event.Event {
            public org.bukkit.event.HandlerList getHandlers() { return new org.bukkit.event.HandlerList(); }
        }
        assertEquals("PlayerJoinEvent", EventBridge.resolve("PlayerJoinEvent").getSimpleName());
        assertThrows(IllegalArgumentException.class, () -> EventBridge.resolve("java.lang.Runtime"));
        assertEquals("safe ", EventBridge.render(new TestEvent(), "safe {event.getClass}"));
    }
    @Test void webhookQueueCapacityAndSignatureDeterminism() throws Exception {
        try (WebhookDispatcher dispatcher = new WebhookDispatcher("node", 1, 2, Duration.ofMillis(500), 100, CoreTest.logger())) {
            dispatcher.routes(List.of(HttpIntegrationTest.route("join", "player.join", 1, Map.of(), false)));
            for (int i=0;i<100;i++) dispatcher.publish("player.join", Map.of());
            assertTrue(dispatcher.statistics().get("dropped") > 0);
        }
        assertNotEquals(WebhookDispatcher.sign(CoreTest.SECRET, "now", "{}"), WebhookDispatcher.sign(CoreTest.SECRET, "now", "{ }"));
        assertNotEquals(WebhookDispatcher.sign(CoreTest.SECRET, "now", "{}"), WebhookDispatcher.sign(CoreTest.SECRET, "later", "{}"));
    }
    @Test void configReadsSchemasKeysAndRouteOverrides() throws Exception {
        YamlConfiguration yaml = new YamlConfiguration();
        yaml.loadFromString("""
                config-version: 2
                security:
                  shared-secret: %s
                  api-keys:
                    shop:
                      secret: %s
                      actions: [grant]
                actions:
                  grant:
                    commands: ['say {player}']
                    validation:
                      player: {type: player_name}
                event-dispatch:
                  enabled: true
                  signing-secret: %s
                event-routes:
                  welcome:
                    type: player.join
                    event-class: org.bukkit.event.player.PlayerJoinEvent
                    endpoint: http://127.0.0.1:3000/hook
                    payload: {player: '{event.player.name}'}
                """.formatted(CoreTest.SECRET, CoreTest.SECRET + "shop", CoreTest.SECRET));
        PluginSettings settings = PluginSettings.read(yaml);
        assertEquals(1, settings.actions().size()); assertEquals(1, settings.routes().size());
        ActionDefinition action = settings.actions().get(0).builder().handler(c -> ActionResult.success()).build();
        assertEquals("player", action.aliases().get("player_name")); assertEquals(Parameter.Type.PLAYER_NAME, action.parameters().get("player").type());
        assertEquals("org.bukkit.event.player.PlayerJoinEvent", settings.bindings().get(0).eventClass());
    }
}

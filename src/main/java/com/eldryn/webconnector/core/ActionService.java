package com.eldryn.webconnector.core;

import com.eldryn.webconnector.api.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.logging.Logger;

/** All transports enter here; validation, policy, journaling and scheduling are shared. */
public final class ActionService implements WebConnectorAPI, AutoCloseable {
    public interface Scheduler {
        void onMainThread(Runnable task);
        boolean isMainThread();
    }
    private final Map<String, ActionDefinition> actions = new ConcurrentHashMap<>();
    private final Set<String> configuredNames = new HashSet<>();
    private final Map<UUID, CompletableFuture<ActionResult>> futures = new ConcurrentHashMap<>();
    private final Set<UUID> executing = ConcurrentHashMap.newKeySet();
    private final Set<UUID> pending = ConcurrentHashMap.newKeySet();
    private final int maxPending;
    private final OperationStore store;
    private final Scheduler scheduler;
    private final ThreadPoolExecutor workers;
    private final ScheduledThreadPoolExecutor timer;
    private final RateLimiter limiter = new RateLimiter(20000);
    private final Logger logger;
    private final int keyLimit, actionLimit;
    private final BiConsumer<String, Map<String, Object>> publisher;
    private UUID dangerousOwner;
    private boolean closed, storageFailed;
    public ActionService(OperationStore store, Scheduler scheduler, int workers, int queue, int keyLimit, int actionLimit,
                         Logger logger, BiConsumer<String, Map<String, Object>> publisher) {
        this.store = store; this.scheduler = scheduler; this.keyLimit = keyLimit; this.actionLimit = actionLimit;
        this.logger = logger; this.publisher = publisher;
        this.maxPending = workers + queue;
        this.workers = new ThreadPoolExecutor(workers, workers, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(queue), factory("actions"));
        timer = new ScheduledThreadPoolExecutor(1, factory("deadlines")); timer.setRemoveOnCancelPolicy(true);
    }
    public static ThreadFactory factory(String name) {
        return r -> { Thread t = new Thread(r, "WebConnector-" + name); t.setDaemon(true); return t; };
    }
    @Override public Optional<ActionDefinition> getAction(String name) { return Optional.ofNullable(actions.get(name)); }
    @Override public Collection<ActionDefinition> getActions() { return actions.values().stream().sorted(Comparator.comparing(ActionDefinition::name)).toList(); }
    @Override public synchronized void registerAction(ActionDefinition action) {
        if (actions.putIfAbsent(action.name(), action) != null) throw new IllegalArgumentException("Action is already registered: " + action.name());
    }
    @Override public synchronized boolean unregisterAction(String name) { if (configuredNames.contains(name)) return false; return actions.remove(name) != null; }
    public synchronized void replaceConfigured(Collection<ActionDefinition> definitions) {
        for (ActionDefinition a : definitions) if (actions.containsKey(a.name()) && !configuredNames.contains(a.name()))
            throw new IllegalArgumentException("Configured action conflicts with Java action: " + a.name());
        configuredNames.forEach(actions::remove); configuredNames.clear();
        definitions.forEach(a -> { actions.put(a.name(), a); configuredNames.add(a.name()); });
    }
    @Override public Submission submit(String action, Map<String, Object> payload, Caller caller, String idempotencyKey) {
        return submit(action, payload, caller, idempotencyKey, UUID.randomUUID());
    }
    public synchronized Submission submit(String action, Map<String, Object> payload, Caller caller, String key, UUID requestId) {
        if (closed || storageFailed) throw error(500, "unavailable", "Action service is unavailable");
        ActionDefinition definition = actions.get(action);
        if (definition == null || (caller.http() && !definition.exposeHttp())) throw error(404, "not_found", "Action not found");
        if (!caller.permits(action) || !caller.hasPermission(definition.permission()) || (definition.dangerous() && !caller.allowDangerous()))
            throw error(403, "forbidden", "Caller is not permitted to execute this action");
        if (!limiter.acquire("key:" + caller.name(), keyLimit) || !limiter.acquire("action:" + action, actionLimit))
            throw error(429, "rate_limited", "Action rate limit exceeded");
        Map<String, Object> validated = new LinkedHashMap<>();
        if (payload != null) {
            payload = new LinkedHashMap<>(payload);
            for (var alias : definition.aliases().entrySet()) if (payload.containsKey(alias.getKey())) {
                if (payload.containsKey(alias.getValue())) throw error(400, "invalid_payload", "Both an alias and its canonical parameter were supplied");
                payload.put(alias.getValue(), payload.remove(alias.getKey()));
            }
        }
        if (payload == null || payload.size() > 256 || !definition.parameters().keySet().containsAll(payload.keySet()))
            throw error(400, "invalid_payload", "Payload contains unknown parameters");
        for (var entry : definition.parameters().entrySet()) {
            try { Object value = entry.getValue().validate(payload.get(entry.getKey())); if (value != null) validated.put(entry.getKey(), value); }
            catch (IllegalArgumentException e) { throw error(400, "invalid_payload", "Invalid parameter: " + entry.getKey()); }
        }
        if (key != null && !key.matches("[A-Za-z0-9._:-]{1,128}")) throw error(400, "invalid_idempotency_key", "Invalid Idempotency-Key");
        if (definition.requireIdempotency() && key == null) throw error(400, "idempotency_required", "Idempotency-Key is required");
        String identity = key == null ? null : hash(caller.name() + "\n" + key);
        String fingerprint = hash(action + "\n" + Json.canonical(validated));
        if (identity != null) {
            Optional<OperationStore.Entry> prior = store.byIdentity(identity);
            if (prior.isPresent()) {
                OperationStore.Entry entry = prior.get();
                if (!fingerprint.equals(entry.fingerprint())) throw error(409, "idempotency_conflict", "This key was used with a different action or payload");
                OperationStatus o = entry.operation();
                CompletableFuture<ActionResult> completion = futures.get(o.id());
                if (completion == null) completion = CompletableFuture.completedFuture(o.result());
                return new Submission(o.id(), o.requestId(), true, completion.copy());
            }
        }
        if (definition.dangerous() && dangerousOwner != null) throw error(409, "dangerous_action_running", "Another dangerous action is active");
        if (pending.size() >= maxPending || workers.getQueue().remainingCapacity() == 0) throw error(429, "queue_full", "Action queue is full");
        UUID id = UUID.randomUUID();
        OperationStatus operation = new OperationStatus(id, action, Instant.now().toString(), null, OperationStatus.State.QUEUED, null, caller.name(), requestId);
        try { store.reserve(new OperationStore.Entry(operation, identity, fingerprint)); }
        catch (IOException e) { storageFailed = true; throw error(500, "storage_error", "Unable to reserve operation"); }
        CompletableFuture<ActionResult> future = new CompletableFuture<>(); futures.put(id, future);
        pending.add(id);
        if (definition.dangerous()) dangerousOwner = id;
        ActionContext context = new ActionContext(action, validated, caller, requestId, id, Instant.now().plus(definition.timeout()));
        ScheduledFuture<?> deadline = timer.schedule(() -> finish(id, ActionResult.failure("timeout", "Deadline exceeded; running side effects may finish. Poll or reconcile this operation."), OperationStatus.State.FAILED), definition.timeout().toMillis(), TimeUnit.MILLISECONDS);
        future.whenComplete((v, e) -> deadline.cancel(false));
        try {
            workers.execute(() -> {
                if (definition.mainThread()) {
                    try {
                        CountDownLatch finished = new CountDownLatch(1);
                        scheduler.onMainThread(() -> { try { run(definition, context); } finally { finished.countDown(); } });
                        finished.await();
                    }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                    catch (RuntimeException e) { finish(id, ActionResult.failure("scheduler_unavailable", "Server scheduler is unavailable"), OperationStatus.State.FAILED); }
                } else run(definition, context);
            });
        } catch (RejectedExecutionException e) { finish(id, ActionResult.failure("queue_full", "Action queue is full"), OperationStatus.State.CANCELLED); }
        return new Submission(id, requestId, false, future.copy());
    }
    private void run(ActionDefinition definition, ActionContext context) {
        synchronized (this) {
            OperationStatus o = store.get(context.operationId()).orElseThrow();
            if (closed || o.terminal()) return;
            if (!Instant.now().isBefore(context.deadline())) { finish(o.id(), ActionResult.failure("timeout", "Deadline exceeded before execution"), OperationStatus.State.FAILED); return; }
            try { store.update(new OperationStatus(o.id(), o.action(), o.createdAt(), null, OperationStatus.State.RUNNING, null, o.initiator(), o.requestId())); }
            catch (IOException e) { storageFailed = true; finish(o.id(), ActionResult.failure("storage_error", "Operation storage failed"), OperationStatus.State.FAILED); return; }
            executing.add(o.id());
        }
        try {
            ActionResult result;
            try { result = Objects.requireNonNull(definition.handler().execute(context)); }
            catch (Throwable e) {
                result = ActionResult.failure("handler_failed", "Action failed; inspect server state before retrying with a new key");
                if (e instanceof VirtualMachineError fatal) {
                    finish(context.operationId(), result, OperationStatus.State.FAILED);
                    throw fatal;
                }
            }
            finish(context.operationId(), result, result.successful() ? OperationStatus.State.COMPLETED : OperationStatus.State.FAILED);
        } finally {
            synchronized (this) { executing.remove(context.operationId()); pending.remove(context.operationId()); releaseDangerous(context.operationId()); }
        }
    }
    private synchronized void finish(UUID id, ActionResult result, OperationStatus.State state) {
        // A timed-out non-idempotent record may already have been evicted by journal retention.
        OperationStatus o = store.get(id).orElse(null);
        if (o == null || o.terminal()) return;
        try { store.update(new OperationStatus(id, o.action(), o.createdAt(), Instant.now().toString(), state, result, o.initiator(), o.requestId())); }
        catch (IOException e) { storageFailed = true; result = ActionResult.failure("storage_error", "Outcome could not be persisted; reconcile operation before retrying"); }
        CompletableFuture<ActionResult> future = futures.remove(id);
        if (future != null) future.complete(result);
        if (!executing.contains(id)) { pending.remove(id); releaseDangerous(id); }
        logger.info("operation=" + id + " request=" + o.requestId() + " action=" + o.action() + " state=" + state);
    }
    private void releaseDangerous(UUID id) { if (id.equals(dangerousOwner)) dangerousOwner = null; }
    private static ActionException error(int status, String code, String message) { return new ActionException(status, code, message); }
    public static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    @Override public ActionResult execute(String action, Map<String, Object> payload) {
        if (scheduler.isMainThread()) throw new IllegalStateException("Use executeAsync on the server thread");
        return executeAsync(action, payload).join();
    }
    @Override public CompletableFuture<ActionResult> executeAsync(String action, Map<String, Object> payload) { return submit(action, payload, Caller.plugin("java"), null).completion(); }
    @Override public UUID submit(String action, Map<String, Object> payload) { return submit(action, payload, Caller.plugin("java"), null).operationId(); }
    @Override public Optional<OperationStatus> getOperation(UUID id) { return store.get(id); }
    public void limitRead(Caller caller) {
        if (!limiter.acquire("key:" + caller.name(), keyLimit)) throw error(429, "rate_limited", "API key rate limit exceeded");
    }
    @Override public Collection<OperationStatus> getOperations() { return store.all(); }
    @Override public void publishEvent(String type, Map<String, Object> payload) { publisher.accept(type, payload); }
    public synchronized boolean healthy() { return !closed && !storageFailed; }
    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        for (OperationStatus o : store.all()) if (!o.terminal()) finish(o.id(), ActionResult.failure("cancelled", "Plugin stopped; running side effects may be partial"), OperationStatus.State.CANCELLED);
        workers.shutdownNow(); timer.shutdownNow(); store.close();
    }
}

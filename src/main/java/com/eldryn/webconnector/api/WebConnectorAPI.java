package com.eldryn.webconnector.api;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/** Obtain via Bukkit ServicesManager. Never shade this API into another plugin. */
public interface WebConnectorAPI {
    Optional<ActionDefinition> getAction(String name);
    Collection<ActionDefinition> getActions();
    default boolean hasAction(String name) { return getAction(name).isPresent(); }
    /** Blocking; must not be used from the server thread. */
    ActionResult execute(String action, Map<String, Object> payload);
    CompletableFuture<ActionResult> executeAsync(String action, Map<String, Object> payload);
    UUID submit(String action, Map<String, Object> payload);
    Submission submit(String action, Map<String, Object> payload, Caller caller, String idempotencyKey);
    Optional<OperationStatus> getOperation(UUID id);
    Collection<OperationStatus> getOperations();
    void registerAction(ActionDefinition definition);
    boolean unregisterAction(String name);
    void publishEvent(String eventType, Map<String, Object> payload);
}

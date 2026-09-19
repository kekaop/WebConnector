package com.eldryn.webconnector.api;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record ActionContext(String action, Map<String, Object> payload, Caller caller,
                            UUID requestId, UUID operationId, Instant deadline) {
    public ActionContext { payload = Map.copyOf(payload); }
    /** Call between side effects in long-running handlers. */
    public void checkDeadline() {
        if (Thread.currentThread().isInterrupted() || !Instant.now().isBefore(deadline))
            throw new IllegalStateException("Action deadline exceeded");
    }
}

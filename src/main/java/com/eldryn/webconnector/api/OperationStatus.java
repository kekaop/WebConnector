package com.eldryn.webconnector.api;

import java.util.UUID;

/** Operation timestamps are ISO-8601 UTC strings. */
public record OperationStatus(UUID id, String action, String createdAt, String completedAt,
                              State state, ActionResult result, String initiator, UUID requestId) {
    public enum State { QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED }
    public boolean terminal() { return state != State.QUEUED && state != State.RUNNING; }
}

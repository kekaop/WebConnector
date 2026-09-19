package com.eldryn.webconnector.api;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public record Submission(UUID operationId, UUID requestId, boolean replayed, CompletableFuture<ActionResult> completion) { }

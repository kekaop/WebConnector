package com.eldryn.webconnector.api;

import java.time.Duration;
import java.util.*;

/** Immutable action contract. Programmatic actions are private to Java by default. */
public record ActionDefinition(String name, String description, Map<String, Parameter> parameters, Map<String, String> aliases,
                               Duration timeout, String permission, boolean dangerous, boolean exposeHttp,
                               boolean asynchronous, boolean requireIdempotency, boolean mainThread,
                               Handler handler) {
    @FunctionalInterface public interface Handler { ActionResult execute(ActionContext context) throws Exception; }
    public ActionDefinition {
        if (name == null || !name.matches("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}") || name.equals("operations"))
            throw new IllegalArgumentException("Invalid or reserved action name");
        parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
        aliases = Map.copyOf(aliases);
        for (var alias : aliases.entrySet()) if (parameters.containsKey(alias.getKey()) || !parameters.containsKey(alias.getValue())) throw new IllegalArgumentException("Invalid parameter alias");
        parameters.keySet().forEach(k -> { if (!k.matches("[A-Za-z_][A-Za-z0-9_]{0,63}")) throw new IllegalArgumentException("Invalid parameter name"); });
        Objects.requireNonNull(handler); Objects.requireNonNull(permission); Objects.requireNonNull(description);
        if (timeout.isZero() || timeout.isNegative() || timeout.compareTo(Duration.ofMinutes(5)) > 0)
            throw new IllegalArgumentException("Action timeout must be between 1ms and 5 minutes");
    }
    public static Builder builder(String name) { return new Builder(name); }
    public static final class Builder {
        private final String name;
        private String description = "", permission = "";
        private final Map<String, Parameter> parameters = new LinkedHashMap<>();
        private final Map<String, String> aliases = new LinkedHashMap<>();
        private Duration timeout = Duration.ofSeconds(10);
        private boolean dangerous, exposeHttp, asynchronous, requireIdempotency, mainThread = true;
        private Handler handler;
        private Builder(String name) { this.name = name; }
        public Builder description(String value) { description = value; return this; }
        public Builder required(String name) { return parameter(name, Parameter.required(Parameter.Type.STRING)); }
        public Builder parameter(String name, Parameter value) { parameters.put(name, value); return this; }
        public Builder alias(String alias, String parameter) { aliases.put(alias, parameter); return this; }
        public Builder timeout(Duration value) { timeout = value; return this; }
        public Builder permission(String value) { permission = value; return this; }
        public Builder dangerous(boolean value) { dangerous = value; return this; }
        public Builder exposeHttp(boolean value) { exposeHttp = value; return this; }
        public Builder asynchronous(boolean value) { asynchronous = value; return this; }
        public Builder requireIdempotency(boolean value) { requireIdempotency = value; return this; }
        public Builder mainThread(boolean value) { mainThread = value; return this; }
        public Builder handler(Handler value) { handler = value; return this; }
        public ActionDefinition build() { return new ActionDefinition(name, description, parameters, aliases, timeout, permission,
                dangerous, exposeHttp, asynchronous, requireIdempotency, mainThread, handler); }
    }
}

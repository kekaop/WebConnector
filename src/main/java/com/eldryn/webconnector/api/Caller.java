package com.eldryn.webconnector.api;

import java.util.Set;

/** Trusted caller metadata. HTTP callers are constructed exclusively by the authenticator. */
public record Caller(String name, Set<String> actions, Set<String> permissions, boolean allowDangerous, boolean http) {
    public Caller { actions = Set.copyOf(actions); permissions = Set.copyOf(permissions); }
    public static Caller plugin(String pluginName) { return new Caller("plugin:" + pluginName, Set.of("*"), Set.of("*"), false, false); }
    public boolean permits(String action) { return actions.contains("*") || actions.contains(action); }
    public boolean hasPermission(String permission) { return permission.isEmpty() || permissions.contains("*") || permissions.contains(permission); }
}

package com.eldryn.webconnector.http;

import com.eldryn.webconnector.api.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;

public final class SecurityPolicy {
    public record Key(String name, String secret, boolean enabled, Instant expiresAt, Set<String> actions,
                      Set<String> permissions, boolean allowDangerous) {
        public Key {
            if (name == null || !name.matches("[A-Za-z0-9_.-]{1,64}")) throw new IllegalArgumentException("Invalid API key name");
            if (enabled && !strongSecret(secret)) throw new IllegalArgumentException("Enabled API keys require a non-placeholder secret of at least 32 characters");
            actions = Set.copyOf(actions); permissions = Set.copyOf(permissions);
        }
    }
    private final List<Key> keys;
    private final List<Cidr> allowlist;
    private final boolean localDevelopment;
    public SecurityPolicy(List<Key> keys, List<String> allowlist, boolean localDevelopment) {
        this.keys = List.copyOf(keys); this.localDevelopment = localDevelopment;
        Set<String> names = new HashSet<>(), secrets = new HashSet<>();
        for (Key key : keys) {
            if (!names.add(key.name()) || (key.enabled() && !secrets.add(key.secret()))) throw new IllegalArgumentException("Duplicate API key name or secret");
        }
        if (!localDevelopment && keys.stream().noneMatch(k -> k.enabled() && (k.expiresAt() == null || Instant.now().isBefore(k.expiresAt()))))
            throw new IllegalArgumentException("Configure at least one enabled, unexpired API key; see docs/CONFIGURATION.md");
        this.allowlist = allowlist.stream().map(Cidr::new).toList();
    }
    public static boolean strongSecret(String secret) {
        if (secret == null || secret.length() < 32) return false;
        String s = secret.toLowerCase(Locale.ROOT);
        return !(s.contains("change-me") || s.contains("replace-") || s.contains("your-secret"));
    }
    public Caller authenticate(InetAddress address, String secret) {
        if (!allowlist.isEmpty() && allowlist.stream().noneMatch(c -> c.contains(address))) throw new ActionException(403, "ip_forbidden", "Source address is not allowed");
        byte[] incoming = digest(secret == null ? "" : secret);
        Key match = null;
        // Hashes have fixed length; every configured key is compared without early return.
        for (Key key : keys) {
            boolean equal = MessageDigest.isEqual(digest(key.secret() == null ? "" : key.secret()), incoming);
            if (equal && key.enabled() && (key.expiresAt() == null || Instant.now().isBefore(key.expiresAt()))) match = key;
        }
        if (match != null) return new Caller("key:" + match.name(), match.actions(), match.permissions(), match.allowDangerous(), true);
        if (localDevelopment && address.isLoopbackAddress() && (secret == null || secret.isEmpty()))
            return new Caller("development:localhost", Set.of("*"), Set.of(), false, true);
        throw new ActionException(401, "unauthorized", "Valid authentication is required");
    }
    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    static final class Cidr {
        private final byte[] network;
        private final int prefix;
        Cidr(String text) {
            try {
                String[] parts = text.split("/", -1);
                if (parts.length > 2 || !parts[0].matches("[0-9A-Fa-f:.]+")) throw new IllegalArgumentException();
                network = InetAddress.getByName(parts[0]).getAddress();
                prefix = parts.length == 2 ? Integer.parseInt(parts[1]) : network.length * 8;
                if (prefix < 0 || prefix > network.length * 8) throw new IllegalArgumentException();
            } catch (Exception e) { throw new IllegalArgumentException("Invalid IP allowlist entry"); }
        }
        boolean contains(InetAddress address) {
            byte[] candidate = address.getAddress();
            if (network.length != candidate.length) return false;
            for (int bit = 0; bit < prefix; bit++) if (((network[bit / 8] ^ candidate[bit / 8]) & (1 << (7 - bit % 8))) != 0) return false;
            return true;
        }
    }
}

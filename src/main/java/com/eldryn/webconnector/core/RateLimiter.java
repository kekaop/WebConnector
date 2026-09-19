package com.eldryn.webconnector.core;

import java.time.Clock;
import java.util.*;

/** Bounded fixed-window counters. A full table refuses new identities until a window expires. */
public final class RateLimiter {
    private record Window(long minute, int count) { }
    private final Map<String, Window> windows = new HashMap<>();
    private final Clock clock;
    private final int capacity;
    public RateLimiter(int capacity) { this(capacity, Clock.systemUTC()); }
    public RateLimiter(int capacity, Clock clock) { this.capacity = capacity; this.clock = clock; }
    public synchronized boolean acquire(String identity, int limit) {
        long minute = clock.millis() / 60000;
        Window previous = windows.get(identity);
        if (previous == null || previous.minute != minute) {
            if (windows.size() >= capacity) windows.entrySet().removeIf(e -> e.getValue().minute != minute);
            if (!windows.containsKey(identity) && windows.size() >= capacity) return false;
            windows.put(identity, new Window(minute, 1)); return true;
        }
        if (previous.count >= limit) return false;
        windows.put(identity, new Window(minute, previous.count + 1)); return true;
    }
}

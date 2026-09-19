package com.eldryn.webconnector.core;

import com.eldryn.webconnector.api.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/** Durable reservations are written before dispatch. Incomplete work is never replayed after restart. */
public final class OperationStore implements AutoCloseable {
    public record Entry(OperationStatus operation, String identity, String fingerprint) { }
    private final Path directory;
    private final int capacity;
    private final Map<UUID, Entry> entries = new LinkedHashMap<>();
    private final Map<String, UUID> identities = new HashMap<>();
    private final FileChannel lockChannel;
    private final FileLock lock;
    public OperationStore(Path directory, int capacity) throws IOException {
        this.directory = directory; this.capacity = capacity;
        Files.createDirectories(directory);
        lockChannel = FileChannel.open(directory.resolve("store.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired;
        try { acquired = lockChannel.tryLock(); } catch (RuntimeException | IOException e) { lockChannel.close(); throw new IOException("Operation store is locked", e); }
        if (acquired == null) { lockChannel.close(); throw new IOException("Operation store is locked"); }
        lock = acquired;
        try (var files = Files.newDirectoryStream(directory, "*.json")) {
            for (Path file : files) {
                Entry entry;
                try { entry = Json.GSON.fromJson(Files.readString(file), Entry.class); }
                catch (RuntimeException e) { throw new IOException("Invalid operation journal; restore it before starting", e); }
                if (entry == null || entry.operation == null || entry.operation.id() == null || entry.operation.state() == null
                        || entry.operation.action() == null || entry.operation.initiator() == null || entry.operation.requestId() == null
                        || entry.operation.createdAt() == null || entry.fingerprint == null
                        || (entry.operation.terminal() && (entry.operation.result() == null || entry.operation.completedAt() == null))
                        || !file.getFileName().toString().equals(entry.operation.id() + ".json"))
                    throw new IOException("Invalid operation journal");
                if (!entry.operation.terminal()) {
                    OperationStatus o = entry.operation;
                    entry = new Entry(new OperationStatus(o.id(), o.action(), o.createdAt(), Instant.now().toString(),
                            OperationStatus.State.FAILED, ActionResult.failure("interrupted", "Server stopped; outcome may be partial. Reconcile before any new request."), o.initiator(), o.requestId()), entry.identity, entry.fingerprint);
                    write(entry);
                }
                entries.put(entry.operation.id(), entry);
                if (entry.identity != null && identities.put(entry.identity, entry.operation.id()) != null) throw new IOException("Duplicate operation identity");
            }
        } catch (Exception e) { close(); throw e instanceof IOException io ? io : new IOException("Cannot read operation store", e); }
    }
    public synchronized Optional<Entry> byIdentity(String identity) { return Optional.ofNullable(entries.get(identities.get(identity))); }
    public synchronized Optional<OperationStatus> get(UUID id) { return Optional.ofNullable(entries.get(id)).map(Entry::operation); }
    public synchronized Collection<OperationStatus> all() { return entries.values().stream().map(Entry::operation).toList(); }
    public synchronized void reserve(Entry entry) throws IOException {
        if (entries.size() >= capacity) {
            Optional<Entry> victim = entries.values().stream().filter(e -> e.identity == null && e.operation.terminal())
                    .min(Comparator.comparing(e -> e.operation.createdAt()));
            if (victim.isEmpty()) throw new ActionException(429, "journal_full", "Operation journal is full; administrator maintenance is required");
            Files.delete(directory.resolve(victim.get().operation.id() + ".json"));
            entries.remove(victim.get().operation.id());
        }
        write(entry); entries.put(entry.operation.id(), entry);
        if (entry.identity != null) identities.put(entry.identity, entry.operation.id());
    }
    public synchronized void update(OperationStatus operation) throws IOException {
        Entry previous = entries.get(operation.id());
        Entry next = new Entry(operation, previous.identity, previous.fingerprint);
        write(next); entries.put(operation.id(), next);
    }
    private void write(Entry entry) throws IOException {
        Path target = directory.resolve(entry.operation.id() + ".json");
        Path temporary = directory.resolve(entry.operation.id() + ".tmp");
        byte[] bytes = Json.GSON.toJson(entry).getBytes(StandardCharsets.UTF_8);
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        // Fail closed on filesystems without atomic replacement.
        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    @Override public void close() throws IOException { lock.release(); lockChannel.close(); }
}

package com.eldryn.webconnector.core;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Deletes individual regular files only. Directories, links and plugin-owned files are forbidden. */
public final class FileGuard {
    private final Path serverRoot;
    private final List<Path> roots, protectedPaths;
    private final boolean enabled;
    public FileGuard(Path serverRoot, List<String> allowedRoots, List<Path> protectedPaths, boolean enabled) throws IOException {
        this.serverRoot = serverRoot.toRealPath(); this.enabled = enabled;
        this.protectedPaths = protectedPaths.stream().map(p -> p.toAbsolutePath().normalize()).toList();
        List<Path> safe = new ArrayList<>();
        for (String root : allowedRoots) {
            Path p = this.serverRoot.resolve(root).normalize();
            if (!p.startsWith(this.serverRoot) || p.equals(this.serverRoot)) throw new IOException("File roots must be subdirectories of the server directory");
            rejectLinks(p);
            if (this.protectedPaths.stream().anyMatch(x -> p.startsWith(x) || x.startsWith(p))) throw new IOException("File root overlaps WebConnector files");
            safe.add(p);
        }
        roots = List.copyOf(safe);
    }
    public Path validate(String file) throws IOException {
        if (!enabled) throw new IOException("File deletion is disabled");
        Path target = serverRoot.resolve(file).normalize();
        if (roots.stream().noneMatch(r -> target.startsWith(r) && !target.equals(r)) || protectedPaths.stream().anyMatch(target::startsWith))
            throw new IOException("File is outside deletion policy");
        rejectLinks(target);
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Only regular files can be deleted");
        return target;
    }
    private void rejectLinks(Path path) throws IOException {
        Path current = serverRoot;
        if (!path.startsWith(serverRoot)) throw new IOException("Path escapes server root");
        for (Path part : serverRoot.relativize(path)) {
            current = current.resolve(part);
            if (Files.isSymbolicLink(current)) throw new IOException("Symbolic links are forbidden");
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS) && !current.toRealPath().equals(current)) throw new IOException("Redirected filesystem paths are forbidden");
        }
    }
    public void delete(String file) throws IOException { Files.deleteIfExists(validate(file)); }
}

// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.IntSupplier;

/** Finding the service (protocol.md section 3). */
public final class Discovery {
    private Discovery() {}

    /**
     * The runtime directory and its endpoint files: the Unix domain sockets
     * on Linux and macOS, the port and token files on Windows; the names a
     * platform does not use are null.
     *
     * @param directory the runtime directory
     * @param clientSocket {@code client.sock} (Linux, macOS)
     * @param adminSocket {@code admin.sock} (Linux, macOS)
     * @param clientPortFile {@code client.port} (Windows)
     * @param clientTokenFile {@code client.token} (Windows)
     * @param adminPortFile {@code admin.port} (Windows)
     */
    public record Endpoints(
            String directory,
            String clientSocket,
            String adminSocket,
            String clientPortFile,
            String clientTokenFile,
            String adminPortFile) {}

    /** {@code linux}, {@code macos} or {@code windows}, as the rules name this process's. */
    public static String currentOperatingSystem() {
        String name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.startsWith("windows")) {
            return "windows";
        }
        if (name.startsWith("mac")) {
            return "macos";
        }
        return "linux";
    }

    private static String strip(String path, boolean windows) {
        int end = path.length();
        while (end > 0 && (path.charAt(end - 1) == '/' || (windows && path.charAt(end - 1) == '\\'))) {
            end--;
        }
        return end == 0 ? path : path.substring(0, end);
    }

    /**
     * The location of the service (3.1) for {@code operatingSystem} (others
     * than {@code macos} and {@code windows} are treated as {@code linux}),
     * {@code environment} and the numeric user id ({@code uid} is asked only
     * for the {@code /tmp/tsm-<uid>} fallback). Empty when no runtime
     * directory can be named (Windows without {@code LOCALAPPDATA} and
     * {@code USERPROFILE}): the service is not running.
     */
    public static Optional<Endpoints> discover(String operatingSystem, Map<String, String> environment, IntSupplier uid) {
        boolean windows = "windows".equals(operatingSystem);
        String override = environment.getOrDefault("TSM_RUNTIME_DIR", "");
        String directory;
        if (!override.isEmpty()) {
            directory = strip(override, windows);
        } else if (windows) {
            String local = environment.getOrDefault("LOCALAPPDATA", "");
            String profile = environment.getOrDefault("USERPROFILE", "");
            String base;
            if (!local.isEmpty()) {
                base = strip(local, true);
            } else if (!profile.isEmpty()) {
                base = strip(profile, true) + "\\AppData\\Local";
            } else {
                return Optional.empty();
            }
            directory = base + "\\TomSecretsManager\\run";
        } else {
            String value = environment.getOrDefault("macos".equals(operatingSystem) ? "TMPDIR" : "XDG_RUNTIME_DIR", "");
            directory = value.startsWith("/") ? strip(value, false) + "/tsm" : "/tmp/tsm-" + uid.getAsInt();
        }
        if (windows) {
            return Optional.of(new Endpoints(directory, null, null,
                    directory + "\\client.port", directory + "\\client.token", directory + "\\admin.port"));
        }
        return Optional.of(new Endpoints(directory, directory + "/client.sock", directory + "/admin.sock", null, null, null));
    }

    static String stripLineEnd(String text) {
        if (text.endsWith("\r\n")) {
            return text.substring(0, text.length() - 2);
        }
        if (text.endsWith("\n")) {
            return text.substring(0, text.length() - 1);
        }
        return text;
    }

    /**
     * The port of a port file's text (decimal 1-65535, no sign or leading
     * zero, at most one trailing LF or CR LF), or empty when unreadable.
     */
    public static OptionalInt readPortFile(String text) {
        String body = stripLineEnd(text);
        if (!body.matches("[1-9][0-9]{0,4}")) {
            return OptionalInt.empty();
        }
        int port = Integer.parseInt(body);
        return port <= 65535 ? OptionalInt.of(port) : OptionalInt.empty();
    }

    /**
     * The process's user id, for the {@code /tmp/tsm-<uid>} fallback, from
     * the JDK's {@code jdk.security.auth} module ({@code UnixSystem}); -1
     * where it has none (Windows names no such fallback).
     */
    static int processUid() {
        try {
            return (int) new com.sun.security.auth.module.UnixSystem().getUid();
        } catch (Throwable e) {
            return -1;
        }
    }
}

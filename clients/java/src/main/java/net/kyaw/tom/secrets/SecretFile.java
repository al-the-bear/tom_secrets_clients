// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.Arrays;

/**
 * An attachment or a typed key read with {@code getFile} (protocol.md 5.5):
 * its name and bytes. Its {@code toString} never shows the bytes, and {@link
 * #close} overwrites them.
 */
public final class SecretFile implements AutoCloseable {
    private final String reference;
    private final String name;
    private final byte[] data;
    private volatile boolean closed;

    SecretFile(String reference, String name, byte[] data) {
        this.reference = reference;
        this.name = name;
        this.data = data;
    }

    /** The reference the file was asked for, as given. */
    public String reference() {
        return reference;
    }

    /** The field's name (an attachment's file name). */
    public String name() {
        return name;
    }

    /** The size in bytes. */
    public int size() {
        return data.length;
    }

    /**
     * The bytes: the buffer itself, which {@link #close} overwrites.
     *
     * @throws IllegalStateException after {@link #close}
     */
    public byte[] bytes() {
        if (closed) {
            throw new IllegalStateException("the file of " + reference + " was closed");
        }
        return data;
    }

    /** Overwrites the bytes with zeros. */
    @Override
    public void close() {
        Arrays.fill(data, (byte) 0);
        closed = true;
    }

    /** Names the file and its size, never its bytes. */
    @Override
    public String toString() {
        return "SecretFile(" + reference + ": " + name + ", " + data.length + " bytes)";
    }
}

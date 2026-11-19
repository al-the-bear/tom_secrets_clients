// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Frames and JSON payloads (protocol.md section 2). */
final class Frames {
    static final int JSON = 0;
    static final int BINARY = 1;
    /** The largest payload of a frame sent to the service. */
    static final int MAX_REQUEST_PAYLOAD = 64 * 1024;
    /** The largest payload of a frame the service sends. */
    static final int MAX_ANSWER_PAYLOAD = 1024 * 1024;

    private Frames() {}

    /** A frame or payload that breaks section 2; the connection is closed. */
    static final class FrameException extends Exception {
        private static final long serialVersionUID = 1L;

        FrameException(String message) {
            super(message);
        }
    }

    /** One frame: its type and payload. */
    static final class Frame {
        final int type;
        final byte[] payload;

        Frame(int type, byte[] payload) {
            this.type = type;
            this.payload = payload;
        }
    }

    /** A frame: the payload length (4 bytes big-endian), the type, the payload. */
    static byte[] encode(int type, byte[] payload) {
        ByteBuffer out = ByteBuffer.allocate(5 + payload.length);
        out.putInt(payload.length).put((byte) type).put(payload);
        return out.array();
    }

    /**
     * The message of a JSON payload; an error when it is empty, not UTF-8,
     * starts with a byte order mark, is not strict JSON, not an object, or has
     * no string {@code op}.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> decode(byte[] payload) throws FrameException {
        if (payload.length == 0) {
            throw new FrameException("empty payload");
        }
        String text;
        try {
            CharBuffer chars = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload));
            text = chars.toString();
            Arrays.fill(chars.array(), '\0');
        } catch (CharacterCodingException e) {
            throw new FrameException("payload is not UTF-8");
        }
        if (text.startsWith("﻿")) {
            throw new FrameException("payload starts with a byte order mark");
        }
        Object value;
        try {
            value = Json.parse(text);
        } catch (Json.ParseException e) {
            throw new FrameException("payload is not JSON: " + e.getMessage());
        }
        if (!(value instanceof Map)) {
            throw new FrameException("payload is not a JSON object");
        }
        Map<String, Object> m = (Map<String, Object>) value;
        if (!(m.get("op") instanceof String)) {
            throw new FrameException("payload has no op");
        }
        return m;
    }

    /**
     * Splits a byte stream into frames, checking every length against the
     * limit before the payload is read and refusing a frame type that is
     * neither JSON nor (once negotiated) binary.
     */
    static final class Reader {
        private final int maxPayload;
        boolean binaryAllowed;
        private byte[] pending = new byte[0];
        private int length;

        Reader(int maxPayload) {
            this.maxPayload = maxPayload;
        }

        List<Frame> add(byte[] data, int count) throws FrameException {
            if (length + count > pending.length) {
                byte[] grown = Arrays.copyOf(pending, Math.max(pending.length * 2, length + count));
                Arrays.fill(pending, (byte) 0);
                pending = grown;
            }
            System.arraycopy(data, 0, pending, length, count);
            length += count;
            List<Frame> frames = new ArrayList<>();
            int offset = 0;
            while (length - offset >= 5) {
                long size = ByteBuffer.wrap(pending, offset, 4).getInt() & 0xFFFFFFFFL;
                int type = pending[offset + 4] & 0xFF;
                if (size > maxPayload) {
                    throw new FrameException("frame of " + size + " bytes over " + maxPayload);
                }
                if (type != JSON && !(type == BINARY && binaryAllowed)) {
                    throw new FrameException("frame type " + type);
                }
                if (length - offset - 5 < size) {
                    break;
                }
                frames.add(new Frame(type, Arrays.copyOfRange(pending, offset + 5, offset + 5 + (int) size)));
                offset += 5 + (int) size;
            }
            // The bytes handed out held frames (values among them):
            // overwritten as the buffer moves on.
            System.arraycopy(pending, offset, pending, 0, length - offset);
            Arrays.fill(pending, length - offset, length, (byte) 0);
            length -= offset;
            return frames;
        }
    }
}

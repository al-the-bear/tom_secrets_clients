// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A parsed reference (protocol.md section 4). {@link #parse} refuses a
 * malformed one with a {@link SecretsException} of kind {@code MALFORMED}
 * whose {@code reason} is the rule of protocol.md 4.6 it broke; {@link
 * #format} gives the canonical form (4.5).
 *
 * @param target what it names
 * @param qualifiers the bindings, in the order written
 * @param field the effective field: {@link #DEFAULT_FIELD} when none is written
 * @param fieldGiven whether a field was written
 */
public record SecretReference(Target target, List<Binding> qualifiers, String field, boolean fieldGiven) {
    /** The field a reference without {@code #field} names. */
    public static final String DEFAULT_FIELD = "Password";
    /** The longest reference, in bytes of UTF-8. */
    public static final int MAX_REFERENCE_BYTES = 1024;

    private static final String RESERVED = "/#[],:%";

    /** What a reference names. */
    public enum TargetKind {
        /** A key: the value of an entry's {@code tsm.key} field. */
        KEY,
        /** A store, the group path below its root group and the entry title. */
        PATH,
        /** An entry of a store by its KDBX UUID (lower case). */
        UUID
    }

    /**
     * What a reference names: {@code key} for {@link TargetKind#KEY}; {@code
     * store} and {@code segments} (unescaped) for {@link TargetKind#PATH};
     * {@code store} and {@code uuid} for {@link TargetKind#UUID}.
     *
     * @param kind the kind
     * @param key the key, or null
     * @param store the store, or null
     * @param segments the path segments, or an empty list
     * @param uuid the UUID, or null
     */
    public record Target(TargetKind kind, String key, String store, List<String> segments, String uuid) {
        /** Keeps the segments as an unmodifiable list. */
        public Target {
            segments = segments == null ? List.of() : List.copyOf(segments);
        }

        /** A key target. */
        public static Target key(String key) {
            return new Target(TargetKind.KEY, key, null, List.of(), null);
        }

        /** A path target. */
        public static Target path(String store, List<String> segments) {
            return new Target(TargetKind.PATH, null, store, segments, null);
        }

        /** A UUID target. */
        public static Target uuid(String store, String uuid) {
            return new Target(TargetKind.UUID, null, store, List.of(), uuid);
        }
    }

    /**
     * One binding {@code <dimension>:<value>} of a reference's qualifiers.
     *
     * @param dimension the dimension
     * @param value the value, unescaped
     */
    public record Binding(String dimension, String value) {}

    /** Keeps the qualifiers as an unmodifiable list and the field never null. */
    public SecretReference {
        Objects.requireNonNull(target, "target");
        qualifiers = qualifiers == null ? List.of() : List.copyOf(qualifiers);
        field = field == null || field.isEmpty() ? DEFAULT_FIELD : field;
    }

    /** A reference to {@code target} with no qualifiers and the default field. */
    public static SecretReference of(Target target) {
        return new SecretReference(target, List.of(), DEFAULT_FIELD, false);
    }

    private static SecretsException malformed(String reason, String detail) {
        String message = "the reference is malformed: " + reason + (detail.isEmpty() ? "" : " (" + detail + ")");
        return SecretsException.malformed(reason, message);
    }

    private static boolean isName(String s) {
        return s.matches("[a-z][a-z0-9_-]*");
    }

    private static boolean isControl(int c) {
        return c < 0x20 || c == 0x7F;
    }

    /** Parses {@code reference} (protocol.md 4.1-4.4, 4.6). */
    public static SecretReference parse(String reference) throws SecretsException {
        if (reference.getBytes(StandardCharsets.UTF_8).length > MAX_REFERENCE_BYTES) {
            throw malformed("too_long", "");
        }
        if (reference.isEmpty()) {
            throw malformed("empty", "");
        }
        String rest = reference;
        List<Binding> qualifiers = new ArrayList<>();
        if (rest.startsWith("[")) {
            int end = rest.indexOf(']');
            if (end < 0) {
                throw malformed("unclosed_qualifiers", "");
            }
            String body = rest.substring(1, end);
            rest = rest.substring(end + 1);
            if (body.isEmpty()) {
                throw malformed("empty_segment", "[]");
            }
            Set<String> seen = new HashSet<>();
            for (String binding : body.split(",", -1)) {
                String[] parts = binding.split(":", -1);
                if (parts.length != 2) {
                    throw malformed("bad_binding", binding);
                }
                if (!isName(parts[0])) {
                    throw malformed("bad_dimension", parts[0]);
                }
                if (!seen.add(parts[0])) {
                    throw malformed("duplicate_dimension", parts[0]);
                }
                qualifiers.add(new Binding(parts[0], decodeSegment(parts[1])));
            }
        }
        int hash = rest.indexOf('#');
        if (hash >= 0 && rest.indexOf('#', hash + 1) >= 0) {
            throw malformed("reserved_character", "#");
        }
        boolean fieldGiven = hash >= 0;
        String targetText = fieldGiven ? rest.substring(0, hash) : rest;
        if (targetText.isEmpty()) {
            throw malformed("empty_target", "");
        }
        String field = fieldGiven ? decodeSegment(rest.substring(hash + 1)) : DEFAULT_FIELD;
        Target target;
        if (targetText.indexOf('/') < 0) {
            for (String part : targetText.split("\\.", -1)) {
                if (!isName(part)) {
                    throw malformed("bad_key", targetText);
                }
            }
            target = Target.key(targetText);
        } else {
            String[] parts = targetText.split("/", -1);
            String store = parts[0];
            if (!store.matches("[a-z0-9][a-z0-9_-]*")) {
                throw malformed("bad_store", store);
            }
            if (parts.length == 2 && parts[1].startsWith("~")) {
                if (!parts[1].matches("~[0-9A-Fa-f]{32}")) {
                    throw malformed("bad_uuid", parts[1]);
                }
                target = Target.uuid(store, parts[1].substring(1).toLowerCase(java.util.Locale.ROOT));
            } else {
                List<String> segments = new ArrayList<>();
                for (int i = 1; i < parts.length; i++) {
                    String segment = parts[i];
                    if (segment.isEmpty()) {
                        throw malformed("empty_segment", "");
                    }
                    if (segment.charAt(0) == '@' || segment.charAt(0) == '~') {
                        throw malformed("reserved_prefix", segment.substring(0, 1));
                    }
                    segments.add(decodeSegment(segment));
                }
                target = Target.path(store, segments);
            }
        }
        return new SecretReference(target, qualifiers, field, fieldGiven);
    }

    /**
     * The canonical text of {@code reference}: bindings sorted by dimension
     * name (by UTF-8 bytes), every segment escaped in exactly what it must
     * be, the uuid in lower case, the field omitted when it is {@link
     * #DEFAULT_FIELD}. A reference with no canonical text (a dimension bound
     * twice, an empty segment) is an {@link IllegalArgumentException}.
     */
    public static String format(SecretReference reference) {
        StringBuilder out = new StringBuilder();
        if (!reference.qualifiers().isEmpty()) {
            List<Binding> bindings = new ArrayList<>(reference.qualifiers());
            bindings.sort(Comparator.comparing(b -> b.dimension().getBytes(StandardCharsets.UTF_8),
                    java.util.Arrays::compareUnsigned));
            out.append('[');
            for (int i = 0; i < bindings.size(); i++) {
                if (i > 0) {
                    if (bindings.get(i - 1).dimension().equals(bindings.get(i).dimension())) {
                        throw new IllegalArgumentException("a dimension is bound once");
                    }
                    out.append(',');
                }
                out.append(bindings.get(i).dimension()).append(':').append(encodeSegment(bindings.get(i).value(), false));
            }
            out.append(']');
        }
        Target t = reference.target();
        switch (t.kind()) {
            case KEY:
                out.append(t.key());
                break;
            case UUID:
                out.append(t.store()).append("/~").append(t.uuid().toLowerCase(java.util.Locale.ROOT));
                break;
            default:
                out.append(t.store());
                for (String s : t.segments()) {
                    out.append('/').append(encodeSegment(s, true));
                }
        }
        if (!DEFAULT_FIELD.equals(reference.field())) {
            out.append('#').append(encodeSegment(reference.field(), false));
        }
        return out.toString();
    }

    /** The canonical form, or an empty string for a reference that has none. */
    public String canonical() {
        try {
            return format(this);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    @Override
    public String toString() {
        return canonical();
    }

    private static String decodeSegment(String raw) throws SecretsException {
        if (raw.isEmpty()) {
            throw malformed("empty_segment", "");
        }
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int i = 0;
        while (i < raw.length()) {
            char c = raw.charAt(i);
            if (c == '%') {
                String pair = raw.substring(i + 1, Math.min(i + 3, raw.length()));
                if (!pair.matches("[0-9a-fA-F]{2}")) {
                    throw malformed("bad_escape", "%" + pair);
                }
                data.write(Integer.parseInt(pair, 16));
                i += 3;
                continue;
            }
            int cp = raw.codePointAt(i);
            if (RESERVED.indexOf(cp) >= 0) {
                throw malformed("reserved_character", new String(Character.toChars(cp)));
            }
            if (isControl(cp)) {
                throw malformed("control_character", String.format("U+%04X", cp));
            }
            byte[] utf8 = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            data.write(utf8, 0, utf8.length);
            i += Character.charCount(cp);
        }
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data.toByteArray()))
                    .toString();
        } catch (CharacterCodingException e) {
            throw malformed("bad_utf8", "");
        }
    }

    private static String encodeSegment(String text, boolean path) {
        if (text.isEmpty()) {
            throw new IllegalArgumentException("a segment is never empty");
        }
        StringBuilder out = new StringBuilder();
        int index = 0;
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            boolean escape = RESERVED.indexOf(cp) >= 0 || isControl(cp)
                    || (path && index == 0 && (cp == '@' || cp == '~'));
            if (escape) {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append(String.format("%%%02X", b & 0xFF));
                }
            } else {
                out.appendCodePoint(cp);
            }
            i += Character.charCount(cp);
            index++;
        }
        return out.toString();
    }
}

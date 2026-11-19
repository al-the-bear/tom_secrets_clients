// Copyright (c) 2026 Peter Nicolai Alexis Kyaw
// SPDX-License-Identifier: BSD-3-Clause

package net.kyaw.tom.secrets;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The JSON the protocol speaks (protocol.md 2.3): a strict parser (one value,
 * no duplicate member names, numbers in the JSON grammar and inside a
 * {@code double}, no unescaped control characters) and a compact writer. The
 * library needs nothing more, so it carries no JSON dependency.
 *
 * <p>Values are {@code null}, {@link Boolean}, {@link Long} (a whole number
 * written without fraction or exponent that fits), {@link Double}, {@link
 * String}, {@link List} and {@link Map} (a {@link TreeMap}: writing an object
 * gives its members sorted by name).
 */
public final class Json {
    private static final int MAX_DEPTH = 512;

    private Json() {}

    /** Why a text is not strict JSON. */
    public static final class ParseException extends Exception {
        private static final long serialVersionUID = 1L;

        ParseException(String message) {
            super(message);
        }
    }

    /**
     * Parses {@code text} strictly: one value, surrounded by whitespace at
     * most. A lone surrogate escape becomes U+FFFD.
     */
    public static Object parse(String text) throws ParseException {
        Parser p = new Parser(text);
        p.skipWhitespace();
        Object value = p.value(0);
        p.skipWhitespace();
        if (p.at != text.length()) {
            throw p.error("data after the value");
        }
        return value;
    }

    /** The compact JSON text of {@code value}, members sorted by name. */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer) {
            out.append(value);
        } else if (value instanceof Number) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("JSON has no " + d);
            }
            if (d == Math.rint(d) && Math.abs(d) < 1e16) {
                out.append((long) d);
            } else {
                out.append(d);
            }
        } else if (value instanceof String) {
            writeString(out, (String) value);
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item);
            }
            out.append(']');
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : new TreeMap<>((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, (String) e.getKey());
                out.append(':');
                write(out, e.getValue());
            }
            out.append('}');
        } else {
            throw new IllegalArgumentException("no JSON value: " + value.getClass().getName());
        }
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        final String text;
        int at;

        Parser(String text) {
            this.text = text;
        }

        ParseException error(String why) {
            return new ParseException(why + " at " + at);
        }

        void skipWhitespace() {
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    break;
                }
                at++;
            }
        }

        char peek() {
            return at < text.length() ? text.charAt(at) : '\0';
        }

        void expect(String word) throws ParseException {
            if (!text.startsWith(word, at)) {
                throw error("unexpected character");
            }
            at += word.length();
        }

        Object value(int depth) throws ParseException {
            if (depth > MAX_DEPTH) {
                throw error("nested too deeply");
            }
            if (at >= text.length()) {
                throw error("unexpected end");
            }
            char c = text.charAt(at);
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw error("unexpected character");
            }
        }

        Map<String, Object> object(int depth) throws ParseException {
            at++;
            Map<String, Object> object = new TreeMap<>();
            skipWhitespace();
            if (peek() == '}') {
                at++;
                return object;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw error("member name is no string");
                }
                String key = string();
                skipWhitespace();
                if (peek() != ':') {
                    throw error("expected :");
                }
                at++;
                skipWhitespace();
                Object value = value(depth + 1);
                if (object.containsKey(key)) {
                    throw error("duplicate member \"" + key + "\"");
                }
                object.put(key, value);
                skipWhitespace();
                char c = peek();
                at++;
                if (c == '}') {
                    return object;
                }
                if (c != ',') {
                    at--;
                    throw error("expected , or }");
                }
            }
        }

        List<Object> array(int depth) throws ParseException {
            at++;
            List<Object> array = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                at++;
                return array;
            }
            while (true) {
                skipWhitespace();
                array.add(value(depth + 1));
                skipWhitespace();
                char c = peek();
                at++;
                if (c == ']') {
                    return array;
                }
                if (c != ',') {
                    at--;
                    throw error("expected , or ]");
                }
            }
        }

        int hex4() throws ParseException {
            if (at + 4 > text.length()) {
                throw error("short \\u escape");
            }
            int n = 0;
            for (int i = 0; i < 4; i++) {
                int d = Character.digit(text.charAt(at + i), 16);
                if (d < 0) {
                    throw error("bad \\u escape");
                }
                n = n * 16 + d;
            }
            at += 4;
            return n;
        }

        String string() throws ParseException {
            at++;
            StringBuilder out = new StringBuilder();
            while (true) {
                if (at >= text.length()) {
                    throw error("unterminated string");
                }
                char c = text.charAt(at++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    at--;
                    throw error("control character in a string");
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (at >= text.length()) {
                    throw error("unexpected end");
                }
                char escape = text.charAt(at++);
                switch (escape) {
                    case '"':
                        out.append('"');
                        break;
                    case '\\':
                        out.append('\\');
                        break;
                    case '/':
                        out.append('/');
                        break;
                    case 'b':
                        out.append('\b');
                        break;
                    case 'f':
                        out.append('\f');
                        break;
                    case 'n':
                        out.append('\n');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    case 'u':
                        int first = hex4();
                        if (first >= 0xD800 && first < 0xDC00 && text.startsWith("\\u", at)) {
                            int save = at;
                            at += 2;
                            int second = hex4();
                            if (second >= 0xDC00 && second < 0xE000) {
                                out.append((char) first).append((char) second);
                                break;
                            }
                            at = save;
                        }
                        out.append(Character.isSurrogate((char) first) ? '�' : (char) first);
                        break;
                    default:
                        throw error("bad escape");
                }
            }
        }

        Object number() throws ParseException {
            int start = at;
            if (peek() == '-') {
                at++;
            }
            if (peek() == '0') {
                at++;
            } else if (peek() >= '1' && peek() <= '9') {
                while (peek() >= '0' && peek() <= '9') {
                    at++;
                }
            } else {
                throw error("bad number");
            }
            boolean whole = true;
            if (peek() == '.') {
                whole = false;
                at++;
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad number");
                }
                while (peek() >= '0' && peek() <= '9') {
                    at++;
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                whole = false;
                at++;
                if (peek() == '+' || peek() == '-') {
                    at++;
                }
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad number");
                }
                while (peek() >= '0' && peek() <= '9') {
                    at++;
                }
            }
            String number = text.substring(start, at);
            if (whole) {
                try {
                    return Long.parseLong(number);
                } catch (NumberFormatException e) {
                    // outside a long: read as a double below
                }
            }
            double d = Double.parseDouble(number);
            if (Double.isInfinite(d)) {
                throw error("number out of range");
            }
            return d;
        }
    }

    /** The member {@code key} of {@code object} when it is a string, else null. */
    static String string(Map<String, Object> object, String key) {
        Object v = object.get(key);
        return v instanceof String ? (String) v : null;
    }

    /** The member {@code key} of {@code object} when it is an object, else null. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Map<String, Object> object, String key) {
        Object v = object.get(key);
        return v instanceof Map ? (Map<String, Object>) v : null;
    }

    /** {@code v} as a whole number, when it is one. */
    static Long whole(Object v) {
        if (v instanceof Long) {
            return (Long) v;
        }
        if (v instanceof Double) {
            double d = (Double) v;
            if (d == Math.rint(d) && Math.abs(d) <= 9007199254740992.0) {
                return (long) d;
            }
        }
        return null;
    }
}

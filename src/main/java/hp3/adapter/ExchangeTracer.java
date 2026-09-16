package hp3.adapter;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import hp3.h3.Http3Request;
import hp3.h3.Http3Response;
import hp3.h3.qpack.FieldLine;
import hp3.translate.ContentCoding;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** Formats one byte-safe Burp Output block for an adapted exchange. */
public final class ExchangeTracer {

    private final Logging logging;
    private final AtomicLong nextId = new AtomicLong();

    public ExchangeTracer(Logging logging) {
        this.logging = logging;
    }

    public Trace open(HttpRequest source, String host, int port) {
        return open(true, source, host, port);
    }

    public Trace open(boolean enabled, HttpRequest source, String host, int port) {
        return new Trace(enabled ? nextId.incrementAndGet() : 0, enabled, source, host, port);
    }

    public final class Trace {
        private final long id;
        private final boolean enabled;
        private final HttpRequest source;
        private final String host;
        private final int port;

        private Trace(long id, boolean enabled, HttpRequest source, String host, int port) {
            this.id = id;
            this.enabled = enabled;
            this.source = source;
            this.host = host;
            this.port = port;
        }

        public void success(Http3Request request, Http3Response response) {
            if (!enabled) {
                return;
            }
            var out = begin();
            appendRequest(out, request);
            appendFields(out, "Received HTTP/3 response fields", response.fields());
            if (!response.trailers().isEmpty()) {
                appendFields(out, "Response trailers", response.trailers());
            }
            appendResponseBody(out, response);
            emit(finish(out));
        }

        public void exchangeFailure(Http3Request request, String reason) {
            if (!enabled) {
                return;
            }
            var out = begin();
            appendRequest(out, request);
            section(out, "HTTP/3 exchange failure").append(safe(reason)).append('\n');
            emit(finish(out));
        }

        public void translationFailure(String reason) {
            if (!enabled) {
                return;
            }
            var out = begin();
            section(out, "Translation failure; nothing was sent").append(safe(reason)).append('\n');
            emit(finish(out));
        }

        private StringBuilder begin() {
            var out = new StringBuilder()
                    .append("=== HTTP/3 Adapter Trace #").append(id).append(" ===\n")
                    .append("Target: ").append(safe(host)).append(':').append(port).append("\n\n");
            appendSource(out, source);
            return out;
        }

        private String finish(StringBuilder out) {
            return out.append("=== End Trace #").append(id).append(" ===").toString();
        }
    }

    private void emit(String block) {
        try {
            logging.logToOutput(block);
        } catch (RuntimeException | LinkageError ignored) {
            // Diagnostics are observational and must never affect the exchange they describe.
        }
    }

    private static void appendSource(StringBuilder out, HttpRequest source) {
        String version = source.httpVersion() == null ? "unknown" : source.httpVersion();
        section(out, "Burp source request (" + safe(version) + ")");
        if ("HTTP/2".equalsIgnoreCase(version)) {
            out.append(safe(source.method())).append(' ')
                    .append(safe(source.path())).append(" HTTP/2\n");
            for (HttpHeader header : source.headers()) {
                out.append(safe(header.name())).append(": ")
                        .append(safe(header.value())).append('\n');
            }
        } else {
            byte[] raw = source.toByteArray().getBytes();
            int headLength = Math.min(source.bodyOffset(), raw.length);
            String head = new String(raw, 0, headLength, StandardCharsets.ISO_8859_1)
                    .replace("\r\n", "\n");
            out.append(head);
            if (!head.endsWith("\n")) {
                out.append('\n');
            }
        }
        out.append('\n');
        appendBody(out, "Source request body", source.body().getBytes());
    }

    private static void appendRequest(StringBuilder out, Http3Request request) {
        appendFields(out, "Translated HTTP/3 request fields", request.fields());
        appendBody(out, "Request body", request.body());
    }

    private static void appendFields(StringBuilder out, String title, List<FieldLine> fields) {
        section(out, title);
        for (FieldLine field : fields) {
            out.append(safe(field.name())).append(": ")
                    .append(safe(field.value())).append('\n');
        }
        out.append('\n');
    }

    /**
     * The response body, inflated where we can inflate it.
     *
     * <p>Output is plain text, so a compressed body traced verbatim is the one thing in the block
     * guaranteed to be unreadable. Unlike the rendering handed back to Burp this is not evidence and
     * has no fields to keep consistent, so it decodes whatever it can regardless of
     * {@code ResponseOptions} — and says which coding it undid, and what the wire length was, since
     * that is the number the origin's {@code content-length} will have claimed.
     */
    private static void appendResponseBody(StringBuilder out, Http3Response response) {
        byte[] wire = response.body();
        ContentCoding.Decoded result =
                ContentCoding.decode(wire, response.valuesOf("content-encoding"));
        if (result.decoded()) {
            appendBody(out, "Response body", result.body(),
                    ", " + result.appliedCodings() + " decoded from " + wire.length);
        } else if (result.skipReason() != null) {
            appendBody(out, "Response body", wire, ", not decoded: " + result.skipReason());
        } else {
            appendBody(out, "Response body", wire);
        }
    }

    private static void appendBody(StringBuilder out, String title, byte[] body) {
        appendBody(out, title, body, "");
    }

    /** @param note extra detail for the section title, inside the parentheses after the byte count */
    private static void appendBody(StringBuilder out, String title, byte[] body, String note) {
        String text = printableUtf8(body);
        if (text != null) {
            section(out, title + " (" + body.length + " bytes" + safe(note) + ")");
            out.append(text).append('\n');
        } else {
            section(out, title + " (" + body.length + " bytes" + safe(note) + ", hex)");
            appendHex(out, body);
        }
        out.append('\n');
    }

    private static StringBuilder section(StringBuilder out, String title) {
        return out.append("--- ").append(title).append(" ---\n");
    }

    private static String printableUtf8(byte[] bytes) {
        final String value;
        try {
            value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        return value.codePoints().allMatch(c -> c == '\n' || c == '\r' || c == '\t'
                || (!Character.isISOControl(c) && c != 0x7f)) ? value : null;
    }

    private static void appendHex(StringBuilder out, byte[] bytes) {
        for (int offset = 0; offset < bytes.length; offset += 16) {
            out.append(String.format("%08x ", offset));
            int end = Math.min(offset + 16, bytes.length);
            for (int i = offset; i < end; i++) {
                out.append(' ').append(String.format("%02x", bytes[i] & 0xff));
            }
            out.append('\n');
        }
    }

    private static String safe(String value) {
        if (value == null) {
            return "<null>";
        }
        var out = new StringBuilder(value.length());
        value.codePoints().forEach(c -> {
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '\r' -> out.append("\\r");
                case '\n' -> out.append("\\n");
                case '\t' -> out.append("\\t");
                case 0 -> out.append("\\0");
                default -> {
                    if (Character.isISOControl(c) || c == 0x7f) {
                        out.append(String.format("\\x%02x", c));
                    } else {
                        out.appendCodePoint(c);
                    }
                }
            }
        });
        return out.toString();
    }
}

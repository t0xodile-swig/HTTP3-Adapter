package hp3.translate;

import hp3.h3.Http3Response;
import hp3.h3.qpack.FieldLine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Renders an HTTP/3 response as the raw bytes Burp parses.
 *
 * <p>The status line mirrors the request's version rather than announcing {@code HTTP/3}. Burp does
 * accept {@code HTTP/3} — the phase 1 spike confirmed it against a live instance, and the version
 * token is safe for the parsers that matter, Turbo Intruder's included. The reason for mirroring is
 * not compatibility but attention: tooling that reads an adapted response, automated analysis
 * especially, fixates on the unfamiliar version token and reports on it instead of on whatever was
 * actually under test. An {@code HTTP/2} request paired with an {@code HTTP/2} response reads exactly
 * as one Burp sent itself.
 *
 * <p>Which protocol really carried the exchange is therefore recorded in the one place nothing has to
 * parse: the {@code X-Http3} marker field, for a person reading the response. The marker is the one
 * field here that is not the origin's, so {@link ResponseOptions} can switch it off.
 *
 * <p>A standard reason phrase is written even though HTTP/3 carries none. RFC 9114 section 4.1.2
 * defines only {@code :status}, so strictly there is nothing to render — but Burp writes one anyway
 * when it renders an HTTP/2 response, which carries none either, emitting {@code HTTP/2 200 OK}.
 * Matching that convention is what makes an adapted response indistinguishable from one Burp
 * produced itself, and omitting it demonstrably breaks other people's tools: Turbo Intruder derives
 * its Status column by splitting the response on spaces alone, so a status line ending right after
 * the code leaves it parsing {@code "200\r\ncontent-type:"} and reporting 0.
 *
 * <p>Where the registry has no phrase for a code, the separating space is still written, as RFC 9112
 * section 4 requires of HTTP/1.x: "A server MUST send the space that separates the status-code from
 * the reason-phrase even when the reason-phrase is absent".
 *
 * <p>Header fields otherwise pass through exactly as received, including any {@code content-length}
 * the server sent and any it omitted. Nothing is synthesised: whether the origin sent a
 * {@code Content-Length} is often the very thing under test, so decoding restates one that exists and
 * still invents none where there was none.
 *
 * <p>The one case where an origin field does not survive is a body we decoded. Inflating a
 * {@code content-encoding: gzip} body leaves both that field and the compressed {@code content-length}
 * describing bytes that are no longer there, and leaving them is worse than not decoding: Burp's own
 * editor inflates a body when it sees {@code content-encoding}, so it would be handed plaintext and
 * told to gunzip it. The field is therefore dropped and the length restated, and
 * {@link ResponseOptions#verbatim()} switches the whole thing off for anyone who needs the wire bytes.
 * A coding {@link ContentCoding} cannot undo changes nothing at all.
 */
public final class ResponseTranslator {

    private static final String CRLF = "\r\n";
    private static final String CONTENT_ENCODING = "content-encoding";
    private static final String CONTENT_LENGTH = "content-length";

    private ResponseTranslator() {
    }

    /**
     * Serialises {@code response} to the byte form Burp's response parser expects.
     *
     * @param requestHttpVersion the version the request was written in, mirrored in the status line
     * @param options            whether to prepend the {@code X-Http3} marker, and whether to undo
     *                           the content codings the origin applied to the body
     */
    public static byte[] toRawBytes(Http3Response response, String requestHttpVersion,
                                    ResponseOptions options) {
        var out = new ByteArrayOutputStream();
        var head = new StringBuilder();

        byte[] body = response.body();
        boolean decoded = false;
        if (options.decodeContentEncoding()) {
            ContentCoding.Decoded result =
                    ContentCoding.decode(body, response.valuesOf(CONTENT_ENCODING));
            decoded = result.decoded();
            body = result.body();
        }

        int status = response.status();
        // A response with no usable :status is malformed, but rendering it is more useful than
        // refusing it — seeing the malformed thing is the point of the tool.
        head.append(statusLine(HttpVersions.orDefault(requestHttpVersion), status < 0 ? 0 : status))
                .append(CRLF);

        // Ours, so it leads: the point of the marker is to be seen without scrolling. It is also the
        // only field here the origin did not send, which is why it is switchable.
        if (options.addHttp3Marker()) {
            head.append(RequestTranslator.HTTP3_MARKER_HEADER).append(": 1").append(CRLF);
        }

        boolean statusSeen = false;
        for (FieldLine field : response.fields()) {
            if (!statusSeen && field.name().equals(":status")) {
                statusSeen = true;   // became the status line; a duplicate would still be rendered
                continue;
            }
            if (decoded && isNamed(field, CONTENT_ENCODING)) {
                continue;   // it described bytes that are no longer here
            }
            if (decoded && isNamed(field, CONTENT_LENGTH)) {
                // Restated in place rather than appended, because field order is evidence too. The
                // origin's spelling of the name survives, and a duplicated length stays duplicated:
                // how many the origin sent may itself be the thing under test.
                appendField(head, FieldLine.of(field.name(), String.valueOf(body.length)));
                continue;
            }
            appendField(head, field);
        }
        // Trailers have nowhere of their own to live in an HTTP/1 rendering. Appending them keeps
        // them visible, which beats discarding them, at the cost of blurring where they came from.
        for (FieldLine trailer : response.trailers()) {
            appendField(head, trailer);
        }

        head.append(CRLF);
        out.writeBytes(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.writeBytes(body);
        return out.toByteArray();
    }

    /**
     * The status line: version, code, separating space, then the standard reason phrase if the
     * registry has one. The space is written either way.
     */
    private static String statusLine(String version, int status) {
        return version + " " + status + " " + ReasonPhrases.forStatus(status);
    }

    /**
     * RFC 9114 section 4.2.2 requires lowercase field names, but nothing in this stack rejects a
     * response for being malformed, so an origin that sends {@code Content-Encoding} is matched too.
     */
    private static boolean isNamed(FieldLine field, String name) {
        return field.name().equalsIgnoreCase(name);
    }

    private static void appendField(StringBuilder head, FieldLine field) {
        head.append(field.name()).append(": ").append(field.value()).append(CRLF);
    }
}

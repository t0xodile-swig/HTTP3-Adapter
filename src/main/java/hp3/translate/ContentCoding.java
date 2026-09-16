package hp3.translate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Undoes the content codings an origin applied to a response body.
 *
 * <p>Pure bytes in, pure bytes out — no Montoya and no HTTP/3, the same shape as
 * {@link KettleEscapes}, and decode-only for the same reason: nothing here would ever compress, so
 * an encoder would only serve tests that fed our output back to our input.
 *
 * <p>{@code gzip} and {@code deflate} are undone with the JDK's own inflaters. {@code br} and
 * {@code zstd} are not, and rather than mangle them the body comes back exactly as it arrived with
 * {@link Decoded#skipReason()} set. That distinction is load-bearing: {@link ResponseTranslator}
 * rewrites the origin's {@code content-encoding} and {@code content-length} fields only when the
 * body really changed, so a refusal here is what keeps an undecodable response byte-faithful.
 *
 * <p><b>Decoding is all or nothing.</b> Given {@code br, gzip} the gzip layer alone could be
 * unwrapped, but the result is still brotli-encoded and no honest {@code content-encoding} value
 * describes it — the field would have to become {@code br}, which claims the adapter re-encoded
 * something it did not. Partial unwrapping buys nothing and lies.
 */
public final class ContentCoding {

    /**
     * The ceiling on a decoded body.
     *
     * <p>Compression ratios are unbounded, so an origin can answer a one-line request with a few
     * kilobytes that inflate forever. The process that dies is Burp, taking the tester's session
     * with it, so inflation stops here and the wire bytes are handed back instead.
     */
    public static final int MAX_DECODED_BYTES = 64 * 1024 * 1024;

    private static final int CHUNK = 8192;

    /**
     * @param body            the decoded bytes, or the original ones untouched when nothing was
     *                        decoded
     * @param appliedCodings  the normalised coding list that was undone, or null if none was
     * @param skipReason      why a coding the origin applied was left in place, or null when there
     *                        was nothing to undo or everything was undone
     */
    public record Decoded(byte[] body, String appliedCodings, String skipReason) {

        /** Whether {@link #body()} differs from what came off the wire. */
        public boolean decoded() {
            return appliedCodings != null;
        }
    }

    private ContentCoding() {
    }

    /**
     * Undoes every coding in {@code contentEncodingValues}, or none of them.
     *
     * @param contentEncodingValues the values of the response's {@code content-encoding} fields, in
     *                              wire order. A list-valued field may be split across several
     *                              lines, so they are joined before being split on commas.
     */
    public static Decoded decode(byte[] body, List<String> contentEncodingValues) {
        List<String> codings = tokenise(contentEncodingValues);
        if (codings.stream().allMatch(ContentCoding::isNoOp)) {
            return untouched(body, null);
        }
        // A coding on an empty body is vacuous — there is nothing to inflate, and treating it as a
        // failure would strand a perfectly ordinary 204 or HEAD-shaped response with a skip reason.
        if (body.length == 0) {
            return untouched(body, null);
        }

        for (String coding : codings) {
            if (!isSupported(coding)) {
                return untouched(body, coding + " is not a coding this adapter can undo");
            }
        }

        // The field lists codings in the order they were applied (RFC 9110 section 8.4.1), so they
        // come off in the opposite order.
        byte[] decoded = body;
        for (int i = codings.size() - 1; i >= 0; i--) {
            String coding = codings.get(i);
            if (isNoOp(coding)) {
                continue;
            }
            try {
                decoded = undo(coding, decoded);
            } catch (IOException e) {
                return untouched(body, coding + ": " + reason(e));
            }
        }
        return new Decoded(decoded, String.join(", ", codings), null);
    }

    private static Decoded untouched(byte[] body, String skipReason) {
        return new Decoded(body, null, skipReason);
    }

    /** Splits the joined field value on commas, lowercasing and trimming each token. */
    private static List<String> tokenise(List<String> values) {
        var codings = new ArrayList<String>();
        for (String value : values) {
            if (value == null) {
                continue;
            }
            for (String token : value.split(",", -1)) {
                String coding = token.trim().toLowerCase(Locale.ROOT);
                if (!coding.isEmpty()) {
                    codings.add(coding);
                }
            }
        }
        return codings;
    }

    private static boolean isNoOp(String coding) {
        return coding.equals("identity");
    }

    private static boolean isSupported(String coding) {
        return switch (coding) {
            case "gzip", "x-gzip", "deflate", "x-deflate", "identity" -> true;
            default -> false;
        };
    }

    private static byte[] undo(String coding, byte[] body) throws IOException {
        return switch (coding) {
            case "gzip", "x-gzip" -> readCapped(new GZIPInputStream(new ByteArrayInputStream(body)));
            // RFC 9110 section 8.4.1 defines deflate as the zlib wrapper of RFC 1950, but enough
            // servers send bare RFC 1951 that understanding only the wrapper fails on real traffic.
            // Browsers try both; so do we. Wrapped first, because raw data almost always fails
            // zlib's header checksum while the reverse pairing would quietly inflate garbage.
            default -> {
                try {
                    yield inflate(body, false);
                } catch (IOException wrappedFailed) {
                    yield inflate(body, true);
                }
            }
        };
    }

    private static byte[] inflate(byte[] body, boolean raw) throws IOException {
        Inflater inflater = new Inflater(raw);
        try (var in = new InflaterInputStream(new ByteArrayInputStream(body), inflater)) {
            return readCapped(in);
        } finally {
            inflater.end();
        }
    }

    private static byte[] readCapped(InputStream in) throws IOException {
        try (in) {
            var out = new ByteArrayOutputStream();
            byte[] chunk = new byte[CHUNK];
            int total = 0;
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > MAX_DECODED_BYTES) {
                    throw new IOException("inflates past the " + MAX_DECODED_BYTES + " byte ceiling");
                }
                out.write(chunk, 0, read);
            }
            return out.toByteArray();
        }
    }

    /** Inflater failures carry a useful message; truncation surfaces as a bare EOFException. */
    private static String reason(IOException e) {
        String message = e.getMessage();
        return message == null ? e.getClass().getSimpleName() : message;
    }
}

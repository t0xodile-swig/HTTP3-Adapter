package hp3.translate;

/**
 * The version token a response written by this extension announces.
 *
 * <p>The adapter renders only responses received from a real HTTP/3 exchange, and mirrors the
 * request's version so the rule for an absent one lives in a single place.
 *
 * <p>Mirroring is unconditional because every instruction this extension takes is a header. An
 * earlier design asked for the kettling syntax with an invented version token, {@code HTTP/kettled},
 * which meant mirroring had to special-case it: echoing a token no response parser has any reason to
 * accept, in the one place a client definitely does parse, was a real hazard. Keeping the control
 * channel in the fields removes the hazard rather than guarding against it.
 */
public final class HttpVersions {

    /** What Burp uses when it has nothing better, and a status line must say something. */
    public static final String DEFAULT = "HTTP/1.1";

    private HttpVersions() {
    }

    /**
     * The request's version, or {@link #DEFAULT} if Burp reported none. A blank token would render a
     * status line beginning with a space, which no parser handles well.
     *
     * <p>This is what a response to the request should announce — see {@link ResponseTranslator} for
     * why mirroring beats announcing {@code HTTP/3}.
     */
    public static String orDefault(String requestHttpVersion) {
        return requestHttpVersion == null || requestHttpVersion.isBlank()
                ? DEFAULT
                : requestHttpVersion.trim();
    }
}

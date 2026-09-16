package hp3.adapter;

/**
 * The reason Repeater draws in its response pane when the adapter produced no response.
 *
 * <p>The only text the adapter writes for a person to read, and only on a failure. Annotations are
 * left exactly as they arrived: the log already carries the origin and the reason, so a note would be
 * a second copy of that line in a column shared with every other tool. A successful exchange writes
 * nothing at all, because the response it hands back carries the {@code X-Http3: 1} marker field and
 * says what carried it.
 *
 * <p>Its own class because it is the only part of {@link Hp3HttpHandler} that can be judged without a
 * live exchange. Pure strings in, pure strings out, so {@code Hp3NoticesTest} covers the wording
 * directly.
 *
 * <p>A reason has a whole pane to itself and names the adapter, because a person reading it has no
 * other clue where the bytes came from. It also distinguishes "no request was sent" from "no response
 * came back", which is the first thing they need to know.
 */
final class Hp3Notices {

    private Hp3Notices() {
    }

    /** Repeater pane text for a request refused before anything was sent. */
    static String kettleSyntaxReason(String detail) {
        return "[HTTP/3 adapter] no request was sent. Kettled syntax error: " + detail;
    }

    /** Repeater pane text for an exchange that was attempted and did not produce a response. */
    static String failureReason(String host, int port, String reason) {
        return "[HTTP/3 adapter] no response from " + host + ":" + port + ". " + reason;
    }

    /**
     * Replaces anything outside printable ASCII, so a reason built from an exception message a server
     * or a library chose cannot put a control character into the response pane.
     *
     * <p>Not folded into the builders above: the guarantee belongs at the point the text becomes
     * bytes, and applying it twice to the same string would be a second chance to be wrong.
     * {@code ByteArray.byteArray(String)} narrows each char to a byte rather than encoding it, so an
     * em-dash arrives on screen as a bare 0x14 that renders as a gap rather than as a character.
     */
    static String ascii(String text) {
        var out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            out.append(c >= 0x20 && c < 0x7f ? c : '?');
        }
        return out.toString();
    }
}

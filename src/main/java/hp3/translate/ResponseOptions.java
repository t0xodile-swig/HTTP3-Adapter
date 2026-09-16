package hp3.translate;

/**
 * What {@link ResponseTranslator} does to an adapted response beyond relaying what the origin sent.
 *
 * <p>Both switches exist for the same reason: the response is evidence. Everything the origin sent
 * is rendered verbatim — including any {@code content-length} it sent and any it omitted — so
 * anything of ours, whether a field we add or a body we rewrite, must be possible to remove for
 * anyone comparing responses byte for byte. {@link #verbatim()} turns off both.
 *
 * @param addHttp3Marker        prepend {@code X-Http3: 1} to the fields, ahead of everything the
 *                              origin sent, so a person can confirm at a glance that the exchange
 *                              really used HTTP/3. The status line cannot carry that information any
 *                              more: it mirrors the request's version, because a response announcing
 *                              {@code HTTP/3} draws the attention of anything inspecting it away from
 *                              what is actually under test.
 * @param decodeContentEncoding undo the content codings the origin applied to the body, dropping the
 *                              {@code content-encoding} field and restating any {@code content-length}
 *                              it sent. Off leaves the compressed bytes and both fields exactly as
 *                              they arrived. Codings we cannot undo are left alone either way — see
 *                              {@link ContentCoding}.
 */
public record ResponseOptions(boolean addHttp3Marker, boolean decodeContentEncoding) {

    /** What ordinary use wants: the origin's response, decoded, plus a marker saying how it travelled. */
    public static ResponseOptions defaults() {
        return new ResponseOptions(true, true);
    }

    /** The origin's bytes and nothing else. Nothing of ours appears, and the body is not touched. */
    public static ResponseOptions verbatim() {
        return new ResponseOptions(false, false);
    }

    public ResponseOptions withHttp3Marker(boolean add) {
        return new ResponseOptions(add, decodeContentEncoding);
    }

    public ResponseOptions withContentDecoding(boolean decode) {
        return new ResponseOptions(addHttp3Marker, decode);
    }
}

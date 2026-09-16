package hp3.translate;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import hp3.h3.Http3Request;
import hp3.h3.qpack.FieldLine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Turns Burp's HTTP/1 view of a request into an HTTP/3 field list.
 *
 * <p>The single documented place where pseudo-headers are derived. Everything below this class does
 * as it is told; everything above works in Burp's terms.
 *
 * <p>Three deliberate departures from passing an ordinary message through untouched, each because
 * the HTTP/1 view cannot express a distinction HTTP/3 requires. Kettled translation applies none of
 * them. Ordinary translation always lowercases names and folds {@code Host}; its five
 * connection-specific fields are independently switchable through {@link TranslationOptions}.
 *
 * <ul>
 *   <li><b>Field names are lowercased.</b> RFC 9114 section 4.2.2 requires lowercase names and says
 *       a message containing uppercase ones must be treated as malformed. Burp's request editor
 *       writes {@code Accept:} and {@code User-Agent:}, so without this every ordinary request
 *       earns a 400 — which is precisely what quic.nginx.org returned before this was added. Burp
 *       normalises the same way when mapping an HTTP/1 view onto HTTP/2.</li>
 *   <li><b>Connection-specific fields are dropped by default.</b> RFC 9114 section 4.2
 *       requires that a message containing {@code Connection}, {@code Keep-Alive},
 *       {@code Proxy-Connection}, {@code Transfer-Encoding} or {@code Upgrade} be treated as
 *       malformed. Each field has its own setting, checked by default for correct implementations
 *       and individually removable when deliberately malformed traffic is wanted.</li>
 *   <li><b>{@code Host} becomes {@code :authority}.</b> The two carry the same information and
 *       sending both invites a mismatch the origin never sees.</li>
 * </ul>
 *
 * <p>Beyond those rules nothing is normalised: field order and duplicates survive, and no field is
 * ever synthesised — notably not {@code Content-Length}.
 *
 * <h2>Authoring pseudo-headers</h2>
 *
 * <p>Ordinary HTTP/1-shaped translation derives the canonical four pseudo-headers. Authored
 * pseudo-header-shaped fields are retained after that derived block, so malformed duplicates reach
 * the peer rather than replacing the values implied by the request line. Burp splits a line such as
 * {@code :method: BREW} at its leading colon and gives this class an empty name with the value
 * {@code "method: BREW"}; ordinary translation reconstructs that authored field before appending it.
 * Only kettled translation treats recovered authored pseudo-header lines as overrides.
 *
 * <h2>Kettled requests</h2>
 *
 * <p>{@link #toKettledHttp3} reads a second input language, in which the destruction above is undone
 * — see {@link KettleEscapes} for the escapes and {@link #KETTLED_MARKER_HEADER} for the marker. It is
 * a separate entry point rather than a {@link TranslationOptions} flag for two reasons: the languages
 * differ in what they can express rather than in how much they normalise, and only one of them can
 * fail on syntax. A caller that must handle {@link KettleSyntaxException} is a caller that asked for
 * kettling.
 */
public final class RequestTranslator {

    /**
     * Asking for HTTP/3 by header rather than by request line.
     *
     * <p>This is the only trigger, for every HTTP version. Editing the request line to
     * {@code HTTP/3} worked in the HTTP/1 view but could never work in the HTTP/2 view, where the
     * version is fixed at {@code HTTP/2} and Burp overwrites any attempt to change it. One mechanism
     * that behaves identically everywhere beats two that behave differently per view. The header can
     * be added anywhere — either message view, a Proxy match-and-replace rule, an Intruder
     * template — and survives all of them.
     *
     * <p>Always stripped before the request goes out, regardless of {@link TranslationOptions}. It
     * is our own control channel: letting it reach the origin would both give the game away and
     * change the request under test.
     */
    public static final String HTTP3_MARKER_HEADER = "X-Http3";

    /**
     * Asking for the kettling escape syntax, saying how to <em>read</em> this request.
     *
     * <p>A header for the same reason {@link #HTTP3_MARKER_HEADER} is one: it can be written in any
     * view, from any tool, and survives every route into the handler. An earlier design used an
     * invented version token in the request line, {@code HTTP/kettled}, which worked only because Burp
     * happens to carry an unrecognised token through to {@code httpVersion()} — a narrow assumption,
     * unavailable in the HTTP/2 view where the version is fixed, and one that leaked into the response
     * status line and had to be mapped back out again.
     *
     * <p>Presence is the whole signal; the value is never read. Stripped before the request goes out
     * on the same terms as the HTTP/3 marker — <em>including</em> in kettled mode, which otherwise
     * normalises nothing. That is not an exception to the promise: the promise is about the request,
     * and this field is ours rather than part of it.
     */
    public static final String KETTLED_MARKER_HEADER = "X-Kettled";

    private RequestTranslator() {
    }

    public static Http3Request toHttp3(HttpRequest request) {
        return toHttp3(request, TranslationOptions.defaults());
    }

    public static Http3Request toHttp3(HttpRequest request, TranslationOptions options) {
        return assemble(request, fieldsAsBurpParsedThem(request),
                request.method(), request.path(), options, true);
    }

    /**
     * Translates a request written in the kettled syntax.
     *
     * <p>Escapes are resolved in field names, field values, and the method and path. The body is left
     * exactly as written: an HTTP/1 body already carries any byte, so escaping there would buy nothing
     * and would corrupt any payload that happens to contain a caret.
     *
     * <p>The syntax exists for the HTTP/1 view, whose parser destroys the bytes that make a request
     * kettled, but nothing here is specific to it and the marker can be written in either view. In the
     * HTTP/2 view the escapes buy the one thing that view cannot otherwise reach: control characters in
     * a field value. Burp's send pipeline sanitises a raw CR LF out of {@code headers()} before a
     * handler ever sees it, while {@code ^~} is two printable bytes that travel untouched and become a
     * CR LF here.
     *
     * @throws KettleSyntaxException if any escape is malformed. Nothing is sent in that case — a
     *                               partially decoded request would look like the one that was
     *                               intended, and no client can tell the difference from the response.
     */
    public static Http3Request toKettledHttp3(HttpRequest request) throws KettleSyntaxException {
        return assemble(request, kettledFields(request),
                KettleEscapes.decode(request.method()),
                KettleEscapes.decode(request.path()), TranslationOptions.none(), false);
    }

    /**
     * The fields as Burp parsed them, with names normalised and pseudo-header-shaped text recovered.
     *
     * <p>After Burp's first-colon split, {@code :method: TRACE} and a genuinely empty-named field
     * whose value is {@code method: TRACE} are indistinguishable. Ordinary translation interprets
     * any empty-named field whose value contains a colon as the former. With no second colon it keeps
     * the empty name untouched.
     */
    private static List<InputField> fieldsAsBurpParsedThem(HttpRequest request) {
        List<InputField> fields = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            FieldLine parsed = FieldLine.of(header.name(), header.value());
            boolean recoveredFromEmptyName = false;
            if (header.name().isEmpty()) {
                int colon = header.value().indexOf(':');
                if (colon >= 0) {
                    parsed = recoverPseudoHeader(header.value(), colon);
                    recoveredFromEmptyName = true;
                }
            }
            FieldLine normalised = FieldLine.of(
                    parsed.name().toLowerCase(Locale.ROOT), parsed.value());
            fields.add(new InputField(normalised,
                    normalised.isPseudoHeader() && !recoveredFromEmptyName));
        }
        return fields;
    }

    /**
     * The fields with the kettled syntax resolved: escapes decoded, and pseudo-header lines rebuilt
     * from what Burp left of them.
     */
    private static List<InputField> kettledFields(HttpRequest request)
            throws KettleSyntaxException {
        List<InputField> fields = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            FieldLine parsed = header.name().isEmpty()
                    ? recoverPseudoHeader(header.value())
                    : FieldLine.of(header.name(), header.value());
            FieldLine decoded = FieldLine.of(KettleEscapes.decode(parsed.name()),
                    KettleEscapes.decode(parsed.value()));
            fields.add(new InputField(decoded, decoded.isPseudoHeader()));
        }
        return fields;
    }

    /**
     * Rebuilds {@code :method: BREW} from the wreckage Burp makes of it.
     *
     * <p>Burp splits a header line at its first colon, so a pseudo-header line arrives as a field with
     * an empty name carrying the rest of the line — {@code "method: BREW"} — as its value. Splitting
     * that at <em>its</em> first colon and putting the leading colon back is exact, because the only
     * information Burp discarded was the position of a colon it is about to be given back.
     *
     * <p>One leading space is dropped from the value, being the separator's optional whitespace that
     * Burp would itself have stripped had it recognised the line. A value that really does begin with
     * a space is written {@code ^s}.
     *
     * <p>The cost: in kettled mode an empty field name always means a pseudo-header line, so a
     * genuinely empty-named field cannot be written at all. Ordinary translation can retain one
     * only when its value contains no colon; otherwise it is indistinguishable from the wreckage
     * above and is recovered as pseudo-header-shaped input.
     */
    private static FieldLine recoverPseudoHeader(String remainderOfLine)
            throws KettleSyntaxException {
        int colon = remainderOfLine.indexOf(':');
        if (colon < 0) {
            throw new KettleSyntaxException(
                    "a field with an empty name means a pseudo-header line in a kettled request, but \""
                            + remainderOfLine + "\" has no colon to split on");
        }
        return recoverPseudoHeader(remainderOfLine, colon);
    }

    private static FieldLine recoverPseudoHeader(String remainderOfLine, int colon) {
        String value = remainderOfLine.substring(colon + 1);
        if (value.startsWith(" ")) {
            value = value.substring(1);
        }
        return FieldLine.of(":" + remainderOfLine.substring(0, colon), value);
    }

    /**
     * Builds the leading pseudo-header block, retains the remaining authored fields in order, and
     * applies whichever prohibited-field filters {@code options} asks for. Common to both input
     * languages, and cannot fail: by this point every escape has already been resolved.
     */
    private static Http3Request assemble(HttpRequest request, List<InputField> fields,
                                         String method, String path, TranslationOptions options,
                                         boolean foldHostIntoAuthority) {
        List<FieldLine> assembled = new ArrayList<>();
        Set<String> suppliedPseudoHeaders = new LinkedHashSet<>();

        // Structured pseudo-fields and kettled input override the derived block. A pseudo-header
        // recovered from ordinary HTTP/1-shaped text deliberately remains trailing instead.
        for (InputField input : fields) {
            if (input.overridesDerivedPseudoHeader()) {
                suppliedPseudoHeaders.add(input.field().name());
                assembled.add(input.field());
            }
        }

        // Kettled or structured input fills only what it did not supply. Ordinary HTTP/1-shaped
        // input always derives all four.
        addIfAbsent(assembled, suppliedPseudoHeaders, ":method", method);
        addIfAbsent(assembled, suppliedPseudoHeaders, ":scheme",
                request.httpService().secure() ? "https" : "http");
        addIfAbsent(assembled, suppliedPseudoHeaders, ":authority", authority(fields, request));
        addIfAbsent(assembled, suppliedPseudoHeaders, ":path", path);

        // Remaining authored fields, in order. In ordinary mode this deliberately includes pseudos.
        for (InputField input : fields) {
            FieldLine field = input.field();
            String name = field.name();
            if (input.overridesDerivedPseudoHeader()) {
                continue;   // already emitted above
            }
            if (foldHostIntoAuthority && name.equalsIgnoreCase("host")) {
                continue;   // folded into :authority
            }
            if (isOurControlHeader(name)) {
                continue;   // ours; never goes on the wire
            }
            if (options.shouldStrip(name)) {
                continue;
            }
            assembled.add(field);
        }

        return new Http3Request(assembled, request.body().getBytes());
    }

    /**
     * True for the two fields that instruct this extension rather than forming part of the request.
     *
     * <p>Both are stripped regardless of {@link TranslationOptions}, kettled mode included. Letting
     * either reach the origin would give the game away and change the request under test.
     */
    private static boolean isOurControlHeader(String fieldName) {
        return fieldName.equalsIgnoreCase(HTTP3_MARKER_HEADER)
                || fieldName.equalsIgnoreCase(KETTLED_MARKER_HEADER);
    }

    private static void addIfAbsent(List<FieldLine> fields, Set<String> supplied, String name,
                                    String derivedValue) {
        if (!supplied.contains(name)) {
            fields.add(FieldLine.of(name, derivedValue));
        }
    }

    /**
     * The Host field if there is one, otherwise the service, with the port when non-default.
     *
     * <p>Read from the gathered fields rather than from the request, so that a kettled {@code Host}
     * contributes its decoded value. An authority is derived even when {@code Host} is being sent as a
     * regular field, because HTTP/3 needs one either way.
     */
    private static String authority(List<InputField> fields, HttpRequest request) {
        for (InputField input : fields) {
            FieldLine field = input.field();
            if (field.name().equalsIgnoreCase("host") && !field.value().isBlank()) {
                return field.value();
            }
        }
        var service = request.httpService();
        int defaultPort = service.secure() ? 443 : 80;
        return service.port() == defaultPort
                ? service.host()
                : service.host() + ":" + service.port();
    }

    /** A parsed field plus whether it belongs in the leading pseudo-header override block. */
    private record InputField(FieldLine field, boolean overridesDerivedPseudoHeader) {
    }

    /** True if the request carries the marker asking for HTTP/3. */
    public static boolean isMarkedForHttp3(HttpRequest request) {
        return carries(request, HTTP3_MARKER_HEADER);
    }

    /**
     * True if the request asks for the kettling escape syntax.
     *
     * <p>Note this says nothing about transport: {@link #KETTLED_MARKER_HEADER} selects how to read the
     * request, and {@link #HTTP3_MARKER_HEADER} still selects how to send it. A kettled request
     * without the HTTP/3 marker cannot be sent at all — its decoded bytes have no HTTP/1 representation
     * to hand back to Burp, which is the whole reason the syntax exists — so it passes through
     * undecoded.
     */
    public static boolean isKettled(HttpRequest request) {
        return carries(request, KETTLED_MARKER_HEADER);
    }

    /**
     * Whether the request carries a field with this name, compared without regard to case.
     *
     * <p>A field name is case-insensitive in every HTTP version, and the HTTP/2 view settles the matter
     * anyway: names there are lowercase, so a marker written as {@code X-Kettled} in Repeater arrives as
     * {@code x-kettled}. Done by hand rather than through {@code hasHeader} so that recognising a marker
     * and {@link #isOurControlHeader stripping} it cannot disagree — a marker that triggered but was not
     * stripped, or was stripped but did not trigger, would be a confusing bug in either direction.
     */
    private static boolean carries(HttpRequest request, String fieldName) {
        return request.headers().stream()
                .anyMatch(header -> header.name().equalsIgnoreCase(fieldName));
    }
}

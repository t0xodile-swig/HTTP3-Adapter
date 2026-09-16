package hp3.adapter;

import burp.api.montoya.http.message.requests.HttpRequest;
import hp3.discovery.H3SupportRegistry.Support;
import hp3.translate.RequestTranslator;

/**
 * Decides whether one request should be adapted onto HTTP/3.
 *
 * <p>A pure function of the mode, which markers the request carries and what is already known about
 * the origin, so the whole decision matrix is testable without Burp or a network.
 */
public final class Hp3ModeDecider {

    /** The version token that used to be the trigger, kept only to recognise it and warn. */
    public static final String HTTP_3 = "HTTP/3";

    private Hp3ModeDecider() {
    }

    /**
     * @param explicitlyRequested the request carries the {@code X-Http3} marker header
     */
    public static Hp3Decision decide(Hp3Mode mode, boolean explicitlyRequested, Support support) {
        // An explicit request wins in either mode, and even for an origin cached as unsupported.
        // The cache exists to spare mode 1 pointless handshakes, not to overrule a direct
        // instruction — and if it does fail, the adapter drops it with diagnostics rather than
        // silently downgrading a request that asked for HTTP/3 by name.
        if (explicitlyRequested) {
            return Hp3Decision.SEND_H3;
        }
        if (mode == Hp3Mode.EXPLICIT_ONLY) {
            return Hp3Decision.PASS_THROUGH;
        }
        return switch (support) {
            case SUPPORTED -> Hp3Decision.SEND_H3;
            case UNSUPPORTED -> Hp3Decision.PASS_THROUGH;
            // Trying is the only way to find out, since an advertisement cannot be trusted.
            case UNKNOWN -> Hp3Decision.PROBE_THEN_H3;
        };
    }

    /** Resolves a speculative decision after the origin's shared discovery completes. */
    public static Hp3Decision afterDiscovery(Support support) {
        return support == Support.SUPPORTED ? Hp3Decision.SEND_H3 : Hp3Decision.PASS_THROUGH;
    }

    /**
     * Whether this request asks for HTTP/3.
     *
     * <p>The {@code X-Http3} marker header is the only trigger, for every HTTP version. Editing the
     * request line to {@code HTTP/3} used to work in the HTTP/1 view, but it could never work in the
     * HTTP/2 view — an HTTP/2 request always reports {@code HTTP/2} and Burp overwrites any attempt
     * to change it. One mechanism that behaves identically everywhere beats two that behave
     * differently per view.
     */
    public static boolean isExplicitlyRequested(HttpRequest request) {
        return RequestTranslator.isMarkedForHttp3(request);
    }

    /**
     * True for a request that looks like someone expected the old request-line trigger to work.
     * Used only to log a hint; it does not adapt anything.
     */
    public static boolean looksLikeStaleVersionTrigger(HttpRequest request) {
        return HTTP_3.equalsIgnoreCase(request.httpVersion())
                && !RequestTranslator.isMarkedForHttp3(request);
    }

    /**
     * True for a kettled request that will not be sent kettled, because it did not ask for HTTP/3.
     *
     * <p>{@code X-Kettled} says how to read a request; {@code X-Http3} says how to send it. Left without
     * the HTTP/3 marker there is nothing useful to do: the decoded bytes exist precisely because they
     * have no HTTP/1 representation, so they cannot be handed back to Burp to send. The request passes
     * through with its escapes intact as ordinary text, which is almost certainly not what was meant —
     * hence a hint. Used only to log; it adapts nothing.
     */
    public static boolean looksLikeKettledWithoutMarker(HttpRequest request) {
        return RequestTranslator.isKettled(request)
                && !RequestTranslator.isMarkedForHttp3(request);
    }
}

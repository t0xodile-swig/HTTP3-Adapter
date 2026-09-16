package hp3.adapter;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import hp3.discovery.H3SupportRegistry;
import hp3.discovery.H3SupportRegistry.Support;
import hp3.h3.Http3Response;
import hp3.translate.RequestTranslator;
import hp3.translate.ResponseOptions;
import hp3.translate.ResponseTranslator;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CancellationException;

/**
 * Asks one origin whether it speaks HTTP/3, by asking it something.
 *
 * <p>The probe is a synthetic {@code GET /} rather than a replay of anything selected. A menu item
 * that reports a capability must not change state on the target, and a selection can contain a
 * {@code POST}; beyond that the question is about the origin, so asking it once per origin with a
 * constant request makes the evidence comparable across a sweep.
 *
 * <p>An origin that answers {@code 404} supports HTTP/3. Any status at all means the handshake, the
 * SETTINGS exchange and a complete frame round trip all succeeded, which is the entire question.
 *
 * <p>The request goes through {@link RequestTranslator} rather than being hand-assembled into field
 * lines, so a probe exercises the same translation an adapted request gets. A probe that took a
 * private path could pass while the shipped path was broken.
 */
public final class Hp3OriginProbe {

    /** What the user asked for on the Organizer item. Exact wording; it is what makes the list. */
    public static final String SUPPORTS_NOTE = "supports h3";

    private final Hp3Exchange exchange;
    private final H3SupportRegistry registry;

    public Hp3OriginProbe(Hp3Exchange exchange, H3SupportRegistry registry) {
        this.exchange = exchange;
        this.registry = registry;
    }

    public ProbeResult probe(HttpService origin) {
        String host = origin.host();
        int port = origin.port();
        HttpRequest request = probeRequest(origin);

        // Set between the handshake and the exchange, which is what distinguishes "this origin has no
        // HTTP/3" from "this one request failed". Recording the wrong one would suppress every later
        // attempt to the host for the session.
        var connectionEstablished = new AtomicBoolean(false);

        try {
            Http3Response response =
                    exchange.send(RequestTranslator.toHttp3(request), host, port, connectionEstablished);
            registry.recordSupported(host, port);
            return ProbeResult.answered(origin, HttpRequestResponse.httpRequestResponse(
                    request, render(response, request), Annotations.annotations(SUPPORTS_NOTE)));

        } catch (InterruptedException e) {
            // Extension unload and sweep cancellation are local events, not evidence about the
            // origin. In particular, never poison the support registry because our own executor
            // stopped accepting or waiting for work.
            Thread.currentThread().interrupt();
            throw new CancellationException("HTTP/3 probe interrupted");
        } catch (Exception e) {
            // The same rule the handler uses, and for the same reason: a completed handshake is proof
            // about the origin whatever failed afterwards. fallBackToBurp is meaningless here — nothing
            // is being sent on anyone's behalf — so the decision passed in is the one that never asks
            // for a fallback.
            Support support =
                    Hp3FailureOutcome.of(connectionEstablished.get(), Hp3Decision.SEND_H3).toRecord();
            registry.record(host, port, support);

            // The pool is deliberately left alone. A failed request does not mean a broken connection,
            // and acquire already replaces one that really is dead, so discarding it here would only
            // cost the next probe a whole handshake.
            String reason = describe(e);
            return connectionEstablished.get()
                    ? ProbeResult.handshakeOnly(origin, reason)
                    : ProbeResult.noHttp3(origin, reason);
        }
    }

    /**
     * The probe request: {@code GET /}, nothing else.
     *
     * <p>No adapter marker. Markers are how a request written in Burp asks to be adapted; this one is
     * not going through Burp's send path at all, and a marker would only be a field to strip again.
     */
    public static HttpRequest probeRequest(HttpService origin) {
        // No Host header: RequestTranslator then derives :authority from HttpService, including a
        // non-default port and correct IPv6 bracket syntax. Supplying host() alone would override
        // that derivation and silently probe the wrong authority.
        return HttpRequest.httpRequest(origin, "GET / HTTP/1.1\r\n\r\n");
    }

    private static HttpResponse render(Http3Response response, HttpRequest request) {
        return HttpResponse.httpResponse(ByteArray.byteArray(
                ResponseTranslator.toRawBytes(response, request.httpVersion(),
                        ResponseOptions.defaults())));
    }

    private static String describe(Throwable t) {
        String message = t.getMessage();
        return t.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }
}

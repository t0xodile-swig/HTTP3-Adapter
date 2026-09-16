package hp3.adapter;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import hp3.discovery.H3SupportRegistry;
import hp3.h3.Http3Request;
import hp3.h3.Http3Response;
import hp3.translate.KettleSyntaxException;
import hp3.translate.RequestTranslator;
import hp3.translate.ResponseOptions;
import hp3.translate.ResponseTranslator;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Adapts outbound requests onto HTTP/3 and hands the result back to Burp.
 *
 * <p>We intercept the request before Burp sends it and run the exchange ourselves over QUIC. A real
 * backend response is returned through {@code RequestToBeSentAction.spoof}; an adapter failure is
 * dropped and written to the log, so Burp never mistakes it for an HTTP response. See
 * {@link #failed} for the one carve-out, which shows the reason in Repeater without inventing a
 * status.
 *
 * <p>Whether an origin speaks HTTP/3 is learned by trying, never by reading {@code Alt-Svc}. An
 * advertisement is a claim: vimeo.com advertises {@code h3=":443"} and does not answer QUIC at all
 * from every network, so believing it meant sending real traffic to an origin that could not receive
 * it. The result is remembered for the life of the extension.
 */
public final class Hp3HttpHandler implements HttpHandler {

    private final Hp3Configuration configuration;
    private final H3SupportRegistry registry;
    private final Hp3Exchange exchange;
    private final Hp3DiscoveryCoordinator discovery;
    private final Logging logging;
    private final ExchangeTracer tracer;

    public Hp3HttpHandler(Hp3Configuration configuration, H3SupportRegistry registry,
                          Hp3Exchange exchange,
                          Hp3DiscoveryCoordinator discovery, Logging logging, ExchangeTracer tracer) {
        this.configuration = configuration;
        this.registry = registry;
        this.exchange = exchange;
        this.discovery = discovery;
        this.logging = logging;
        this.tracer = tracer;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String host = requestToBeSent.httpService().host();
        int port = requestToBeSent.httpService().port();

        Hp3Decision decision = Hp3ModeDecider.decide(
                configuration.mode(),
                Hp3ModeDecider.isExplicitlyRequested(requestToBeSent),
                registry.lookup(host, port));

        if (decision == Hp3Decision.PASS_THROUGH) {
            if (Hp3ModeDecider.looksLikeStaleVersionTrigger(requestToBeSent)) {
                logging.logToOutput("Request line says HTTP/3 but the trigger is the "
                        + RequestTranslator.HTTP3_MARKER_HEADER
                        + " header. Add it, or switch to mode 1. Passing this one through.");
            }
            if (Hp3ModeDecider.looksLikeKettledWithoutMarker(requestToBeSent)) {
                logging.logToOutput("This request carries " + RequestTranslator.KETTLED_MARKER_HEADER
                        + " but nothing asked for HTTP/3, and kettled bytes cannot be handed back to "
                        + "Burp to send. Add the " + RequestTranslator.HTTP3_MARKER_HEADER
                        + " header, or switch to mode 1. Passing this one through with its escapes "
                        + "undecoded.");
            }
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        int targetPort = port;
        ExchangeTracer.Trace trace = tracer.open(configuration.traceAdaptedExchanges(),
                requestToBeSent, host, targetPort);

        // Translated before anything is attempted, so that a malformed escape costs one clear error
        // rather than a connection. Nothing is sent, and in particular the origin is not recorded as
        // lacking HTTP/3, it was never asked.
        Http3Request http3Request;
        try {
            http3Request = translate(requestToBeSent);
        } catch (KettleSyntaxException e) {
            trace.translationFailure(e.getMessage());
            logging.logToError("Refused a kettled request to " + host + ":" + targetPort + ": "
                    + e.getMessage());
            return failed(requestToBeSent, Hp3Notices.kettleSyntaxReason(e.getMessage()));
        }

        // Validate and translate before discovery. A malformed request says nothing about whether
        // the origin supports HTTP/3 and must not spend a handshake or alter the capability cache.
        if (decision == Hp3Decision.PROBE_THEN_H3) {
            H3SupportRegistry.Support discovered = discovery.discover(host, port);
            decision = Hp3ModeDecider.afterDiscovery(discovered);
            if (decision == Hp3Decision.PASS_THROUGH) {
                logging.logToOutput(discovered == H3SupportRegistry.Support.UNSUPPORTED
                        ? "HTTP/3 discovery failed for " + host + ":" + port
                                + "; falling back and remembering the failure"
                        : "HTTP/3 discovery wait was interrupted for " + host + ":" + port
                                + "; this request is passing through Burp without recording a verdict");
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
        }

        // Set once the handshake and SETTINGS exchange have completed, which is the only thing an
        // attempt reveals about the origin. Without it the handler cannot tell "this origin does not
        // speak HTTP/3" from "this request failed", and blamed the origin for both.
        var connectionEstablished = new AtomicBoolean(false);

        try {
            Http3Response response =
                    exchange.send(http3Request, host, targetPort, connectionEstablished);
            trace.success(http3Request, response);
            registry.recordSupported(host, port);
            // The response mirrors the request's version and carries an X-Http3 marker field, so a
            // person can confirm HTTP/3 at a glance without anything inspecting the response being
            // drawn to an unfamiliar version token. That marker is the whole signal, and the
            // annotations are left exactly as they arrived: a successful exchange hands back a
            // response that already says what carried it, so a note would repeat it in a column
            // shared with every other tool. Notes are for the failure paths, which have no response
            // to say it with.
            return RequestToBeSentAction.spoof(
                    HttpResponse.httpResponse(ByteArray.byteArray(ResponseTranslator.toRawBytes(
                            response, requestToBeSent.httpVersion(), ResponseOptions.defaults()))));

        } catch (Exception e) {
            Hp3FailureOutcome outcome =
                    Hp3FailureOutcome.of(connectionEstablished.get(), decision);
            registry.record(host, port, outcome.toRecord());

            // Only drop the pooled connection when there is no connection to keep. A request that
            // failed on a healthy one, a timeout or an origin rejecting deliberately malformed
            // fields, leaves it perfectly usable, and discarding it would cost the next request a
            // whole handshake. A connection that really did break is replaced by acquire, which
            // checks isConnected before handing one out.
            String reason = describe(e);
            trace.exchangeFailure(http3Request, reason);
            if (outcome.fallBackToBurp()) {
                // The request never asked for HTTP/3; we guessed. A failed guess is a discovery,
                // not an error, so Burp sends it normally and the origin is remembered as not
                // speaking HTTP/3. Dropping it here would break ordinary browsing in mode 1.
                logging.logToOutput("HTTP/3 probe failed for " + host + ":" + port
                        + " (" + reason + "); falling back and remembering the failure");
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // The request asked for HTTP/3, or the origin was believed to support it, or it demonstrably
            // speaks it and only this exchange failed. Say so rather than downgrading.
            logging.logToError("HTTP/3 request to " + host + ":" + targetPort + " failed: " + reason);
            return failed(requestToBeSent, Hp3Notices.failureReason(host, targetPort, reason));
        }
    }

    /**
     * Nothing to do. Discovery happens by trying, not by reading advertisements, and an adapted
     * response never reaches here anyway: Burp does not fire this callback for a spoofed one.
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Which input language this request is written in.
     *
     * <p>Keyed off the kettled marker alone, not off why HTTP/3 was chosen: that marker says how to read
     * the message, so a kettled request is decoded whether the HTTP/3 marker forced HTTP/3 or mode 1
     * chose it.
     */
    private Http3Request translate(HttpRequestToBeSent request) throws KettleSyntaxException {
        return RequestTranslator.isKettled(request)
                ? RequestTranslator.toKettledHttp3(request)
                : RequestTranslator.toHttp3(request, configuration.translationOptions());
    }

    /**
     * Ends a failed exchange, and in Repeater alone shows why in the response pane.
     *
     * <p>Burp renders its own transport failures as a line of text rather than as a response, but that
     * is an internal state with no Montoya equivalent: {@link RequestToBeSentAction} offers only
     * continue, drop and spoof. Dropping is truthful and leaves the pane empty, so a Repeater user saw
     * nothing at all and had to go and read the Errors tab to learn that anything had happened.
     *
     * <p>So the reason is spoofed as bytes that are deliberately not a parseable HTTP response. Burp
     * keeps all of them in {@code toByteArray} and Repeater draws them, while parsing them to status 0,
     * no headers and an empty body. Status 0 is already this codebase's own test for "no response", so
     * nothing downstream gains a backend answer it did not have, and no status line is invented.
     *
     * <p>Repeater only, because it is the one tool whose response pane is terminal: a person reads it
     * and nothing else consumes it. Proxy would hand the bytes to a browser, Scanner would grep them,
     * Intruder would size and cluster them, and an extension would count them as a response. Every
     * other tool keeps the drop.
     *
     * <p>The text must stay ASCII, which {@link Hp3Notices#ascii} enforces.
     * {@code ByteArray.byteArray(String)} narrows each char to a byte rather than encoding it, so a
     * non-ASCII character arrives on screen as a stray control byte.
     *
     * <p>Nothing is annotated, and the annotations arrive back untouched. Both callers write the
     * origin and the reason to the log before calling here, so a note would be a second copy of a
     * line that already exists, in a column shared with every other tool. The log is the record of a
     * failure; this decides only what the tool that sent the request is left looking at.
     */
    private RequestToBeSentAction failed(HttpRequestToBeSent request, String reason) {
        if (!request.toolSource().isFromTool(ToolType.REPEATER)) {
            return RequestToBeSentAction.drop();
        }
        try {
            return RequestToBeSentAction.spoof(
                    HttpResponse.httpResponse(ByteArray.byteArray(Hp3Notices.ascii(reason))));
        } catch (RuntimeException e) {
            // Showing the reason is a courtesy; failing to show it must not change the outcome.
            return RequestToBeSentAction.drop();
        }
    }

    private static String describe(Throwable t) {
        String message = t.getMessage();
        return t.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }


}

package hp3.adapter;

import hp3.discovery.H3SupportRegistry.Support;

/**
 * What a failed HTTP/3 attempt is blamed on, and what follows from that.
 *
 * <p>A pure function of two facts, so the whole matrix is testable without Burp or a network — the same
 * reasoning as {@link Hp3ModeDecider}, and the two are the only places routing is decided.
 *
 * <h2>Why this exists</h2>
 *
 * <p>{@link hp3.discovery.H3SupportRegistry} answers exactly one question: does this origin speak
 * HTTP/3. Its answer suppresses future attempts, so writing to it on the strength of anything else is
 * not a wrong log line, it is a downgrade of every later request to that origin for the session.
 *
 * <p>The handler originally recorded {@code UNSUPPORTED} for any exception at all, with the connection
 * attempt and the exchange inside one {@code try}. That conflated two unrelated failures. For an
 * adapter whose product is deliberately malformed traffic the consequence was perverse: a request
 * rejected by the origin — the tool working — turned HTTP/3 off for that host, so the second malformed
 * request went out over HTTP/2 and quietly tested nothing.
 *
 * @param toRecord      what the registry should be told. {@code SUPPORTED} when a handshake completed,
 *                      because that is proof; {@code UNSUPPORTED} only when one never did.
 * @param fallBackToBurp whether to hand the request back for Burp to send normally. Reserved for a
 *                      failed <em>probe</em>: nothing asked for HTTP/3, we guessed, and the guess was
 *                      wrong, so a quiet fallback is right and dropping the request would break
 *                      ordinary browsing in mode 1. Never for a request that asked by name, and
 *                      never once a connection exists — the origin does speak HTTP/3, so sending
 *                      over HTTP/2 instead would misreport which protocol carried it.
 */
public record Hp3FailureOutcome(Support toRecord, boolean fallBackToBurp) {

    /**
     * @param connectionEstablished whether a QUIC handshake and the HTTP/3 SETTINGS exchange completed
     *                              before the failure. This is the whole distinction: it is the only
     *                              evidence about the origin that an attempt produces.
     */
    public static Hp3FailureOutcome of(boolean connectionEstablished, Hp3Decision decision) {
        if (connectionEstablished) {
            // The origin answered QUIC and exchanged SETTINGS. Whatever went wrong afterwards belongs
            // to this request, and recording it against the origin would be a category error.
            return new Hp3FailureOutcome(Support.SUPPORTED, false);
        }
        return new Hp3FailureOutcome(Support.UNSUPPORTED, decision == Hp3Decision.PROBE_THEN_H3);
    }
}

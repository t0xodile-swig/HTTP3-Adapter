package hp3.adapter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * What one origin answered when asked whether it speaks HTTP/3.
 *
 * <p>Three outcomes rather than two, because a handshake and a response are different evidence and
 * collapsing them would lose the distinction that {@link Hp3FailureOutcome} exists to preserve.
 *
 * @param origin   the origin probed
 * @param verdict  what was established
 * @param evidence the exchange, present only for {@link Verdict#ANSWERED}
 * @param detail   why, for a verdict that needs explaining; empty otherwise
 */
public record ProbeResult(HttpService origin, Verdict verdict, HttpRequestResponse evidence,
                          String detail) {

    public enum Verdict {
        /** A complete exchange. The origin speaks HTTP/3 and there is a response to prove it. */
        ANSWERED,
        /**
         * The QUIC handshake and SETTINGS exchange completed and then the request failed.
         *
         * <p>The origin does speak HTTP/3 — that is exactly what a completed handshake proves, and
         * the registry is told so. But there is no response to attach, so nothing goes to Organizer:
         * an item there is evidence, and an item with no response would be a claim.
         */
        HANDSHAKE_ONLY,
        /** No connection was ever established. As far as this session can tell, no HTTP/3 here. */
        NO_HTTP3
    }

    public static ProbeResult answered(HttpService origin, HttpRequestResponse evidence) {
        return new ProbeResult(origin, Verdict.ANSWERED, evidence, "");
    }

    public static ProbeResult handshakeOnly(HttpService origin, String detail) {
        return new ProbeResult(origin, Verdict.HANDSHAKE_ONLY, null, detail);
    }

    public static ProbeResult noHttp3(HttpService origin, String detail) {
        return new ProbeResult(origin, Verdict.NO_HTTP3, null, detail);
    }

    /** Only a complete exchange is worth keeping; the rest are reported and forgotten. */
    public boolean isKeepable() {
        return verdict == Verdict.ANSWERED;
    }

    public String originLabel() {
        return origin.host() + ":" + origin.port();
    }
}

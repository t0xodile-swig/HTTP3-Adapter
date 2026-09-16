package hp3.adapter;

/** What the adapter should do with one outbound request. */
public enum Hp3Decision {

    /** Send it over HTTP/3 and spoof the result back to Burp. */
    SEND_H3,

    /** The origin is unknown; try a QUIC handshake, and fall back to Burp if it fails. */
    PROBE_THEN_H3,

    /** Leave it alone. Burp sends it as it normally would. */
    PASS_THROUGH
}

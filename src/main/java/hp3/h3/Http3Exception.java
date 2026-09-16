package hp3.h3;

import java.io.IOException;

/**
 * An HTTP/3 protocol error, carrying the error code to close the connection or stream with
 * (RFC 9114 section 8.1).
 *
 * <p>Extends {@link IOException} because every path that raises one is already reading or writing a
 * QUIC stream, and callers should not have to catch two unrelated exception families.
 */
public class Http3Exception extends IOException {

    /** RFC 9114 section 8.1 error codes, as used on the wire. */
    public static final long H3_GENERAL_PROTOCOL_ERROR = 0x0101;
    public static final long H3_FRAME_UNEXPECTED = 0x0105;
    public static final long H3_FRAME_ERROR = 0x0106;
    public static final long H3_EXCESSIVE_LOAD = 0x0107;
    public static final long H3_MISSING_SETTINGS = 0x010a;
    public static final long H3_REQUEST_CANCELLED = 0x010c;
    public static final long H3_MESSAGE_ERROR = 0x010e;
    public static final long QPACK_DECOMPRESSION_FAILED = 0x0200;

    private final long errorCode;

    public Http3Exception(long errorCode, String message) {
        super(message + " [0x" + Long.toHexString(errorCode) + "]");
        this.errorCode = errorCode;
    }

    public long errorCode() {
        return errorCode;
    }
}

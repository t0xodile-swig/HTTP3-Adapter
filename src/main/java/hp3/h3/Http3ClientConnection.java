package hp3.h3;

import hp3.h3.qpack.FieldLine;
import hp3.h3.qpack.QpackDecoder;
import hp3.h3.qpack.QpackEncoder;
import hp3.quic.QuicStream;
import hp3.quic.QuicTransport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * An HTTP/3 client connection over a {@link QuicTransport}, RFC 9114.
 *
 * <p>On open it does what every HTTP/3 client must: a unidirectional control stream carrying
 * SETTINGS, plus QPACK encoder and decoder streams. The QPACK streams are opened and then left
 * silent, because phase 1 advertises a zero-capacity dynamic table and so has no instructions to
 * send — but RFC 9114 section 6.2.1 requires them to exist.
 *
 * <p>Knows nothing about Montoya. It speaks {@link Http3Request} and {@link Http3Response}, which
 * makes it testable against an in-memory transport and reusable outside Burp.
 */
public final class Http3ClientConnection implements AutoCloseable {

    private final QuicTransport transport;
    private QuicStream controlStream;
    private QuicStream qpackEncoderStream;
    private QuicStream qpackDecoderStream;

    private Http3ClientConnection(QuicTransport transport) {
        this.transport = transport;
    }

    /** Opens the control and QPACK streams and sends our SETTINGS. */
    public static Http3ClientConnection open(QuicTransport transport) throws IOException {
        return open(transport, Http3Settings.clientDefaults());
    }

    public static Http3ClientConnection open(QuicTransport transport, Http3Settings settings)
            throws IOException {
        var connection = new Http3ClientConnection(transport);

        // The peer's own control and QPACK streams arrive unsolicited. Phase 1 has nothing to do
        // with them — the dynamic table is disabled, so there are no QPACK instructions to apply —
        // but the handler must be registered before they show up.
        transport.onPeerStream(stream -> {
        });

        connection.controlStream = transport.openUnidirectionalStream();
        OutputStream control = connection.controlStream.output();
        VarInt.write(control, Http3StreamType.CONTROL);
        Http3FrameWriter.write(control, Http3FrameType.SETTINGS, settings.encodePayload());
        control.flush();

        connection.qpackEncoderStream = openSilentStream(transport, Http3StreamType.QPACK_ENCODER);
        connection.qpackDecoderStream = openSilentStream(transport, Http3StreamType.QPACK_DECODER);

        return connection;
    }

    /**
     * Opens a unidirectional stream, declares its type and writes nothing more. Required by
     * RFC 9114 section 6.2.1 even though a zero-capacity dynamic table gives us nothing to say.
     */
    private static QuicStream openSilentStream(QuicTransport transport, long streamType)
            throws IOException {
        QuicStream stream = transport.openUnidirectionalStream();
        VarInt.write(stream.output(), streamType);
        stream.output().flush();
        return stream;
    }

    /** Sends {@code request} on a fresh bidirectional stream and reads the response. */
    public Http3Response send(Http3Request request) throws IOException {
        QuicStream stream = openRequestStream();
        writeRequest(stream, request);
        return readResponse(stream);
    }

    /** Writes {@code request} to {@code stream} and finishes the sending half. */
    public void writeRequest(QuicStream stream, Http3Request request) throws IOException {
        OutputStream out = stream.output();
        Http3FrameWriter.write(out, Http3FrameType.HEADERS,
                QpackEncoder.encodeFieldSection(request.fields()));
        if (request.hasBody()) {
            Http3FrameWriter.write(out, Http3FrameType.DATA, request.body());
        }
        out.flush();
        // Closing the sending half is HTTP/3's end of message; there is no END_STREAM flag.
        stream.finishSending();
    }

    /**
     * Opens a request stream without writing anything to it, for callers that intend to compose the
     * bytes themselves. A control seam: phase 2 uses this with
     * {@link Http3FrameWriter#writeWithDeclaredLength} and friends.
     */
    public QuicStream openRequestStream() throws IOException {
        return transport.openBidirectionalStream();
    }

    /** Reads a response from a stream the caller has already written and finished. */
    public Http3Response readResponse(QuicStream stream) throws IOException {
        var reader = new Http3FrameReader(stream.input());
        List<FieldLine> fields = null;
        List<FieldLine> trailers = List.of();
        var body = new ByteArrayOutputStream();

        Http3Frame frame;
        while ((frame = reader.readFrameIgnoringUnknown()) != null) {
            if (Http3FrameType.isReservedHttp2Type(frame.type())) {
                throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                        "peer sent " + Http3FrameType.name(frame.type())
                                + ", which HTTP/3 reserves and forbids");
            }
            if (frame.type() == Http3FrameType.HEADERS) {
                if (fields == null) {
                    fields = QpackDecoder.decodeFieldSection(frame.payload());
                } else {
                    // A second field section, after the body, is the trailer section.
                    trailers = QpackDecoder.decodeFieldSection(frame.payload());
                }
            } else if (frame.type() == Http3FrameType.DATA) {
                if (fields == null) {
                    throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                            "DATA arrived before any HEADERS frame");
                }
                body.writeBytes(frame.payload());
            }
            // Any other known frame type is legal here but of no interest to a client.
        }

        if (fields == null) {
            throw new Http3Exception(Http3Exception.H3_FRAME_UNEXPECTED,
                    "response stream ended without a HEADERS frame");
        }
        return new Http3Response(fields, body.toByteArray(), trailers);
    }

    public QuicStream controlStream() {
        return controlStream;
    }

    public boolean isConnected() {
        return transport.isConnected();
    }

    @Override
    public void close() {
        transport.close();
    }
}

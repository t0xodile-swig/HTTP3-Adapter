package hp3.quic;

import tech.kwik.core.QuicClientConnection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.function.Consumer;

/**
 * {@link QuicTransport} over Kwik.
 *
 * <p>The only class in the project that imports Kwik. Everything above it works against the
 * interface, so replacing or forking the QUIC stack — which phase 2 needs in order to reach
 * transport-level behaviour such as malformed packets and flow-control abuse — changes this file
 * and nothing else.
 */
public final class KwikQuicTransport implements QuicTransport {

    private final QuicClientConnection connection;

    private KwikQuicTransport(QuicClientConnection connection) {
        this.connection = connection;
    }

    /** Connects and completes the QUIC handshake with ALPN {@code h3}. */
    public static KwikQuicTransport connect(String host, int port, QuicConfig config)
            throws IOException {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .uri(URI.create("https://" + host + ":" + port))
                .applicationProtocol("h3")
                .connectTimeout(config.handshakeTimeout())
                .maxIdleTimeout(config.idleTimeout())
                // The server opens its own control and QPACK streams unprompted; refusing them
                // would fail the connection.
                .maxOpenPeerInitiatedUnidirectionalStreams(16);

        if (!config.verifyCertificates()) {
            builder.noServerCertificateCheck();
        }

        QuicClientConnection connection = builder.build();
        connection.connect();
        return new KwikQuicTransport(connection);
    }

    @Override
    public QuicStream openBidirectionalStream() throws IOException {
        return new KwikStream(connection.createStream(true));
    }

    @Override
    public QuicStream openUnidirectionalStream() throws IOException {
        return new KwikStream(connection.createStream(false));
    }

    @Override
    public void onPeerStream(Consumer<QuicStream> handler) {
        connection.setPeerInitiatedStreamCallback(stream -> handler.accept(new KwikStream(stream)));
    }

    @Override
    public boolean isConnected() {
        return connection.isConnected();
    }

    @Override
    public void close(long errorCode, String reason) {
        connection.close(errorCode, reason);
    }

    @Override
    public void close() {
        connection.close();
    }

    /** Adapts a Kwik stream. Named to avoid colliding with {@link QuicStream}. */
    private record KwikStream(tech.kwik.core.QuicStream delegate) implements QuicStream {

        @Override
        public long id() {
            return delegate.getStreamId();
        }

        @Override
        public InputStream input() {
            return delegate.getInputStream();
        }

        @Override
        public OutputStream output() {
            return delegate.getOutputStream();
        }

        @Override
        public boolean isUnidirectional() {
            return delegate.isUnidirectional();
        }

        @Override
        public void finishSending() throws IOException {
            // Closing Kwik's output stream sends the QUIC FIN, which is how HTTP/3 ends a message.
            delegate.getOutputStream().close();
        }

        @Override
        public void resetStream(long errorCode) {
            delegate.resetStream(errorCode);
        }

        @Override
        public void stopSending(long errorCode) {
            delegate.abortReading(errorCode);
        }
    }
}

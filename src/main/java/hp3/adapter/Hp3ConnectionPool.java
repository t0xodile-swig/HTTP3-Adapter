package hp3.adapter;

import hp3.h3.Http3ClientConnection;
import hp3.quic.KwikQuicTransport;
import hp3.quic.QuicConfig;
import hp3.quic.QuicTransport;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keeps one HTTP/3 connection per origin alive and hands it out again.
 *
 * <p>Worth the bookkeeping because a handshake is expensive: measured at six to seven seconds on a
 * network where a middlebox drops the first QUIC Initial packets. Paying that per request would
 * make the adapter unusable.
 *
 * <p>Requests on the same connection each get their own QUIC stream, so reuse does not serialise
 * them.
 *
 * <p>Every caller takes a {@link Lease} rather than a connection, because reuse decides who owns
 * the thing handed out. A pooled lease is borrowed: releasing it leaves the connection in the map
 * for the next request. An unpooled one is owned by its caller, and releasing it closes the
 * connection — nothing else ever will, so a caller that forgets leaks a UDP socket and a receive
 * loop for the life of the extension.
 */
public final class Hp3ConnectionPool implements AutoCloseable {

    /**
     * How a transport is obtained. Kwik in production; the seam exists because the pool's own
     * behaviour — reuse, replacement of a dead connection, who closes what — is not observable
     * against a real origin. Package-private, exactly like the coordinator's own connector.
     */
    @FunctionalInterface
    interface Connector {
        QuicTransport connect(String host, int port, QuicConfig config) throws IOException;
    }

    /**
     * A connection borrowed from the pool, or owned outright when reuse is off. Releasing it is what
     * distinguishes the two, and nothing else about the connection differs.
     */
    public interface Lease extends AutoCloseable {

        Http3ClientConnection connection();

        @Override
        void close();
    }

    private final Map<String, Http3ClientConnection> connections = new ConcurrentHashMap<>();
    private final Connector connector;

    public Hp3ConnectionPool() {
        this(KwikQuicTransport::connect);
    }

    Hp3ConnectionPool(Connector connector) {
        this.connector = connector;
    }

    /**
     * Returns a connection to {@code host:port}, from the pool when {@code reuse} is set and fresh
     * otherwise.
     *
     * <p>An unpooled lease never touches the map, so a connection already pooled for the origin is
     * neither borrowed nor evicted. That matters because the setting can be toggled while Burp is
     * sending.
     */
    public Lease lease(String host, int port, QuicConfig config, boolean reuse) throws IOException {
        if (!reuse) {
            return new OwnedLease(open(host, port, config));
        }
        return new PooledLease(acquire(host, port, config));
    }

    /**
     * Returns a live pooled connection to {@code host:port}, opening one if needed.
     *
     * <p>{@code computeIfAbsent} does the handshake while holding the map's bin lock, which is
     * deliberate: it means concurrent first requests to the same origin wait for one handshake
     * rather than starting several.
     */
    private Http3ClientConnection acquire(String host, int port, QuicConfig config)
            throws IOException {
        String key = host + ":" + port;

        Http3ClientConnection existing = connections.get(key);
        if (existing != null && !existing.isConnected()) {
            connections.remove(key, existing);
            closeQuietly(existing);
        }

        try {
            return connections.computeIfAbsent(key, unused -> {
                try {
                    return open(host, port, config);
                } catch (IOException e) {
                    throw new UncheckedConnectException(e);
                }
            });
        } catch (UncheckedConnectException e) {
            throw e.cause;
        }
    }

    private Http3ClientConnection open(String host, int port, QuicConfig config) throws IOException {
        return Http3ClientConnection.open(connector.connect(host, port, config));
    }

    /** Drops the connection to this origin, so the next request reconnects. */
    public void invalidate(String host, int port) {
        Http3ClientConnection connection = connections.remove(host + ":" + port);
        closeQuietly(connection);
    }

    public int size() {
        return connections.size();
    }

    @Override
    public void close() {
        connections.values().forEach(Hp3ConnectionPool::closeQuietly);
        connections.clear();
    }

    private static void closeQuietly(Http3ClientConnection connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.close();
        } catch (RuntimeException ignored) {
            // Already broken; nothing useful to do about it here.
        }
    }

    /** A connection the map owns; releasing it only means the caller has finished with it. */
    private record PooledLease(Http3ClientConnection connection) implements Lease {
        @Override
        public void close() {
            // Deliberately nothing. The pool closes it, on invalidate or on extension unload.
        }
    }

    /** A connection nobody else holds, closed when the caller is done with it. */
    private record OwnedLease(Http3ClientConnection connection) implements Lease {
        @Override
        public void close() {
            closeQuietly(connection);
        }
    }

    /** Carries a checked IOException out of the computeIfAbsent lambda. */
    private static final class UncheckedConnectException extends RuntimeException {
        private final IOException cause;

        UncheckedConnectException(IOException cause) {
            super(cause);
            this.cause = cause;
        }
    }
}

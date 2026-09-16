package hp3.adapter;

import hp3.h3.Http3ClientConnection;
import hp3.h3.Http3Exception;
import hp3.h3.Http3Request;
import hp3.h3.Http3Response;
import hp3.quic.QuicConfig;
import hp3.quic.QuicStream;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One HTTP/3 exchange against one origin.
 *
 * <p>Extracted from {@code Hp3HttpHandler} when the context menu needed the same thing. What is left
 * in the handler is Burp-action policy — whether an attempt is dropped or handed back through
 * {@code continueWith}, and how a real response is spoofed — which a probe has no use for. What moved
 * here is everything that touches the network.
 *
 * <p>Connection acquisition and request-stream admission happen on the caller: the former has its
 * own handshake deadline, while the latter is peer backpressure rather than response latency. Once
 * a stream is available, writing the request and reading its response run on a separate thread under
 * the configured request timeout. A timed-out stream is cancelled in both directions so its worker
 * and peer stream credit are released.
 *
 * <p>The connection is held as a {@link Hp3ConnectionPool.Lease} for the whole exchange, so that with
 * connection reuse turned off it is closed on every path out — success, timeout, interruption and
 * protocol failure alike. The response is fully read by then, so releasing it costs nothing.
 */
public final class Hp3Exchange {

    @FunctionalInterface
    interface ConnectionProvider {
        Hp3ConnectionPool.Lease lease(String host, int port, QuicConfig config) throws IOException;
    }

    private final Hp3Configuration configuration;
    private final ConnectionProvider connections;
    private final ExecutorService executor =
            Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());

    public Hp3Exchange(Hp3Configuration configuration, Hp3ConnectionPool pool) {
        this(configuration, (host, port, config) ->
                pool.lease(host, port, config, configuration.reuseConnections()));
    }

    Hp3Exchange(Hp3Configuration configuration, ConnectionProvider connections) {
        this.configuration = configuration;
        this.connections = connections;
    }

    /**
     * @param connectionEstablished set once the QUIC handshake and the HTTP/3 SETTINGS exchange have
     *                              completed, which is the only thing an attempt reveals about the
     *                              origin. Set after connection acquisition and before stream
     *                              admission, so a later failure is still attributed to the request.
     *                              {@link Hp3FailureOutcome} is what reads it, and collapsing the
     *                              phases back into one {@code try} would make a request that failed on
     *                              a healthy connection look like an origin without HTTP/3 — which
     *                              suppresses every later attempt to that host.
     */
    public Http3Response send(Http3Request request, String host, int port,
                              AtomicBoolean connectionEstablished) throws Exception {
        try (Hp3ConnectionPool.Lease lease =
                     connections.lease(host, port, configuration.quicConfig())) {
            Http3ClientConnection connection = lease.connection();
            connectionEstablished.set(true);
            QuicStream stream = connection.openRequestStream();

            Future<Http3Response> future;
            try {
                future = executor.submit(() -> {
                    connection.writeRequest(stream, request);
                    return connection.readResponse(stream);
                });
            } catch (RuntimeException e) {
                cancel(stream);
                throw e;
            }

            long timeoutMillis = configuration.requestTimeout().toMillis();
            try {
                return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                cancel(stream);
                future.cancel(true);
                throw new TimeoutException("no response within " + timeoutMillis + "ms");
            } catch (InterruptedException e) {
                cancel(stream);
                future.cancel(true);
                throw e;
            } catch (ExecutionException e) {
                cancel(stream);
                Throwable cause = e.getCause();
                throw cause instanceof Exception exception ? exception : new RuntimeException(cause);
            }
        }
    }

    private static void cancel(QuicStream stream) {
        stream.resetStream(Http3Exception.H3_REQUEST_CANCELLED);
        stream.stopSending(Http3Exception.H3_REQUEST_CANCELLED);
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}

package hp3.adapter;

import hp3.quic.QuicConfig;
import hp3.translate.TranslationOptions;

import java.time.Duration;

/**
 * Everything the handler needs to know about how it should behave.
 *
 * <p>An interface rather than {@link Hp3Settings} directly, so the handler does not depend on
 * Burp's settings dialog and a test can drive it with plain values.
 */
public interface Hp3Configuration {

    Hp3Mode mode();

    default TranslationOptions translationOptions() {
        return TranslationOptions.defaults();
    }

    default boolean traceAdaptedExchanges() {
        return false;
    }

    /**
     * Whether a connection is kept for the next request to the same origin.
     *
     * <p>Off means a fresh QUIC connection per request, which is the point — some behaviour only
     * shows up on a connection nothing else has used — but every request then pays a handshake,
     * measured at six to seven seconds on a network that drops the first Initial packets.
     */
    default boolean reuseConnections() {
        return true;
    }

    Duration requestTimeout();

    QuicConfig quicConfig();


    /**
     * The same configuration with connection reuse turned off, for a caller that wants a fresh
     * connection per request without restating everything else.
     */
    static Hp3Configuration withoutConnectionReuse(Hp3Configuration base) {
        return new Hp3Configuration() {
            @Override
            public Hp3Mode mode() {
                return base.mode();
            }

            @Override
            public TranslationOptions translationOptions() {
                return base.translationOptions();
            }

            @Override
            public boolean traceAdaptedExchanges() {
                return base.traceAdaptedExchanges();
            }

            @Override
            public boolean reuseConnections() {
                return false;
            }

            @Override
            public Duration requestTimeout() {
                return base.requestTimeout();
            }

            @Override
            public QuicConfig quicConfig() {
                return base.quicConfig();
            }
        };
    }

    /** A fixed configuration, for tests and for callers that do not want the settings panel. */
    static Hp3Configuration fixed(Hp3Mode mode, QuicConfig quicConfig,
                                  Duration requestTimeout) {
        return fixed(mode, quicConfig, requestTimeout, false);
    }

    /** A fixed configuration with an explicit tracing choice. */
    static Hp3Configuration fixed(Hp3Mode mode, QuicConfig quicConfig,
                                  Duration requestTimeout, boolean traceAdaptedExchanges) {
        return new Hp3Configuration() {
            @Override
            public Hp3Mode mode() {
                return mode;
            }


            @Override
            public boolean traceAdaptedExchanges() {
                return traceAdaptedExchanges;
            }

            @Override
            public Duration requestTimeout() {
                return requestTimeout;
            }

            @Override
            public QuicConfig quicConfig() {
                return quicConfig;
            }
        };
    }
}

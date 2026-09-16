package hp3.discovery;

import burp.api.montoya.core.Registration;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Remembers which origins actually speak HTTP/3, so mode 1 pays for that discovery once.
 *
 * <p>Every entry comes from a real exchange. Nothing is taken on trust, and in particular
 * {@code Alt-Svc} is ignored: it is a claim rather than a fact. vimeo.com advertises
 * {@code h3=":443"; ma=86400} and does not answer QUIC at all from every network, and believing it
 * meant sending real traffic to an origin that could not receive it — surfacing as errors rather
 * than as the quiet fallback a failed guess deserves.
 *
 * <p>Entries live for as long as the extension is loaded. There is no expiry: an origin either
 * completed an HTTP/3 exchange during this session or it did not, and re-testing costs a whole
 * handshake timeout because an origin with no QUIC listener answers with silence rather than a
 * refusal. Reloading the extension starts afresh.
 *
 * <p>Thread-safe: Burp calls HTTP handlers from many threads at once.
 */
public final class H3SupportRegistry {

    /** Canonical origin identity used by the settings view. */
    public record Origin(String host, int port) implements Comparable<Origin> {
        @Override
        public int compareTo(Origin other) {
            int hostOrder = host.compareTo(other.host);
            return hostOrder != 0 ? hostOrder : Integer.compare(port, other.port);
        }

        @Override
        public String toString() {
            return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
        }
    }

    public enum Support {
        /** Not tried yet during this session. */
        UNKNOWN,
        /** Completed an HTTP/3 exchange. */
        SUPPORTED,
        /** Tried and could not. */
        UNSUPPORTED
    }

    private final Map<Origin, Support> entries = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Runnable> listeners = new CopyOnWriteArrayList<>();

    public void recordSupported(String host, int port) {
        Support previous = entries.put(key(host, port), Support.SUPPORTED);
        if (previous == Support.UNSUPPORTED) {
            notifyChanged();
        }
    }

    public void recordUnsupported(String host, int port) {
        var changed = new AtomicBoolean(false);
        entries.compute(key(host, port), (unused, current) -> {
            if (current == Support.SUPPORTED || current == Support.UNSUPPORTED) {
                return current;
            }
            changed.set(true);
            return Support.UNSUPPORTED;
        });
        if (changed.get()) {
            notifyChanged();
        }
    }

    /**
     * Records an answer decided elsewhere, for a caller holding one as a value rather than as a branch.
     * {@link Support#UNKNOWN} forgets the origin instead of storing "unknown" as a verdict.
     */
    public void record(String host, int port, Support support) {
        if (support == Support.UNKNOWN) {
            forget(host, port);
            return;
        }
        if (support == Support.UNSUPPORTED) {
            recordUnsupported(host, port);
        } else {
            recordSupported(host, port);
        }
    }

    public Support lookup(String host, int port) {
        return entries.getOrDefault(key(host, port), Support.UNKNOWN);
    }

    /** Immutable, canonical, sorted view of the current negative cache. */
    public List<Origin> unsupportedOrigins() {
        return entries.entrySet().stream()
                .filter(entry -> entry.getValue() == Support.UNSUPPORTED)
                .map(Map.Entry::getKey)
                .sorted()
                .toList();
    }

    /** Drops what is known about this origin, so the next request tests it again. */
    public void forget(String host, int port) {
        if (entries.remove(key(host, port)) == Support.UNSUPPORTED) {
            notifyChanged();
        }
    }

    public void clear() {
        boolean hadUnsupported = entries.containsValue(Support.UNSUPPORTED);
        entries.clear();
        if (hadUnsupported) {
            notifyChanged();
        }
    }

    /** Drops negative discoveries without forgetting origins already proved to support HTTP/3. */
    public void clearUnsupported() {
        boolean changed = entries.entrySet().removeIf(
                entry -> entry.getValue() == Support.UNSUPPORTED);
        if (changed) {
            notifyChanged();
        }
    }

    /** Registers a contained observer of changes to the visible unsupported-origin set. */
    public Registration onChange(Runnable listener) {
        listeners.add(listener);
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return listeners.contains(listener);
            }

            @Override
            public void deregister() {
                listeners.remove(listener);
            }
        };
    }

    public int size() {
        return entries.size();
    }

    private void notifyChanged() {
        for (Runnable listener : listeners) {
            try {
                listener.run();
            } catch (RuntimeException | LinkageError ignored) {
                // Observation must never affect routing or another observer.
            }
        }
    }

    private static Origin key(String host, int port) {
        return new Origin(host.toLowerCase(Locale.ROOT), port);
    }
}

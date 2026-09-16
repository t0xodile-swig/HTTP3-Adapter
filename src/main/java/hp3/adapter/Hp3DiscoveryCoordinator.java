package hp3.adapter;

import hp3.discovery.H3SupportRegistry;
import hp3.discovery.H3SupportRegistry.Support;

import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/** Coordinates one initial HTTP/3 connection attempt per origin. */
public final class Hp3DiscoveryCoordinator {

    @FunctionalInterface
    interface Connector {
        void connect(String host, int port) throws Exception;
    }

    private final H3SupportRegistry registry;
    private final Connector connector;
    private final ConcurrentHashMap<Origin, CompletableFuture<Support>> inFlight =
            new ConcurrentHashMap<>();

    Hp3DiscoveryCoordinator(H3SupportRegistry registry, Connector connector) {
        this.registry = registry;
        this.connector = connector;
    }

    /**
     * Returns the shared discovery result. Followers wait for the elected leader; connection timeout
     * policy belongs to that leader's connector, so followers cannot independently fall through.
     */
    public Support discover(String host, int port) {
        Support known = registry.lookup(host, port);
        if (known != Support.UNKNOWN) {
            return known;
        }

        Origin origin = new Origin(host.toLowerCase(Locale.ROOT), port);
        var candidate = new CompletableFuture<Support>();
        CompletableFuture<Support> shared = inFlight.putIfAbsent(origin, candidate);
        if (shared == null) {
            return lead(origin, candidate);
        }
        return await(shared);
    }

    private Support lead(Origin origin, CompletableFuture<Support> result) {
        try {
            // Close the gap between the first lookup and winning the in-flight slot.
            Support known = registry.lookup(origin.host(), origin.port());
            if (known != Support.UNKNOWN) {
                result.complete(known);
                return known;
            }

            connector.connect(origin.host(), origin.port());
            registry.recordSupported(origin.host(), origin.port());
            result.complete(Support.SUPPORTED);
            return Support.SUPPORTED;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result.complete(Support.UNKNOWN);
            return Support.UNKNOWN;
        } catch (Exception e) {
            registry.recordUnsupported(origin.host(), origin.port());
            Support recorded = registry.lookup(origin.host(), origin.port());
            result.complete(recorded);
            return recorded;
        } finally {
            inFlight.remove(origin, result);
        }
    }

    private Support await(CompletableFuture<Support> result) {
        try {
            return result.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Support.UNKNOWN;
        } catch (ExecutionException e) {
            // Leaders always complete with a Support value, but remain conservative if that invariant
            // is broken: a local coordination failure is not evidence against the origin.
            return Support.UNKNOWN;
        }
    }

    private record Origin(String host, int port) {
    }
}

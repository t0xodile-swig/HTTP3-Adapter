package hp3.adapter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * What a selection of requests means when the question is about origins.
 *
 * <p>A person selects requests; HTTP/3 support is a property of a host and port. Fifty history items
 * against three hosts is three questions, and answering it fifty times would spend fifty exchanges to
 * learn three facts. So the selection collapses, in the order it was made — stable order keeps the
 * summary readable and the tests deterministic.
 *
 * <p>Pure, and deliberately so. Deciding what to probe is the part worth testing without a network,
 * and it is the part that would otherwise hide inside a menu action where nothing could reach it.
 *
 * @param origins what to probe: one entry per secure {@code host:port}
 * @param skipped plaintext origins, reported rather than dropped. QUIC is always TLS, so an origin
 *                Burp recorded as non-secure has no HTTP/3 to find on that port. Probing one is not
 *                merely useless but slow: an origin with no QUIC listener answers with silence rather
 *                than a refusal, so the attempt costs the whole handshake timeout. A selection that
 *                produces no results should be able to say why.
 */
public record ProbeTargets(List<HttpService> origins, List<HttpService> skipped) {

    public static ProbeTargets from(List<HttpRequestResponse> selection) {
        Map<String, HttpService> origins = new LinkedHashMap<>();
        Map<String, HttpService> skipped = new LinkedHashMap<>();

        for (HttpRequestResponse item : selection) {
            HttpService service = serviceOf(item);
            if (service == null) {
                continue;
            }
            (service.secure() ? origins : skipped).putIfAbsent(key(service), service);
        }

        return new ProbeTargets(List.copyOf(origins.values()), List.copyOf(skipped.values()));
    }

    public boolean isEmpty() {
        return origins.isEmpty() && skipped.isEmpty();
    }

    /** Everything the selection named, probed or not, for a summary that accounts for all of it. */
    public List<HttpService> all() {
        List<HttpService> all = new ArrayList<>(origins);
        all.addAll(skipped);
        return List.copyOf(all);
    }

    /**
     * The origin an item belongs to, or null if it cannot be established.
     *
     * <p>A selection can contain an item with no request, and asking one for its service may throw
     * rather than return null. An unusable item is skipped silently: it names no origin, so there is
     * nothing to report about it.
     */
    private static HttpService serviceOf(HttpRequestResponse item) {
        try {
            return item == null || item.request() == null ? null : item.request().httpService();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Same keying as {@code H3SupportRegistry}: host case-insensitive, port significant. */
    private static String key(HttpService service) {
        return service.host().toLowerCase(Locale.ROOT) + ":" + service.port();
    }
}

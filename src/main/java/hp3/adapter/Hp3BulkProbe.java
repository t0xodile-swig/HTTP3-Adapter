package hp3.adapter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.logging.Logging;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Future;
import java.util.function.Function;

/**
 * Probes many origins and reports what they said.
 *
 * <p>Concurrent, because a handshake is measured in seconds against some networks and a sweep of
 * thirty origins run one at a time would be a coffee break. Bounded, because thirty simultaneous QUIC
 * handshakes is a different kind of rude, and because an origin that does not answer costs the whole
 * timeout, so the slow ones are exactly the ones that would pile up.
 *
 * <p>Progress goes to the extension's Output tab rather than a progress dialog. A sweep is not
 * interactive: there is nothing to decide while it runs, and a modal window would be a second user
 * interface to maintain for no information a log line does not already carry.
 */
public final class Hp3BulkProbe {

    /** Enough to keep a sweep moving, few enough not to open a burst of handshakes at one origin set. */
    private static final int MAX_CONCURRENT_ORIGINS = 8;

    private final Function<HttpService, ProbeResult> probe;
    private final Logging logging;
    private final ExecutorService workers;

    public Hp3BulkProbe(Hp3OriginProbe probe, Logging logging, ExecutorService workers) {
        this(probe::probe, logging, workers);
    }

    Hp3BulkProbe(Function<HttpService, ProbeResult> probe, Logging logging,
                 ExecutorService workers) {
        this.probe = probe;
        this.logging = logging;
        this.workers = workers;
    }

    public ProbeSummary run(ProbeTargets targets, ProbeSink sink) {
        if (targets.origins().isEmpty()) {
            ProbeSummary summary = new ProbeSummary(List.of(), targets.skipped().size());
            logging.logToOutput(summary.describe());
            return summary;
        }

        logging.logToOutput("HTTP/3 support check: probing " + targets.origins().size()
                + " origin(s) with GET /. A handshake can take several seconds each.");

        List<ProbeResult> results = new ArrayList<>();
        CompletionService<ProbeResult> completed = new ExecutorCompletionService<>(workers);
        List<Future<ProbeResult>> futures = new ArrayList<>();
        for (HttpService origin : targets.origins()) {
            futures.add(completed.submit(() -> probe.apply(origin)));
        }
        int total = futures.size();
        try {
            for (int remaining = total; remaining > 0; remaining--) {
                Future<ProbeResult> future = completed.take();
                ProbeResult result = await(future);
                if (result == null) {
                    continue;
                }
                results.add(result);
                int processed = total - remaining + 1;
                report(result, processed, total);
                // Handed over as each one lands rather than in a batch at the end, so a long sweep
                // fills Organizer as it goes and a cancelled Burp still leaves what it learned.
                if (result.isKeepable()) {
                    sink.keep(result);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logging.logToError("HTTP/3 support check interrupted; the remaining origins were cancelled");
        } finally {
            futures.forEach(future -> future.cancel(true));
        }

        ProbeSummary summary = new ProbeSummary(List.copyOf(results), targets.skipped().size());
        logging.logToOutput(summary.describe());
        return summary;
    }

    private void report(ProbeResult result, int processed, int total) {
        logging.logToOutput(progressDescription(result, processed, total));
    }

    static String progressDescription(ProbeResult result, int processed, int total) {
        String prefix = "[" + processed + "/" + total + "] " + result.originLabel();
        return switch (result.verdict()) {
            case ANSWERED -> prefix + " supports HTTP/3";
            case HANDSHAKE_ONLY -> prefix
                    + " speaks HTTP/3 but did not answer this request (" + result.detail()
                    + "), so there is no exchange to keep";
            case NO_HTTP3 -> prefix + ": no HTTP/3 (" + result.detail() + ")";
        };
    }

    /**
     * A probe that dies is reported and skipped rather than sinking the sweep. One origin's failure
     * must not cost the answers for the other twenty-nine.
     */
    private ProbeResult await(Future<ProbeResult> future) {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logging.logToError("HTTP/3 support check interrupted; the remaining origins were not probed");
            return null;
        } catch (CancellationException e) {
            return null;
        } catch (ExecutionException e) {
            logging.logToError("HTTP/3 support check: a probe failed unexpectedly: " + e.getCause());
            return null;
        }
    }

    public static int maxConcurrentOrigins() {
        return MAX_CONCURRENT_ORIGINS;
    }
}

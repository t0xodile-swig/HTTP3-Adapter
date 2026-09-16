package hp3.adapter;

import java.util.List;

/**
 * What a sweep found, in a form a log line and a test can both read.
 *
 * @param results every origin probed, in completion order so slow origins do not hold back evidence
 * @param skipped plaintext origins that were never probed
 */
public record ProbeSummary(List<ProbeResult> results, int skipped) {

    public List<ProbeResult> supporting() {
        return results.stream().filter(ProbeResult::isKeepable).toList();
    }

    public long countOf(ProbeResult.Verdict verdict) {
        return results.stream().filter(r -> r.verdict() == verdict).count();
    }

    /**
     * One line accounting for everything the selection named.
     *
     * <p>Every category is stated even when it is zero-sized only if it happened, so the common case
     * reads as a sentence rather than as a form with blank fields. Silence about a category is the one
     * thing this must not do: a sweep that found nothing has to say whether it asked.
     */
    public String describe() {
        long answered = countOf(ProbeResult.Verdict.ANSWERED);
        long handshakeOnly = countOf(ProbeResult.Verdict.HANDSHAKE_ONLY);
        var line = new StringBuilder("HTTP/3 support check: ")
                .append(answered + handshakeOnly).append(" of ").append(results.size())
                .append(" origins support HTTP/3");

        if (handshakeOnly > 0) {
            line.append("; ").append(handshakeOnly)
                    .append(" completed a QUIC handshake but did not answer, so they are recorded as "
                            + "supporting HTTP/3 without an exchange to keep");
        }
        if (skipped > 0) {
            line.append("; ").append(skipped)
                    .append(" plaintext origin(s) skipped, since QUIC is always TLS");
        }
        return line.append(".").toString();
    }
}

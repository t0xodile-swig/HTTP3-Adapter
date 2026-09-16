package hp3.adapter;

/**
 * Where a positive probe result goes.
 *
 * <p>An interface because Organizer is a destination rather than a responsibility of probing, and the
 * prober should not know which destination it is. The practical consequence is that the suite can
 * drive the real prober without writing into the Organizer of whoever is running it — but that is a
 * consequence, not the reason: a sink is the right shape whether or not anything tests it.
 */
@FunctionalInterface
public interface ProbeSink {

    void keep(ProbeResult result);
}

package hp3.adapter;

import burp.api.montoya.organizer.Organizer;

/**
 * Sends a supporting origin's exchange to Burp's Organizer.
 *
 * <p>The note travels on the item's annotations rather than as an argument, because
 * {@link Organizer#sendToOrganizer} takes none — {@link Hp3OriginProbe} attaches it when it builds the
 * evidence, so the note and the exchange it describes are assembled in one place and cannot drift.
 */
public final class OrganizerProbeSink implements ProbeSink {

    private final Organizer organizer;

    public OrganizerProbeSink(Organizer organizer) {
        this.organizer = organizer;
    }

    @Override
    public void keep(ProbeResult result) {
        if (!result.isKeepable()) {
            return;
        }
        organizer.sendToOrganizer(result.evidence());
    }
}

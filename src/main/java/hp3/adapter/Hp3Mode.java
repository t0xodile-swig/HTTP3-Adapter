package hp3.adapter;

/** How aggressively the adapter routes traffic onto HTTP/3. */
public enum Hp3Mode {

    /**
     * Mode 2, and the release default. Only requests carrying the {@code X-Http3} header are
     * adapted; everything else is left to Burp untouched.
     */
    EXPLICIT_ONLY("Explicit HTTP/3 only"),

    /**
     * Mode 1. Any origin known or found to speak HTTP/3 is adapted, whether or not the request
     * asked for it.
     */
    ALWAYS_WHERE_POSSIBLE("Always HTTP/3 where possible");

    private final String label;

    Hp3Mode(String label) {
        this.label = label;
    }

    /** The text shown in Burp's settings dialog, and stored in its settings file. */
    public String label() {
        return label;
    }

    public static Hp3Mode fromLabel(String label) {
        for (Hp3Mode mode : values()) {
            if (mode.label.equals(label)) {
                return mode;
            }
        }
        return EXPLICIT_ONLY;   // an unreadable setting must not silently start rewriting traffic
    }
}

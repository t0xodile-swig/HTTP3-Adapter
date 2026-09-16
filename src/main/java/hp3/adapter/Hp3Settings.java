package hp3.adapter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import hp3.quic.QuicConfig;
import hp3.translate.TranslationOptions;

import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * The adapter's settings, shown in Burp's own settings dialog.
 *
 * <p>Built with {@link SettingsPanelBuilder} rather than custom Swing, so the panel is searchable
 * alongside Burp's own settings and persists without any work here.
 *
 * <p>Every default is chosen to be inert or measured. Mode 2 means installing the extension changes
 * no traffic until asked. Probing is off because it costs a whole handshake timeout per unknown
 * origin. The handshake timeout is ten seconds because measured handshakes took about seven on a
 * network where a middlebox drops the first QUIC Initial packets.
 *
 * <p><b>The panel carries labels and no per-setting prose.</b> A description is a full-width label
 * on its own row above the setting, so eleven of them would turn a compact panel into an essay. The
 * reasons are one line each in {@link #TOOLTIPS} instead, where they are read by whoever hovers and
 * by nobody else, and only for the settings whose labels leave something unsaid. Keep new settings
 * description-free and give them a tooltip on the same terms.
 *
 * <p><b>Mode is the one exception</b>, because it is the only setting whose values are not
 * self-describing: a checkbox label says what ticking it does, whereas "Explicit HTTP/3 only" and
 * "Always HTTP/3 where possible" name two policies without saying what separates them. So it carries
 * one clause per mode, each opening with the value it explains.
 *
 * <p><b>Getting it onto two lines takes work</b>, and {@link SettingsDescriptionLines} does it: a
 * description is one {@code JLabel}, a JLabel cannot wrap plain text, and Burp's look and feel sets
 * {@code html.disable} on every label it creates, so HTML markup arrives as literal tags. The
 * property is per component, so the label is found after registration and upgraded in place. The
 * plain text remains the fallback and must therefore read correctly on its own.
 *
 * <p><b>The defaults are duplicated as constants here on purpose.</b> Burp does not materialise a
 * panel's declared defaults until the settings dialog has been opened: on a fresh install
 * {@code getString} returns null and {@code getInteger} returns 0. Relying on the panel alone would
 * give a freshly installed extension a zero-millisecond handshake timeout, which fails every
 * request before the user has visited Settings once. Each accessor therefore treats an unset value
 * as "use the default".
 *
 * <p>The same caveat makes an unset true-defaulted checkbox indistinguishable from an unchecked
 * one. While the whole panel is unmaterialised, the absent mode value is the sentinel: all five
 * rejected-header filters and connection reuse use their enabled defaults. Once materialised, their
 * persisted values are used verbatim, including when a user unchecks all of them.
 */
public final class Hp3Settings implements Hp3Configuration {

    public static final String MODE = "Mode";
    public static final String HANDSHAKE_TIMEOUT_MS = "Handshake timeout (ms)";
    public static final String REQUEST_TIMEOUT_MS = "Request timeout (ms)";
    public static final String REUSE_CONNECTIONS = "Reuse connections";
    public static final String VERIFY_CERTIFICATES = "Verify TLS certificates";
    public static final String TRACE_ADAPTED_EXCHANGES = "Log exchanges to Output";
    public static final String SHOW_UNSUPPORTED_ORIGINS_TAB = "Show unsupported origins tab";
    public static final String STRIP_CONNECTION = "Strip Connection header";
    public static final String STRIP_KEEP_ALIVE = "Strip Keep-Alive header";
    public static final String STRIP_PROXY_CONNECTION = "Strip Proxy-Connection header";
    public static final String STRIP_TRANSFER_ENCODING = "Strip Transfer-Encoding header";
    public static final String STRIP_UPGRADE = "Strip Upgrade header";

    /**
     * What Burp builds the description label with, and therefore the key
     * {@link SettingsDescriptionLines} searches for. It is also the fallback: if the panel's internals
     * ever change and the label cannot be found, this is what stays on screen, so it has to read
     * correctly on one line and fit one. Under ninety characters; an overflowing JLabel is clipped
     * rather than wrapped.
     */
    private static final String MODE_DESCRIPTION =
            "Explicit: only requests marked X-Http3. Always: also any origin that answers HTTP/3.";

    /**
     * The description as it actually appears: one line per mode, each naming the value it explains.
     * Built from the {@link Hp3Mode} labels so it cannot drift from the combo box. Installed after
     * registration by {@link SettingsDescriptionLines}, which has to defeat the look and feel's
     * {@code html.disable} default to do it.
     */
    private static final String MODE_DESCRIPTION_LINES = "<html>"
            + Hp3Mode.EXPLICIT_ONLY.label() + ": adapts a request only if it carries an X-Http3 header."
            + "<br>"
            + Hp3Mode.ALWAYS_WHERE_POSSIBLE.label() + ": also adapts any origin that answers HTTP/3."
            + "</html>";

    /** Said five times, because five fields are forbidden for the same reason. */
    private static final String FORBIDDEN_FIELD = "Forbidden by HTTP/3. Untick to send it anyway.";

    /**
     * One line per setting, hung on the panel by {@link SettingsTooltips} after registration.
     *
     * <p>Each says what the unobvious side of the switch does, not what its label already says.
     * Ticking "Strip Connection header" strips the Connection header; what a tester needs is why it
     * is on and what unticking buys. A setting whose label already answers that has no tooltip:
     * "Reuse connections" and "Verify TLS certificates" mean what they say, mode has a description
     * of its own, and a timeout in milliseconds explains itself.
     */
    private static final Map<String, String> TOOLTIPS = tooltips();

    private static Map<String, String> tooltips() {
        Map<String, String> tooltips = new LinkedHashMap<>();
        tooltips.put(TRACE_ADAPTED_EXCHANGES, "Writes each adapted exchange to the Output panel.");
        tooltips.put(SHOW_UNSUPPORTED_ORIGINS_TAB,
                "Adds a Suite tab for clearing origins cached as not speaking HTTP/3.");
        tooltips.put(STRIP_CONNECTION, FORBIDDEN_FIELD);
        tooltips.put(STRIP_KEEP_ALIVE, FORBIDDEN_FIELD);
        tooltips.put(STRIP_PROXY_CONNECTION, FORBIDDEN_FIELD);
        tooltips.put(STRIP_TRANSFER_ENCODING, FORBIDDEN_FIELD);
        tooltips.put(STRIP_UPGRADE, FORBIDDEN_FIELD);
        return Collections.unmodifiableMap(tooltips);
    }

    public static final int DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;
    public static final int DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

    private final SettingsPanelWithData panel;
    private final Registration registration;
    private volatile boolean modeDescriptionOnSeveralLines;
    private volatile List<String> settingsMissingTooltips = List.copyOf(TOOLTIPS.keySet());
    private volatile boolean unsupportedOriginsTabToggleIsLive;
    private volatile Consumer<Boolean> unsupportedOriginsTabListener = visible -> {
    };

    private Hp3Settings(SettingsPanelWithData panel, Registration registration) {
        this.panel = panel;
        this.registration = registration;
    }

    public static Hp3Settings register(MontoyaApi api) {
        SettingsPanelWithData panel = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("HTTP/3 Adapter")
                .withDescription("Sends traffic over HTTP/3.")
                .withKeywords("http3", "h3", "quic", "alt-svc")
                .withSettings(
                        SettingsPanelSetting.listSetting(
                                MODE_DESCRIPTION,
                                MODE,
                                List.of(Hp3Mode.EXPLICIT_ONLY.label(),
                                        Hp3Mode.ALWAYS_WHERE_POSSIBLE.label()),
                                Hp3Mode.EXPLICIT_ONLY.label()),
                        SettingsPanelSetting.integerSetting(HANDSHAKE_TIMEOUT_MS, DEFAULT_HANDSHAKE_TIMEOUT_MS),
                        SettingsPanelSetting.integerSetting(REQUEST_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS),
                        SettingsPanelSetting.booleanSetting(REUSE_CONNECTIONS, true),
                        SettingsPanelSetting.booleanSetting(TRACE_ADAPTED_EXCHANGES, false),
                        SettingsPanelSetting.booleanSetting(SHOW_UNSUPPORTED_ORIGINS_TAB, false),
                        SettingsPanelSetting.booleanSetting(STRIP_CONNECTION, true),
                        SettingsPanelSetting.booleanSetting(STRIP_KEEP_ALIVE, true),
                        SettingsPanelSetting.booleanSetting(STRIP_PROXY_CONNECTION, true),
                        SettingsPanelSetting.booleanSetting(STRIP_TRANSFER_ENCODING, true),
                        SettingsPanelSetting.booleanSetting(STRIP_UPGRADE, true),
                        SettingsPanelSetting.booleanSetting(VERIFY_CERTIFICATES, false))
                .build();

        Hp3Settings settings = new Hp3Settings(panel, api.userInterface().registerSettingsPanel(panel));
        settings.decorate();
        return settings;
    }

    /**
     * Reaches into the registered panel for the two things Montoya cannot express: the mode
     * description on one line per mode, and a tooltip on each checkbox. On the event dispatch thread
     * and after registration, because {@code uiComponent()} throws inside desktop Burp before its UI
     * context exists.
     *
     * <p>Contained absolutely, and one try for both because both are cosmetic. The whole extension
     * loads through here, so anything thrown while decorating a panel would otherwise take the
     * adapter down with it. The failure mode is the panel Burp already built: a plain single-line
     * description, and no tooltips.
     */
    private void decorate() {
        SwingUtilities.invokeLater(() -> {
            try {
                JComponent ui = panel.uiComponent();
                modeDescriptionOnSeveralLines =
                        SettingsDescriptionLines.apply(ui, MODE_DESCRIPTION, MODE_DESCRIPTION_LINES);
                settingsMissingTooltips = SettingsTooltips.apply(ui, TOOLTIPS);
                // Read through the field on every click rather than capturing it: the listener is
                // wired by Hp3Extension after register() returns, so it is not set yet.
                unsupportedOriginsTabToggleIsLive = SettingsRows.onToggle(
                        ui, SHOW_UNSUPPORTED_ORIGINS_TAB,
                        visible -> unsupportedOriginsTabListener.accept(visible));
            } catch (Throwable t) {
                modeDescriptionOnSeveralLines = false;
                unsupportedOriginsTabToggleIsLive = false;
            }
        });
    }

    /** Whether the mode description is showing one line per mode rather than the plain fallback. */
    public boolean modeDescriptionOnSeveralLines() {
        return modeDescriptionOnSeveralLines;
    }

    /**
     * The settings whose tooltip could not be hung, because no component on the panel showed their
     * name. Empty once every tooltip has landed; every name until the decoration has run.
     */
    public List<String> settingsMissingTooltips() {
        return settingsMissingTooltips;
    }

    @Override
    public Hp3Mode mode() {
        return Hp3Mode.fromLabel(panel.getString(MODE));
    }

    @Override
    public TranslationOptions translationOptions() {
        if (panel.getString(MODE) == null) {
            return TranslationOptions.defaults();
        }
        return new TranslationOptions(
                panel.getBoolean(STRIP_CONNECTION),
                panel.getBoolean(STRIP_KEEP_ALIVE),
                panel.getBoolean(STRIP_PROXY_CONNECTION),
                panel.getBoolean(STRIP_TRANSFER_ENCODING),
                panel.getBoolean(STRIP_UPGRADE));
    }

    /**
     * Whether the unsupported-origins Suite tab should be on screen.
     *
     * <p>The one setting for which Burp's unmaterialised-panel behaviour needs no sentinel. An unset
     * boolean reads false, and false is exactly what a fresh install should get, so the trap that
     * makes {@link #reuseConnections()} consult the mode value is harmless here. Do not add one.
     */
    public boolean showUnsupportedOriginsTab() {
        return panel.getBoolean(SHOW_UNSUPPORTED_ORIGINS_TAB);
    }

    /**
     * Calls back when someone ticks or unticks that setting, so the tab appears and disappears with
     * the checkbox rather than at the next extension reload.
     *
     * <p>Montoya has no change notification on a settings panel, so the callback is driven by the
     * checkbox itself, found in the registered panel by {@link SettingsRows}. Nothing polls. If the
     * panel's internals ever move and the checkbox cannot be found,
     * {@link #unsupportedOriginsTabToggleIsLive()} reports false and the setting is left being read
     * once at load, which is the behaviour without this wiring at all.
     */
    public void onShowUnsupportedOriginsTabChanged(Consumer<Boolean> listener) {
        this.unsupportedOriginsTabListener = listener;
    }

    /** Whether ticking the tab setting takes effect at once, rather than on the next reload. */
    public boolean unsupportedOriginsTabToggleIsLive() {
        return unsupportedOriginsTabToggleIsLive;
    }

    /**
     * Whether the decoration applied at install is still on the panel Burp shows.
     *
     * <p>Everything {@link #decorate()} does is hung once, on whatever {@code uiComponent()} returned
     * then, and that is only sound because Burp hands back the same instance on every call. Measured
     * inside a live Burp rather than assumed. If a release ever rebuilt the tree per call, the
     * tooltips and the description would revert unnoticed and the tab toggle would fire on a
     * component nobody can see, while {@link #unsupportedOriginsTabToggleIsLive()} still reported
     * true: it records that a checkbox was found, not that it is the one on screen.
     *
     * <p>So this re-reads the panel and looks for the decoration where it should be. False is the
     * signal to stop hanging listeners at install and read the setting once at load instead.
     */
    public boolean decorationIsOnTheLivePanel() {
        AtomicBoolean decorated = new AtomicBoolean();
        try {
            SwingUtilities.invokeAndWait(() -> {
                AbstractButton checkbox =
                        SettingsRows.checkboxFor(panel.uiComponent(), SHOW_UNSUPPORTED_ORIGINS_TAB);
                decorated.set(checkbox != null && checkbox.getToolTipText() != null);
            });
        } catch (Exception | LinkageError e) {
            return false;
        }
        return decorated.get();
    }

    @Override
    public boolean traceAdaptedExchanges() {
        return panel.getBoolean(TRACE_ADAPTED_EXCHANGES);
    }

    /**
     * Reuse is on unless the panel says otherwise, and the same unmaterialised-panel sentinel as
     * {@link #translationOptions()} decides which. Reading the raw boolean on a fresh install would
     * give false, silently shipping a handshake per request to someone who never opened Settings.
     */
    @Override
    public boolean reuseConnections() {
        if (panel.getString(MODE) == null) {
            return true;
        }
        return panel.getBoolean(REUSE_CONNECTIONS);
    }

    @Override
    public Duration requestTimeout() {
        return Duration.ofMillis(positiveOrDefault(REQUEST_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS));
    }

    @Override
    public QuicConfig quicConfig() {
        return new QuicConfig(
                Duration.ofMillis(positiveOrDefault(HANDSHAKE_TIMEOUT_MS, DEFAULT_HANDSHAKE_TIMEOUT_MS)),
                Duration.ofSeconds(30),
                panel.getBoolean(VERIFY_CERTIFICATES));
    }

    /**
     * A non-positive value means the panel has never been opened, since Burp returns 0 for an
     * unset integer. None of these settings has a meaningful zero, so treating it as unset costs
     * nothing and avoids a zero timeout on a fresh install.
     */
    private int positiveOrDefault(String name, int fallback) {
        int value = panel.getInteger(name);
        return value > 0 ? value : fallback;
    }

    /** Raw panel value, bypassing the default fallback. Exists so a test can pin Burp's behaviour. */
    public int rawInteger(String name) {
        return panel.getInteger(name);
    }

    /** Raw panel value, bypassing the default fallback. Exists so a test can pin Burp's behaviour. */
    public String rawString(String name) {
        return panel.getString(name);
    }

    /** Raw panel value, bypassing the default fallback. Exists so a test can pin Burp's behaviour. */
    public boolean rawBoolean(String name) {
        return panel.getBoolean(name);
    }

    public void deregister() {
        registration.deregister();
    }
}

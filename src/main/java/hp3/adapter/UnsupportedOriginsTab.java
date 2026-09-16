package hp3.adapter;

import burp.api.montoya.core.Registration;
import hp3.discovery.H3SupportRegistry;

import javax.swing.JComponent;
import java.util.function.Consumer;

/**
 * The unsupported-origins manager, shown as a Suite tab only when asked for.
 *
 * <p>Off by default, because the tab is a repair tool: it exists for the session where an origin
 * was wrongly cached as not speaking HTTP/3, and most people never need it. Hidden costs nothing at
 * all here, since the panel is built when it is shown rather than kept aside, so an extension whose
 * owner never asks for the tab does no Swing work and leaves no listener on the registry.
 *
 * <p><b>It is a view, and hiding it changes no routing.</b> {@link H3SupportRegistry} is untouched
 * either way; what disappears is the ability to edit the negative cache by hand.
 *
 * <p>Registration failure is contained, as it is for the context menu: this is the only part of the
 * extension that needs a user interface, the test suite runs Burp headless, and a cosmetic tab must
 * cost a line in Output rather than the adapter.
 */
public final class UnsupportedOriginsTab implements AutoCloseable {

    static final String TITLE = "HTTP/3 Unsupported Origins";

    /**
     * How the tab reaches Burp, so the lifecycle is testable without one. The implementation applies
     * Burp's theme before registering; a failure in either half is caught here alike.
     */
    public interface Host {
        Registration registerSuiteTab(String title, JComponent component);
    }

    private final H3SupportRegistry registry;
    private final Host host;
    private final Consumer<String> log;

    private UnsupportedOriginsSettingsPanel panel;
    private Registration registration;

    public UnsupportedOriginsTab(H3SupportRegistry registry, Host host, Consumer<String> log) {
        this.registry = registry;
        this.host = host;
        this.log = log;
    }

    /** Shows or hides the tab. Asking for the state it is already in does nothing. */
    public synchronized void setVisible(boolean visible) {
        if (visible == isShown()) {
            return;
        }
        if (visible) {
            show();
        } else {
            hide();
        }
    }

    public synchronized boolean isShown() {
        return registration != null;
    }

    /** The live panel, or null while the tab is hidden. */
    public synchronized UnsupportedOriginsSettingsPanel panel() {
        return panel;
    }

    private void show() {
        UnsupportedOriginsSettingsPanel showing = new UnsupportedOriginsSettingsPanel(registry);
        try {
            registration = host.registerSuiteTab(TITLE, showing.uiComponent());
            panel = showing;
        } catch (RuntimeException | LinkageError e) {
            // The panel is closed rather than kept: a listener on the registry with nothing on
            // screen to update is a leak, and the next attempt builds a fresh one anyway.
            showing.close();
            registration = null;
            log.accept("HTTP/3 unsupported-origins tab unavailable: it could not be registered ("
                    + e + "). Everything else works.");
        }
    }

    private void hide() {
        registration.deregister();
        registration = null;
        panel.close();
        panel = null;
    }

    @Override
    public void close() {
        setVisible(false);
    }
}

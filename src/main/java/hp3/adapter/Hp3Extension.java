package hp3.adapter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import hp3.discovery.H3SupportRegistry;
import hp3.quic.QuicConfig;
import hp3.translate.TranslationOptions;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Assembles the adapter and registers it with Burp.
 *
 * <p>Extracted from {@code Extension} so the production wiring is something a test can reach and
 * inspect, rather than existing only inside {@code initialize}.
 */
public final class Hp3Extension implements AutoCloseable {

    /**
     * The instance installed by {@code Extension}, so integration tests drive the real object graph
     * rather than assembling a parallel one. A second adapter would fight the first for every
     * request, and a test that builds its own proves nothing about the wiring that ships.
     */
    private static volatile Hp3Extension current;

    private final Hp3Settings settings;
    private final H3SupportRegistry registry;
    private final Hp3ConnectionPool pool;
    private final Hp3Exchange exchange;
    private final Hp3DiscoveryCoordinator discovery;
    private final Hp3HttpHandler handler;
    private final Hp3BulkProbe bulkProbe;
    private final ExecutorService probeWorkers;
    private final ExecutorService probeCoordinator;
    private final Registration handlerRegistration;
    private final Registration contextMenuRegistration;
    private final UnsupportedOriginsTab unsupportedOriginsTab;

    /**
     * What the handler currently reads. Normally the settings panel; tests substitute a fixed
     * configuration, because the panel persists to user settings and therefore reflects whatever the
     * person running the tests last chose in the Burp UI. A suite that asserted on defaults while
     * reading live preferences would fail for anyone who had changed a setting.
     */
    private final AtomicReference<Hp3Configuration> active = new AtomicReference<>();

    private Hp3Extension(MontoyaApi api, Hp3Settings settings) {
        this.settings = settings;
        this.registry = new H3SupportRegistry();
        this.pool = new Hp3ConnectionPool();
        this.active.set(settings);
        // Off by default, so the tab is built only for someone who asked for it, and it follows the
        // checkbox from then on rather than waiting for a reload.
        this.unsupportedOriginsTab = new UnsupportedOriginsTab(
                registry, suiteTabHost(api), api.logging()::logToOutput);
        this.unsupportedOriginsTab.setVisible(settings.showUnsupportedOriginsTab());
        settings.onShowUnsupportedOriginsTabChanged(unsupportedOriginsTab::setVisible);
        // The handler reads through the reference rather than holding the settings directly, so the
        // configuration can be swapped without re-registering. Registration is not immediately
        // effective in Burp, so re-registering mid-run is unreliable.
        this.exchange = new Hp3Exchange(delegatingConfiguration(), pool);
        Hp3Configuration configuration = delegatingConfiguration();
        // Discovery's evidence is the handshake itself, so the lease is taken and released at once.
        // With reuse on, releasing it leaves the connection pooled for the request that prompted the
        // discovery; with reuse off it closes, and that request pays a second handshake.
        this.discovery = new Hp3DiscoveryCoordinator(registry, (host, port) ->
                pool.lease(host, port, configuration.quicConfig(), configuration.reuseConnections())
                        .close());
        this.handler = new Hp3HttpHandler(configuration, registry, exchange, discovery,
                api.logging(), new ExchangeTracer(api.logging()));
        this.handlerRegistration = api.http().registerHttpHandler(handler);
        this.probeWorkers = Executors.newFixedThreadPool(Hp3BulkProbe.maxConcurrentOrigins(),
                Thread.ofVirtual().name("hp3-origin-probe-", 0).factory());
        this.probeCoordinator = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("hp3-bulk-probe-", 0).factory());
        this.bulkProbe = new Hp3BulkProbe(new Hp3OriginProbe(exchange, registry), api.logging(),
                probeWorkers);
        this.contextMenuRegistration = registerContextMenu(api);
    }

    /**
     * The context menu is optional in a way the handler is not: it is the only part of the extension
     * that needs a user interface, and the suite runs Burp headless. A failure to register must cost a
     * log line rather than the adapter, so this is caught rather than allowed to abort {@code install}.
     */
    private Registration registerContextMenu(MontoyaApi api) {
        try {
            return api.userInterface().registerContextMenuItemsProvider(new Hp3ContextMenu(
                    bulkProbe, new OrganizerProbeSink(api.organizer()), api.logging(),
                    probeCoordinator));
        } catch (RuntimeException | LinkageError e) {
            api.logging().logToOutput("HTTP/3 support check unavailable: the context menu could not "
                    + "be registered (" + e + "). Everything else works.");
            return null;
        }
    }

    /**
     * Applies Burp's theme, then registers the tab. A theme failure costs the tab its styling and
     * nothing more, so it is contained here rather than left to abort the registration behind it.
     */
    private static UnsupportedOriginsTab.Host suiteTabHost(MontoyaApi api) {
        return (title, component) -> {
            try {
                api.userInterface().applyThemeToComponent(component);
            } catch (RuntimeException | LinkageError e) {
                api.logging().logToOutput("Could not apply Burp's theme to the unsupported-origins "
                        + "tab (" + e + "); using component defaults.");
            }
            return api.userInterface().registerSuiteTab(title, component);
        };
    }

    public static Hp3Extension install(MontoyaApi api) {
        return install(api, Hp3Settings.register(api));
    }

    public static Hp3Extension install(MontoyaApi api, Hp3Settings settings) {
        Hp3Extension extension = new Hp3Extension(api, settings);
        current = extension;
        return extension;
    }

    /** The installed adapter, or null if none has been installed in this Burp session. */
    public static Hp3Extension current() {
        return current;
    }

    public H3SupportRegistry registry() {
        return registry;
    }

    public Hp3ConnectionPool pool() {
        return pool;
    }

    public Hp3Settings settings() {
        return settings;
    }

    /**
     * The optional negative-cache Suite tab. Exposed so the suite drives the shipped object graph
     * rather than assembling a parallel one, exactly as it does for the handler and the bulk probe.
     */
    public UnsupportedOriginsTab unsupportedOriginsTab() {
        return unsupportedOriginsTab;
    }

    /**
     * The sweep the context menu drives. Exposed so the suite exercises the shipped object graph
     * rather than assembling a parallel one, exactly as it does for the handler.
     */
    public Hp3BulkProbe bulkProbe() {
        return bulkProbe;
    }

    /**
     * Replaces what the handler reads. For tests only: they must not depend on whatever settings a
     * person happens to have persisted in the Burp UI.
     */
    public void overrideConfiguration(Hp3Configuration override) {
        active.set(override);
    }

    /** Restores the settings panel as the active configuration. */
    public void restoreConfiguration() {
        active.set(settings);
    }

    @Override
    public void close() {
        if (current == this) {
            current = null;
        }
        handlerRegistration.deregister();
        if (contextMenuRegistration != null) {
            contextMenuRegistration.deregister();
        }
        unsupportedOriginsTab.close();
        probeCoordinator.shutdownNow();
        probeWorkers.shutdownNow();
        exchange.shutdown();
        pool.close();
        settings.deregister();
    }

    /** A view onto whichever configuration is currently active. */
    private Hp3Configuration delegatingConfiguration() {
        return new Hp3Configuration() {
            @Override
            public Hp3Mode mode() {
                return active.get().mode();
            }

            @Override
            public TranslationOptions translationOptions() {
                return active.get().translationOptions();
            }

            @Override
            public boolean traceAdaptedExchanges() {
                return active.get().traceAdaptedExchanges();
            }

            @Override
            public boolean reuseConnections() {
                return active.get().reuseConnections();
            }

            @Override
            public Duration requestTimeout() {
                return active.get().requestTimeout();
            }

            @Override
            public QuicConfig quicConfig() {
                return active.get().quicConfig();
            }
        };
    }
}

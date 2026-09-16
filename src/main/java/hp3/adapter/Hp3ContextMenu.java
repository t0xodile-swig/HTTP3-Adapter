package hp3.adapter;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

/**
 * The right-click entry point: check a selection of requests for HTTP/3 support.
 *
 * <p>The extension's second way in, and the first that is a person asking a question rather than Burp
 * routing traffic. {@code Hp3HttpHandler} can only learn about an origin as a side effect of a request
 * someone was already sending; this asks directly, of a list.
 *
 * <p>Everything this class does on the event dispatch thread is arithmetic: collapsing the selection to
 * origins so the label can count them. The sweep itself is handed to a virtual thread, because a
 * handshake takes seconds and the thread that draws Burp must not be waiting on QUIC.
 */
public final class Hp3ContextMenu implements ContextMenuItemsProvider {

    private final Hp3BulkProbe bulkProbe;
    private final ProbeSink sink;
    private final Logging logging;
    private final ExecutorService coordinator;

    public Hp3ContextMenu(Hp3BulkProbe bulkProbe, ProbeSink sink, Logging logging,
                          ExecutorService coordinator) {
        this.bulkProbe = bulkProbe;
        this.sink = sink;
        this.logging = logging;
        this.coordinator = coordinator;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selection = event.selectedRequestResponses();
        if (selection.isEmpty()) {
            return List.of();
        }

        ProbeTargets targets = ProbeTargets.from(selection);
        if (targets.isEmpty()) {
            return List.of();
        }

        JMenuItem item = new JMenuItem(label(targets));
        // Nothing to probe, but the item still appears and says why: a selection of plaintext origins
        // silently growing no menu entry looks like a broken extension.
        item.addActionListener(unused -> start(targets));
        return List.of(item);
    }

    static String label(ProbeTargets targets) {
        int count = targets.origins().size();
        if (count == 0) {
            return "Check HTTP/3 support (nothing to check: QUIC needs TLS)";
        }
        return "Check HTTP/3 support (" + count + (count == 1 ? " origin)" : " origins)");
    }

    private void start(ProbeTargets targets) {
        try {
            coordinator.submit(() -> {
                try {
                    bulkProbe.run(targets, sink);
                } catch (RuntimeException e) {
                    logging.logToError("HTTP/3 support check failed: " + e);
                }
            });
        } catch (RejectedExecutionException ignored) {
            // The extension is unloading; the menu has already been deregistered.
        }
    }
}

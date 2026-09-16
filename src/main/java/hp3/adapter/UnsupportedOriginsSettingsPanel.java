package hp3.adapter;

import burp.api.montoya.core.Registration;
import hp3.discovery.H3SupportRegistry;
import hp3.discovery.H3SupportRegistry.Origin;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

/** Live management view of origins cached as not supporting HTTP/3. */
public final class UnsupportedOriginsSettingsPanel implements AutoCloseable {

    private final H3SupportRegistry registry;
    private final JPanel root = new JPanel(new BorderLayout(0, 8));
    private final DefaultListModel<Origin> model = new DefaultListModel<>();
    private final JList<Origin> originList = new JList<>(model);
    private final JLabel countLabel = new JLabel();
    private final JButton removeSelected = new JButton("Remove selected");
    private final JButton clearAll = new JButton("Clear all");
    private final Registration listenerRegistration;

    public UnsupportedOriginsSettingsPanel(H3SupportRegistry registry) {
        this.registry = registry;

        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        var heading = new JPanel(new BorderLayout());
        heading.add(new JLabel("Unsupported HTTP/3 origins"), BorderLayout.WEST);
        heading.add(countLabel, BorderLayout.EAST);
        root.add(heading, BorderLayout.NORTH);

        originList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        originList.addListSelectionListener(event -> updateButtonState());
        root.add(new JScrollPane(originList), BorderLayout.CENTER);

        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(removeSelected);
        actions.add(clearAll);
        root.add(actions, BorderLayout.SOUTH);

        removeSelected.addActionListener(event -> removeSelected());
        clearAll.addActionListener(event -> registry.clearUnsupported());

        listenerRegistration = registry.onChange(this::scheduleRefresh);
        refresh();
    }

    public JComponent uiComponent() {
        return root;
    }

    private void removeSelected() {
        for (Origin origin : originList.getSelectedValuesList()) {
            registry.forget(origin.host(), origin.port());
        }
    }

    private void scheduleRefresh() {
        if (SwingUtilities.isEventDispatchThread()) {
            refresh();
        } else {
            SwingUtilities.invokeLater(this::refresh);
        }
    }

    private void refresh() {
        model.clear();
        registry.unsupportedOrigins().forEach(model::addElement);
        countLabel.setText(model.size() + " unsupported origins");
        updateButtonState();
    }

    private void updateButtonState() {
        removeSelected.setEnabled(!originList.isSelectionEmpty());
        clearAll.setEnabled(!model.isEmpty());
    }

    @Override
    public void close() {
        listenerRegistration.deregister();
    }

    JList<Origin> originList() {
        return originList;
    }

    JLabel countLabel() {
        return countLabel;
    }

    JButton removeSelectedButton() {
        return removeSelected;
    }

    JButton clearAllButton() {
        return clearAll;
    }
}

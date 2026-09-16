package hp3.adapter;

import javax.swing.AbstractButton;
import javax.swing.JLabel;
import java.awt.Component;
import java.awt.Container;
import java.util.function.Consumer;

/**
 * The shape of a row in Burp's settings panel, in one place.
 *
 * <p><b>Measured, not assumed</b>, by dumping the registered panel's component tree inside a live
 * Burp: a row is a label whose text is the setting's name followed by a colon and a space, then the
 * control, which for a checkbox carries no text at all. Rows are flat siblings with a spacer
 * between them.
 *
 * <p>Two callers need that fact, so it lives here rather than in either of them:
 * {@link SettingsTooltips} hangs a tooltip on every row it recognises, and {@link Hp3Settings}
 * needs the one checkbox it must listen to. A second copy of the traversal would be free to drift
 * from the measurement.
 *
 * <p>Pure Swing on purpose, so both callers stay testable without Burp.
 */
final class SettingsRows {

    private SettingsRows() {
    }

    /**
     * The checkbox belonging to a named setting, or null if the panel shows no such row.
     *
     * <p>Null is a real answer rather than an error: Burp is free to lay its panel out differently,
     * and every caller here treats a control it cannot find as a feature it does without.
     */
    static AbstractButton checkboxFor(Container root, String settingName) {
        Component[] children = root.getComponents();
        for (int i = 0; i < children.length; i++) {
            Component child = children[i];
            if (settingName.equals(settingNameShownBy(child))
                    && i + 1 < children.length
                    && children[i + 1] instanceof AbstractButton control) {
                return control;
            }
            if (child instanceof Container nested) {
                AbstractButton found = checkboxFor(nested, settingName);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /**
     * Reports a named setting's checkbox to a listener whenever someone ticks or unticks it.
     *
     * <p>Montoya has no change notification on a settings panel at all, so the only way to hear
     * about a setting is the control itself. Swing delivers the click; nothing polls.
     *
     * <p>Must be called on the event dispatch thread, and only after the panel has been registered.
     *
     * @return whether the panel showed a checkbox to listen to; false means the caller is on its own
     */
    static boolean onToggle(Container root, String settingName, Consumer<Boolean> listener) {
        AbstractButton checkbox = checkboxFor(root, settingName);
        if (checkbox == null) {
            return false;
        }
        checkbox.addItemListener(event -> listener.accept(checkbox.isSelected()));
        return true;
    }

    /**
     * The setting a component names, or null if it names none. Burp writes {@code "Mode: "}, so the
     * trailing colon and the space around it are not part of the name.
     */
    static String settingNameShownBy(Component component) {
        String text = textOf(component);
        if (text == null) {
            return null;
        }
        String name = text.strip();
        return name.endsWith(":") ? name.substring(0, name.length() - 1).strip() : name;
    }

    private static String textOf(Component component) {
        if (component instanceof AbstractButton button) {
            return button.getText();
        }
        if (component instanceof JLabel label) {
            return label.getText();
        }
        return null;
    }
}

package hp3.adapter;

import javax.swing.AbstractButton;
import javax.swing.JComponent;
import java.awt.Component;
import java.awt.Container;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Hangs a tooltip on each setting in Burp's settings panel.
 *
 * <p>Montoya has no tooltip on {@code SettingsPanelSetting}: a setting is a name, optionally a
 * description, and that is all. A description is a full-width label on its own row above the
 * setting, so one per checkbox would turn a compact panel into an essay. A tooltip says the same
 * thing only to whoever asks for it.
 *
 * <p>So the components are reached directly, the same way {@link SettingsDescriptionLines} reaches
 * the description label. The row's measured shape belongs to {@link SettingsRows}, which names the
 * setting a component shows; both the label and the control beside it get the tooltip, because a
 * person hovers whichever of the two their pointer is over. A control carrying the name itself is
 * matched too, so a Burp release that labels its checkboxes differently keeps working.
 *
 * <p>Pure Swing on purpose — no Montoya, so it is testable without Burp. The text is plain, never
 * HTML: Burp's look and feel sets {@code html.disable} on the labels it creates, and a tooltip is
 * not worth the fight {@link SettingsDescriptionLines} has to pick. Failure is silent and partial —
 * the names not found are returned rather than thrown, because a missing tooltip is cosmetic and
 * must never be able to break registration.
 */
final class SettingsTooltips {

    private SettingsTooltips() {
    }

    /**
     * Attaches each tooltip to the component showing its setting's name, and to the control beside
     * it.
     *
     * <p>Must be called on the event dispatch thread, and only after the panel has been registered:
     * reaching {@code uiComponent()} earlier throws inside desktop Burp.
     *
     * @param tooltipByName setting name to tooltip, in the order they should be reported
     * @return the names not found on screen, in that order; empty when every tooltip landed
     */
    static List<String> apply(Container root, Map<String, String> tooltipByName) {
        Set<String> found = new HashSet<>();
        attach(root, tooltipByName, found);
        return tooltipByName.keySet().stream().filter(name -> !found.contains(name)).toList();
    }

    private static void attach(Container container, Map<String, String> tooltipByName, Set<String> found) {
        Component[] children = container.getComponents();
        for (int i = 0; i < children.length; i++) {
            Component child = children[i];
            String name = SettingsRows.settingNameShownBy(child);
            String tooltip = name == null ? null : tooltipByName.get(name);
            if (tooltip != null) {
                ((JComponent) child).setToolTipText(tooltip);
                found.add(name);
                // The row's own checkbox, which carries no text to be found by.
                if (i + 1 < children.length && children[i + 1] instanceof AbstractButton control) {
                    control.setToolTipText(tooltip);
                }
            }
            if (child instanceof Container nested) {
                attach(nested, tooltipByName, found);
            }
        }
    }

}

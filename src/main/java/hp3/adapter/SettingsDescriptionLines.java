package hp3.adapter;

import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import java.awt.Component;
import java.awt.Container;

/**
 * Breaks a settings-panel description across several lines.
 *
 * <p>Burp's settings panel gives a description one {@link JLabel} on its own full-width row, and a
 * JLabel cannot wrap plain text: a {@code \n} renders as nothing. HTML is the only mechanism Swing
 * offers, and <b>Burp's look and feel switches it off</b> — every label it creates carries the
 * client property {@code html.disable} set to {@code TRUE}, which is what
 * {@link BasicHTML#updateRenderer} consults before building a view. So a description written as
 * {@code <html>one<br>two</html>} reaches the panel as literal tags on a single line. That is a
 * reasonable default for a tool that displays strings an attacker chose; it is simply wrong for a
 * string of ours.
 *
 * <p>The property is per component, so this clears it on that one label and installs the renderer by
 * hand. Measured against the real registered panel: the mode description went from 465x17 to 379x34,
 * one line to two.
 *
 * <p>Pure Swing on purpose — no Montoya, so the behaviour is testable without Burp. Failure is
 * always silent and always leaves the plain single-line description in place, because a description
 * is cosmetic and must never be able to break registration. The caller passes the plain text as the
 * search key precisely so that a Burp release which changes the panel's internals fails this way:
 * the label is not found, nothing is touched, and the panel keeps the line Burp already built.
 */
final class SettingsDescriptionLines {

    private SettingsDescriptionLines() {
    }

    /**
     * Replaces the label showing {@code plainText} with {@code htmlText}, rendered as HTML.
     *
     * <p>Must be called on the event dispatch thread, and only after the panel has been registered:
     * reaching {@code uiComponent()} earlier throws inside desktop Burp, which has not initialised
     * its UI context then.
     *
     * @return whether a label was found and upgraded
     */
    static boolean apply(Container root, String plainText, String htmlText) {
        JLabel label = findLabelShowing(root, plainText);
        if (label == null) {
            return false;
        }
        label.putClientProperty("html.disable", null);
        label.setText(htmlText);
        BasicHTML.updateRenderer(label, htmlText);
        return label.getClientProperty("html") != null;
    }

    private static JLabel findLabelShowing(Container container, String text) {
        for (Component child : container.getComponents()) {
            if (child instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (child instanceof Container nested) {
                JLabel found = findLabelShowing(nested, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}

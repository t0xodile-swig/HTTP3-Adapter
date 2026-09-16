package hp3.translate;

import java.util.Locale;

/** The RFC 9114 connection-specific fields filtered from an ordinary HTTP/3 request. */
public record TranslationOptions(
        boolean stripConnectionField,
        boolean stripKeepAliveField,
        boolean stripProxyConnectionField,
        boolean stripTransferEncodingField,
        boolean stripUpgradeField) {

    public static TranslationOptions defaults() {
        return new TranslationOptions(true, true, true, true, true);
    }

    public static TranslationOptions none() {
        return new TranslationOptions(false, false, false, false, false);
    }

    public boolean shouldStrip(String fieldName) {
        return switch (fieldName.toLowerCase(Locale.ROOT)) {
            case "connection" -> stripConnectionField;
            case "keep-alive" -> stripKeepAliveField;
            case "proxy-connection" -> stripProxyConnectionField;
            case "transfer-encoding" -> stripTransferEncodingField;
            case "upgrade" -> stripUpgradeField;
            default -> false;
        };
    }

    public TranslationOptions withStripConnectionField(boolean strip) {
        return new TranslationOptions(strip, stripKeepAliveField, stripProxyConnectionField,
                stripTransferEncodingField, stripUpgradeField);
    }

    public TranslationOptions withStripKeepAliveField(boolean strip) {
        return new TranslationOptions(stripConnectionField, strip, stripProxyConnectionField,
                stripTransferEncodingField, stripUpgradeField);
    }

    public TranslationOptions withStripProxyConnectionField(boolean strip) {
        return new TranslationOptions(stripConnectionField, stripKeepAliveField, strip,
                stripTransferEncodingField, stripUpgradeField);
    }

    public TranslationOptions withStripTransferEncodingField(boolean strip) {
        return new TranslationOptions(stripConnectionField, stripKeepAliveField,
                stripProxyConnectionField, strip, stripUpgradeField);
    }

    public TranslationOptions withStripUpgradeField(boolean strip) {
        return new TranslationOptions(stripConnectionField, stripKeepAliveField,
                stripProxyConnectionField, stripTransferEncodingField, strip);
    }
}

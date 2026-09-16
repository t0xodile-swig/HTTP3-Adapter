package hp3.h3.qpack;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Encodes QPACK field sections, RFC 9204 section 4.5.
 *
 * <p><b>Faithful, not correct.</b> This encoder reproduces exactly the field list it is given:
 * order preserved, no lowercasing, no deduplication, no reordering, no validation, and no
 * synthesised fields — notably no {@code Content-Length}. That is the point. Matching Burp's HTTP/2
 * capabilities means being able to send uppercase names, colons inside names, newlines in values and
 * duplicate or absent pseudo-headers, and RFC 9204 section 4.5.6 permits all of it because a literal
 * name is just a string literal and QPACK performs no case validation.
 *
 * <p><b>Huffman coding is off by default.</b> It is a free choice per string, so leaving it off
 * costs interoperability nothing — the phase 1 spike fetched a real page from quic.tech with every
 * field uncoded — and buys deterministic, eyeball-readable output plus byte-for-byte agreement with
 * the worked example in RFC 9204 Appendix B.1. Callers that want it ask for it.
 *
 * <p>Phase 1 never touches the dynamic table. The connection advertises
 * {@code QPACK_MAX_TABLE_CAPACITY = 0}, so every field section carries a
 * {@code Required Insert Count} and {@code Base} of zero.
 *
 * <p>The representation primitives are public so a phase 2 caller can hand-build a field section
 * that this encoder's own policy would never produce.
 */
public final class QpackEncoder {

    private QpackEncoder() {
    }

    /**
     * Encodes {@code fields} in order, choosing the smallest representation that does not alter the
     * bytes on the wire: an indexed field line only when name and value both match a static entry
     * exactly, a name reference only when the name matches exactly, and a literal name otherwise.
     */
    public static byte[] encodeFieldSection(List<FieldLine> fields) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(encodeFieldSectionPrefix(0, 0));

        for (FieldLine field : fields) {
            int exact = QpackStaticTable.findExact(field.name(), field.value());
            if (exact >= 0) {
                out.writeBytes(encodeIndexed(exact));
                continue;
            }
            int byName = QpackStaticTable.findName(field.name());
            if (byName >= 0) {
                out.writeBytes(encodeLiteralWithNameReference(byName, field.value(), false, false));
                continue;
            }
            out.writeBytes(
                    encodeLiteralWithLiteralName(field.name(), field.value(), false, false, false));
        }
        return out.toByteArray();
    }

    /** Field section prefix, RFC 9204 section 4.5.1. */
    public static byte[] encodeFieldSectionPrefix(long requiredInsertCount, long base) {
        var out = new ByteArrayOutputStream();
        out.writeBytes(PrefixInteger.encode(requiredInsertCount, 8, 0));
        // Sign bit clear means Base >= Required Insert Count; with both zero the delta is zero.
        out.writeBytes(PrefixInteger.encode(base, 7, 0));
        return out.toByteArray();
    }

    /** Indexed field line against the static table, RFC 9204 section 4.5.2: {@code 1 T index(6+)}. */
    public static byte[] encodeIndexed(int staticIndex) {
        return PrefixInteger.encode(staticIndex, 6, 0x80 | 0x40);
    }

    /**
     * Literal field line with a static name reference, RFC 9204 section 4.5.4:
     * {@code 01 N T index(4+)} followed by the value as a string literal.
     */
    public static byte[] encodeLiteralWithNameReference(int staticIndex, String value,
                                                        boolean huffmanValue, boolean neverIndex) {
        var out = new ByteArrayOutputStream();
        int flags = 0x40 | (neverIndex ? 0x20 : 0) | 0x10;   // 01, N, T=1 for static
        out.writeBytes(PrefixInteger.encode(staticIndex, 4, flags));
        writeStringLiteral(out, value, huffmanValue, 7, 0);
        return out.toByteArray();
    }

    /**
     * Literal field line with a literal name, RFC 9204 section 4.5.6:
     * {@code 001 N H nameLength(3+)}, the name, then the value as a string literal.
     */
    public static byte[] encodeLiteralWithLiteralName(String name, String value,
                                                      boolean huffmanName, boolean huffmanValue,
                                                      boolean neverIndex) {
        var out = new ByteArrayOutputStream();
        writeStringLiteral(out, name, huffmanName, 3, 0x20 | (neverIndex ? 0x10 : 0));
        writeStringLiteral(out, value, huffmanValue, 7, 0);
        return out.toByteArray();
    }

    /**
     * A string literal: a one-bit Huffman flag sitting immediately above the length prefix, a
     * prefix-integer length, then the octets.
     */
    static void writeStringLiteral(ByteArrayOutputStream out, String value, boolean huffman,
                                   int prefixBits, int flags) {
        byte[] octets = huffman
                ? HuffmanCodec.encode(value)
                : value.getBytes(StandardCharsets.ISO_8859_1);
        int huffmanFlag = huffman ? (1 << prefixBits) : 0;
        out.writeBytes(PrefixInteger.encode(octets.length, prefixBits, flags | huffmanFlag));
        out.writeBytes(octets);
    }
}

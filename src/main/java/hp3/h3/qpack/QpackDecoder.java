package hp3.h3.qpack;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes QPACK field sections, RFC 9204 section 4.5.
 *
 * <p>Static table only. The connection advertises {@code QPACK_MAX_TABLE_CAPACITY = 0} and
 * {@code QPACK_BLOCKED_STREAMS = 0}, which forbids the peer from using the dynamic table
 * (RFC 9204 section 3.2.3). A peer that ignores that must fail loudly here rather than produce
 * quietly wrong headers, so dynamic and post-base references are rejected explicitly.
 *
 * <p>Order and duplicates are preserved exactly as received; nothing is normalised on the way in
 * either.
 */
public final class QpackDecoder {

    private QpackDecoder() {
    }

    /** Decodes a complete field section, preserving order and duplicates exactly as received. */
    public static List<FieldLine> decodeFieldSection(byte[] encoded) throws QpackException {
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        List<FieldLine> fields = new ArrayList<>();
        try {
            readFieldSectionPrefix(buffer);
            while (buffer.hasRemaining()) {
                fields.add(readFieldLine(buffer));
            }
        } catch (BufferUnderflowException e) {
            throw new QpackException("field section ended part-way through a representation");
        }
        return fields;
    }

    private static void readFieldSectionPrefix(ByteBuffer buffer) throws QpackException {
        long requiredInsertCount = PrefixInteger.read(buffer, 8);
        if (requiredInsertCount != 0) {
            throw new QpackException("Required Insert Count is " + requiredInsertCount
                    + " but the dynamic table is disabled (QPACK_MAX_TABLE_CAPACITY=0)");
        }
        boolean negativeDelta = (peek(buffer) & 0x80) != 0;
        long deltaBase = PrefixInteger.read(buffer, 7);
        if (negativeDelta || deltaBase != 0) {
            throw new QpackException("Base must be 0 when Required Insert Count is 0, got delta "
                    + (negativeDelta ? "-" : "+") + deltaBase);
        }
    }

    private static FieldLine readFieldLine(ByteBuffer buffer) throws QpackException {
        int first = peek(buffer);

        if ((first & 0x80) != 0) {                       // 1 T index(6+)
            boolean fromStaticTable = (first & 0x40) != 0;
            long index = PrefixInteger.read(buffer, 6);
            requireStatic(fromStaticTable, "indexed field line");
            return staticEntry(index);
        }
        if ((first & 0xc0) == 0x40) {                    // 01 N T index(4+)
            boolean fromStaticTable = (first & 0x10) != 0;
            long index = PrefixInteger.read(buffer, 4);
            requireStatic(fromStaticTable, "literal field line with name reference");
            requireStaticIndex(index);
            return new FieldLine(QpackStaticTable.name((int) index), readStringLiteral(buffer, 7));
        }
        if ((first & 0xe0) == 0x20) {                    // 001 N H nameLength(3+)
            String name = readStringLiteral(buffer, 3);
            return new FieldLine(name, readStringLiteral(buffer, 7));
        }
        if ((first & 0xf0) == 0x10) {                    // 0001 index(4+)
            throw new QpackException(
                    "indexed field line with post-base index requires the dynamic table");
        }
        // 0000 N index(3+)
        throw new QpackException(
                "literal field line with post-base name reference requires the dynamic table");
    }

    private static String readStringLiteral(ByteBuffer buffer, int prefixBits) throws QpackException {
        boolean huffman = (peek(buffer) & (1 << prefixBits)) != 0;
        long length = PrefixInteger.read(buffer, prefixBits);
        if (length > buffer.remaining()) {
            throw new QpackException("string literal declares " + length
                    + " octets but only " + buffer.remaining() + " remain");
        }
        byte[] octets = new byte[(int) length];
        buffer.get(octets);
        return huffman
                ? HuffmanCodec.decode(octets)
                : new String(octets, StandardCharsets.ISO_8859_1);
    }

    private static FieldLine staticEntry(long index) throws QpackException {
        requireStaticIndex(index);
        return new FieldLine(QpackStaticTable.name((int) index), QpackStaticTable.value((int) index));
    }

    private static void requireStatic(boolean fromStaticTable, String what) throws QpackException {
        if (!fromStaticTable) {
            throw new QpackException(what + " references the dynamic table, which is disabled");
        }
    }

    private static void requireStaticIndex(long index) throws QpackException {
        if (index < 0 || index >= QpackStaticTable.size()) {
            throw new QpackException("static table index " + index + " is out of range 0.."
                    + (QpackStaticTable.size() - 1));
        }
    }

    /** Reads the byte at the current position without consuming it. */
    private static int peek(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            throw new BufferUnderflowException();
        }
        return buffer.get(buffer.position()) & 0xff;
    }
}

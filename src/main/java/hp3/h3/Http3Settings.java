package hp3.h3;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A SETTINGS frame payload: a sequence of identifier/value varint pairs, RFC 9114 section 7.2.4.
 *
 * <p>Insertion order is preserved so a caller can control the order settings appear on the wire.
 */
public final class Http3Settings {

    public static final long QPACK_MAX_TABLE_CAPACITY = 0x01;
    public static final long MAX_FIELD_SECTION_SIZE = 0x06;
    public static final long QPACK_BLOCKED_STREAMS = 0x07;
    public static final long ENABLE_CONNECT_PROTOCOL = 0x08;

    private final Map<Long, Long> settings = new LinkedHashMap<>();

    /**
     * What this client advertises: no QPACK dynamic table and no blocked streams.
     *
     * <p>Both already default to zero (RFC 9204 section 5), so sending them changes nothing on the
     * wire semantically. They are sent explicitly because they are the load-bearing assumption
     * behind the static-table-only decoder, and a reader of a packet capture should not have to
     * know the defaults to see it.
     */
    public static Http3Settings clientDefaults() {
        return new Http3Settings()
                .with(QPACK_MAX_TABLE_CAPACITY, 0)
                .with(QPACK_BLOCKED_STREAMS, 0);
    }

    public static Http3Settings empty() {
        return new Http3Settings();
    }

    public Http3Settings with(long identifier, long value) {
        settings.put(identifier, value);
        return this;
    }

    public long get(long identifier, long defaultValue) {
        return settings.getOrDefault(identifier, defaultValue);
    }

    public boolean contains(long identifier) {
        return settings.containsKey(identifier);
    }

    public int size() {
        return settings.size();
    }

    public byte[] encodePayload() {
        var out = new ByteArrayOutputStream();
        try {
            for (Map.Entry<Long, Long> entry : settings.entrySet()) {
                VarInt.write(out, entry.getKey());
                VarInt.write(out, entry.getValue());
            }
        } catch (IOException e) {
            throw new IllegalStateException("ByteArrayOutputStream does not throw", e);
        }
        return out.toByteArray();
    }

    public static Http3Settings decodePayload(byte[] payload) throws Http3Exception {
        var result = new Http3Settings();
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        try {
            while (buffer.hasRemaining()) {
                long identifier = VarInt.read(buffer);
                long value = VarInt.read(buffer);
                result.settings.put(identifier, value);
            }
        } catch (BufferUnderflowException e) {
            throw new Http3Exception(Http3Exception.H3_FRAME_ERROR,
                    "SETTINGS payload ended part-way through an identifier/value pair");
        }
        return result;
    }

    @Override
    public String toString() {
        return settings.toString();
    }
}

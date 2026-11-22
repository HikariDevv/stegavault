package com.dips.stegavault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class PayloadCodec {
    public static final byte[] MAGIC = new byte[]{'S', 'T', 'G', 'V'};
    public static final byte VERSION = 1;
    public static final byte FLAG_COMPRESSED = 0x01;
    public static final byte TYPE_FILE = 0x01;
    public static final byte TYPE_TEXT = 0x02;

    public static final int HEADER_BYTES = 4 + 1 + 1 + CryptoEngine.SALT_BYTES + CryptoEngine.IV_BYTES + 4;
    public static final int MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024;

    private PayloadCodec() {
    }

    public record HeaderInfo(byte version, byte flags, byte[] salt, byte[] iv, int cipherLength) {
        public boolean isCompressed() {
            return (flags & FLAG_COMPRESSED) != 0;
        }

        public int totalEnvelopeBytes() {
            return HEADER_BYTES + cipherLength;
        }
    }

    public record DecodedPayload(byte type, String filename, byte[] data, boolean compressed) {
        public boolean isText() {
            return type == TYPE_TEXT;
        }
    }

    public record SealedResult(byte[] envelope, int rawInnerBytes, int storedInnerBytes, boolean compressed) {
    }

    public static SealedResult seal(byte type, String filename, byte[] data, char[] password, boolean allowCompress)
            throws GeneralSecurityException, IOException {
        byte[] nameBytes = filename == null ? new byte[0] : filename.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length > 65535) {
            throw new IllegalArgumentException("Filename exceeds maximum length.");
        }

        ByteBuffer inner = ByteBuffer.allocate(1 + 2 + nameBytes.length + 4 + data.length);
        inner.put(type);
        inner.putShort((short) nameBytes.length);
        inner.put(nameBytes);
        inner.putInt(data.length);
        inner.put(data);
        byte[] rawInner = inner.array();

        byte flags = 0;
        byte[] toEncrypt = rawInner;
        if (allowCompress) {
            byte[] compressed = deflate(rawInner);
            if (compressed.length < rawInner.length) {
                toEncrypt = compressed;
                flags |= FLAG_COMPRESSED;
            }
        }

        byte[] salt = CryptoEngine.randomBytes(CryptoEngine.SALT_BYTES);
        byte[] iv = CryptoEngine.randomBytes(CryptoEngine.IV_BYTES);
        byte[] aad = buildAad(VERSION, flags, salt, iv);
        byte[] ciphertext = CryptoEngine.encrypt(toEncrypt, password, salt, iv, aad);

        ByteBuffer envelope = ByteBuffer.allocate(HEADER_BYTES + ciphertext.length);
        envelope.put(MAGIC);
        envelope.put(VERSION);
        envelope.put(flags);
        envelope.put(salt);
        envelope.put(iv);
        envelope.putInt(ciphertext.length);
        envelope.put(ciphertext);

        return new SealedResult(envelope.array(), rawInner.length, toEncrypt.length, (flags & FLAG_COMPRESSED) != 0);
    }

    public static HeaderInfo parseHeader(byte[] headerBytes) {
        if (headerBytes == null || headerBytes.length < HEADER_BYTES) {
            return null;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (headerBytes[i] != MAGIC[i]) {
                return null;
            }
        }
        ByteBuffer buf = ByteBuffer.wrap(headerBytes);
        buf.position(4);
        byte version = buf.get();
        if (version != VERSION) {
            return null;
        }
        byte flags = buf.get();
        byte[] salt = new byte[CryptoEngine.SALT_BYTES];
        buf.get(salt);
        byte[] iv = new byte[CryptoEngine.IV_BYTES];
        buf.get(iv);
        int cipherLength = buf.getInt();
        if (cipherLength <= 16) {
            return null;
        }
        return new HeaderInfo(version, flags, salt, iv, cipherLength);
    }

    public static DecodedPayload open(byte[] envelope, char[] password)
            throws GeneralSecurityException, IOException {
        HeaderInfo header = parseHeader(envelope);
        if (header == null) {
            throw new IllegalArgumentException("No valid StegaVault payload found in image.");
        }
        if (envelope.length < header.totalEnvelopeBytes()) {
            throw new IllegalArgumentException("Truncated StegaVault payload.");
        }

        byte[] ciphertext = Arrays.copyOfRange(envelope, HEADER_BYTES, header.totalEnvelopeBytes());
        byte[] aad = buildAad(header.version(), header.flags(), header.salt(), header.iv());
        byte[] plaintext = CryptoEngine.decrypt(ciphertext, password, header.salt(), header.iv(), aad);

        byte[] innerBytes = header.isCompressed() ? inflate(plaintext) : plaintext;
        ByteBuffer buf = ByteBuffer.wrap(innerBytes);
        if (buf.remaining() < 7) {
            throw new IOException("Corrupted inner payload structure.");
        }
        byte type = buf.get();
        int nameLen = Short.toUnsignedInt(buf.getShort());
        if (buf.remaining() < nameLen + 4) {
            throw new IOException("Corrupted filename field.");
        }
        byte[] nameBytes = new byte[nameLen];
        buf.get(nameBytes);
        String filename = new String(nameBytes, StandardCharsets.UTF_8);

        int dataLen = buf.getInt();
        if (dataLen < 0 || buf.remaining() < dataLen) {
            throw new IOException("Corrupted data length field.");
        }
        byte[] data = new byte[dataLen];
        buf.get(data);

        return new DecodedPayload(type, filename, data, header.isCompressed());
    }

    private static byte[] buildAad(byte version, byte flags, byte[] salt, byte[] iv) {
        ByteBuffer aad = ByteBuffer.allocate(4 + 1 + 1 + salt.length + iv.length);
        aad.put(MAGIC);
        aad.put(version);
        aad.put(flags);
        aad.put(salt);
        aad.put(iv);
        return aad.array();
    }

    private static byte[] deflate(byte[] input) throws IOException {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(input);
        deflater.finish();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(input.length)) {
            byte[] buffer = new byte[8192];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                if (count == 0 && deflater.needsInput()) {
                    break;
                }
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    private static byte[] inflate(byte[] input) throws IOException {
        Inflater inflater = new Inflater();
        inflater.setInput(input);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(input.length * 2)) {
            byte[] buffer = new byte[8192];
            int total = 0;
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                }
                total += count;
                if (total > MAX_DECOMPRESSED_BYTES) {
                    throw new IOException("Decompressed payload exceeds safety limit.");
                }
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("Failed to decompress payload.", e);
        } finally {
            inflater.end();
        }
    }
}

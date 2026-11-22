package com.dips.stegavault;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

public final class LsbStego {
    private LsbStego() {
    }

    public static long maxCapacityBytes(BufferedImage image) {
        return ((long) image.getWidth() * (long) image.getHeight() * 3L) / 8L;
    }

    public static BufferedImage embed(BufferedImage source, byte[] payload) {
        long capacity = maxCapacityBytes(source);
        if (payload.length > capacity) {
            throw new IllegalArgumentException(
                    "Payload (" + payload.length + " bytes) exceeds image capacity (" + capacity + " bytes).");
        }

        int targetType = source.getColorModel().hasAlpha()
                ? BufferedImage.TYPE_INT_ARGB
                : BufferedImage.TYPE_INT_RGB;
        BufferedImage copy = new BufferedImage(source.getWidth(), source.getHeight(), targetType);
        Graphics2D g = copy.createGraphics();
        g.drawImage(source, 0, 0, null);
        g.dispose();

        int width = copy.getWidth();
        int height = copy.getHeight();
        int totalBits = payload.length * 8;
        int bitIndex = 0;

        for (int y = 0; y < height && bitIndex < totalBits; y++) {
            for (int x = 0; x < width && bitIndex < totalBits; x++) {
                int argb = copy.getRGB(x, y);
                int a = (argb >>> 24) & 0xFF;
                int r = (argb >>> 16) & 0xFF;
                int gr = (argb >>> 8) & 0xFF;
                int b = argb & 0xFF;

                if (bitIndex < totalBits) {
                    r = (r & 0xFE) | getBit(payload, bitIndex++);
                }
                if (bitIndex < totalBits) {
                    gr = (gr & 0xFE) | getBit(payload, bitIndex++);
                }
                if (bitIndex < totalBits) {
                    b = (b & 0xFE) | getBit(payload, bitIndex++);
                }

                int updated = (a << 24) | (r << 16) | (gr << 8) | b;
                copy.setRGB(x, y, updated);
            }
        }

        return copy;
    }

    public static byte[] extractBytes(BufferedImage image, int byteCount) {
        long capacity = maxCapacityBytes(image);
        if (byteCount < 0 || byteCount > capacity) {
            throw new IllegalArgumentException("Requested byte count exceeds image capacity.");
        }

        byte[] result = new byte[byteCount];
        int width = image.getWidth();
        int height = image.getHeight();
        int totalBits = byteCount * 8;
        int bitIndex = 0;

        for (int y = 0; y < height && bitIndex < totalBits; y++) {
            for (int x = 0; x < width && bitIndex < totalBits; x++) {
                int argb = image.getRGB(x, y);
                int r = (argb >>> 16) & 1;
                int gr = (argb >>> 8) & 1;
                int b = argb & 1;

                if (bitIndex < totalBits) {
                    setBit(result, bitIndex++, r);
                }
                if (bitIndex < totalBits) {
                    setBit(result, bitIndex++, gr);
                }
                if (bitIndex < totalBits) {
                    setBit(result, bitIndex++, b);
                }
            }
        }

        return result;
    }

    public static PayloadCodec.HeaderInfo inspectHeader(BufferedImage image) {
        if (maxCapacityBytes(image) < PayloadCodec.HEADER_BYTES) {
            return null;
        }
        byte[] headerBytes = extractBytes(image, PayloadCodec.HEADER_BYTES);
        PayloadCodec.HeaderInfo header = PayloadCodec.parseHeader(headerBytes);
        if (header == null) {
            return null;
        }
        if (header.totalEnvelopeBytes() > maxCapacityBytes(image)) {
            return null;
        }
        return header;
    }

    public static byte[] extractEnvelope(BufferedImage image) {
        PayloadCodec.HeaderInfo header = inspectHeader(image);
        if (header == null) {
            throw new IllegalArgumentException("No valid StegaVault payload detected in this image.");
        }
        return extractBytes(image, header.totalEnvelopeBytes());
    }

    private static int getBit(byte[] data, int bitIndex) {
        int byteIdx = bitIndex >>> 3;
        int bitOffset = 7 - (bitIndex & 7);
        return (data[byteIdx] >>> bitOffset) & 1;
    }

    private static void setBit(byte[] data, int bitIndex, int bit) {
        if (bit == 1) {
            int byteIdx = bitIndex >>> 3;
            int bitOffset = 7 - (bitIndex & 7);
            data[byteIdx] |= (byte) (1 << bitOffset);
        }
    }
}

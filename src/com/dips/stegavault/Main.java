package com.dips.stegavault;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public final class Main {
    private static final String VERSION = "1.0.0";

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String command = args[0].toLowerCase(Locale.ROOT);
        try {
            switch (command) {
                case "hide" -> runHide(Arrays.copyOfRange(args, 1, args.length));
                case "extract" -> runExtract(Arrays.copyOfRange(args, 1, args.length));
                case "info" -> runInfo(Arrays.copyOfRange(args, 1, args.length));
                case "version", "-v", "--version" -> System.out.println("stegavault " + VERSION);
                case "help", "-h", "--help" -> printUsage();
                default -> {
                    System.err.println(ConsoleUi.red("Unknown command: " + command));
                    printUsage();
                    System.exit(1);
                }
            }
        } catch (SecurityException e) {
            System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            System.exit(2);
        } catch (Exception e) {
            System.err.println(ConsoleUi.red("Error: " + e.getMessage()));
            System.exit(1);
        }
    }

    private static void runHide(String[] args) throws Exception {
        String passwordArg = null;
        String textMessage = null;
        boolean allowCompress = true;
        List<String> positional = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p", "--password" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("Missing value for " + args[i]);
                    }
                    passwordArg = args[++i];
                }
                case "-t", "--text" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("Missing value for " + args[i]);
                    }
                    textMessage = args[++i];
                }
                case "--no-compress" -> allowCompress = false;
                case "--no-color" -> ConsoleUi.setColorEnabled(false);
                default -> positional.add(args[i]);
            }
        }

        Path coverPath;
        Path outputPath;
        byte payloadType;
        String filename;
        byte[] payloadBytes;

        if (textMessage != null) {
            if (positional.size() != 2) {
                throw new IllegalArgumentException("Usage: hide <cover-image> --text \"<message>\" <output.png> [--password <pass>]");
            }
            coverPath = Path.of(positional.get(0));
            outputPath = Path.of(positional.get(1));
            payloadType = PayloadCodec.TYPE_TEXT;
            filename = "";
            payloadBytes = textMessage.getBytes(StandardCharsets.UTF_8);
        } else {
            if (positional.size() != 3) {
                throw new IllegalArgumentException("Usage: hide <cover-image> <secret-file> <output.png> [--password <pass>]");
            }
            coverPath = Path.of(positional.get(0));
            Path secretPath = Path.of(positional.get(1));
            outputPath = Path.of(positional.get(2));
            if (!Files.isRegularFile(secretPath)) {
                throw new IllegalArgumentException("Secret file not found: " + secretPath);
            }
            payloadType = PayloadCodec.TYPE_FILE;
            filename = secretPath.getFileName().toString();
            payloadBytes = Files.readAllBytes(secretPath);
        }

        BufferedImage cover = readImage(coverPath);
        char[] password = passwordArg != null ? passwordArg.toCharArray() : ConsoleUi.promptPassword(true);
        long startNanos = System.nanoTime();

        try {
            PayloadCodec.SealedResult sealed = PayloadCodec.seal(payloadType, filename, payloadBytes, password, allowCompress);
            long capacity = LsbStego.maxCapacityBytes(cover);
            if (sealed.envelope().length > capacity) {
                throw new IllegalArgumentException(
                        "Encrypted payload (" + ConsoleUi.formatBytes(sealed.envelope().length)
                                + ") exceeds cover image capacity (" + ConsoleUi.formatBytes(capacity) + ").");
            }

            BufferedImage stego = LsbStego.embed(cover, sealed.envelope());
            Path parent = outputPath.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            if (!ImageIO.write(stego, "png", outputPath.toFile())) {
                throw new IOException("Failed to write PNG output: " + outputPath);
            }

            double elapsedMs = (System.nanoTime() - startNanos) / 1_000_000.0;
            double usagePct = (sealed.envelope().length * 100.0) / capacity;

            System.out.println(ConsoleUi.bold(ConsoleUi.green("Hidden successfully")));
            System.out.println("  Cover      : " + coverPath.getFileName() + " (" + cover.getWidth() + "x" + cover.getHeight() + ")");
            System.out.println("  Output     : " + outputPath.toAbsolutePath());
            System.out.println("  Mode       : " + (payloadType == PayloadCodec.TYPE_TEXT ? "Text message" : "File (" + filename + ")"));
            System.out.println("  Cipher     : AES-256-GCM + PBKDF2-HMAC-SHA256 (" + CryptoEngine.PBKDF2_ITERATIONS + " iter)");
            System.out.println("  Envelope   : " + ConsoleUi.formatBytes(sealed.envelope().length)
                    + (sealed.compressed() ? " (compressed)" : " (raw)")
                    + String.format(Locale.ROOT, " [%.2f%% of %s]", usagePct, ConsoleUi.formatBytes(capacity)));
            System.out.println("  SHA-256    : " + sha256Hex(payloadBytes));
            System.out.printf(Locale.ROOT, "  Time       : %.1f ms%n", elapsedMs);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void runExtract(String[] args) throws Exception {
        String passwordArg = null;
        boolean force = false;
        List<String> positional = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p", "--password" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("Missing value for " + args[i]);
                    }
                    passwordArg = args[++i];
                }
                case "-f", "--force" -> force = true;
                case "--no-color" -> ConsoleUi.setColorEnabled(false);
                default -> positional.add(args[i]);
            }
        }

        if (positional.isEmpty() || positional.size() > 2) {
            throw new IllegalArgumentException("Usage: extract <stego.png> [output-dir] [--password <pass>] [--force]");
        }

        Path stegoPath = Path.of(positional.get(0));
        Path outDir = positional.size() == 2 ? Path.of(positional.get(1)) : Path.of(".");
        BufferedImage stego = readImage(stegoPath);

        byte[] envelope = LsbStego.extractEnvelope(stego);
        char[] password = passwordArg != null ? passwordArg.toCharArray() : ConsoleUi.promptPassword(false);
        long startNanos = System.nanoTime();

        try {
            PayloadCodec.DecodedPayload decoded = PayloadCodec.open(envelope, password);
            double elapsedMs = (System.nanoTime() - startNanos) / 1_000_000.0;

            if (decoded.isText()) {
                String message = new String(decoded.data(), StandardCharsets.UTF_8);
                System.out.println(ConsoleUi.bold(ConsoleUi.green("Decrypted message")));
                System.out.println(ConsoleUi.dim("----------------------------------------"));
                System.out.println(message);
                System.out.println(ConsoleUi.dim("----------------------------------------"));
                System.out.printf(Locale.ROOT, "  Verified   : AES-256-GCM OK (%.1f ms)%n", elapsedMs);
                return;
            }

            String safeName = sanitizeFilename(decoded.filename());
            Files.createDirectories(outDir);
            Path target = outDir.resolve(safeName).normalize();
            if (!target.startsWith(outDir.normalize())) {
                throw new SecurityException("Unsafe output filename detected.");
            }
            if (Files.exists(target) && !force) {
                throw new IOException("Output file already exists: " + target + " (use --force to overwrite)");
            }

            Files.write(target, decoded.data());
            System.out.println(ConsoleUi.bold(ConsoleUi.green("Extracted successfully")));
            System.out.println("  Output     : " + target.toAbsolutePath());
            System.out.println("  Size       : " + ConsoleUi.formatBytes(decoded.data().length));
            System.out.println("  SHA-256    : " + sha256Hex(decoded.data()));
            System.out.printf(Locale.ROOT, "  Verified   : AES-256-GCM OK (%.1f ms)%n", elapsedMs);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void runInfo(String[] args) throws Exception {
        List<String> positional = new ArrayList<>();
        for (String arg : args) {
            if ("--no-color".equals(arg)) {
                ConsoleUi.setColorEnabled(false);
            } else {
                positional.add(arg);
            }
        }
        if (positional.size() != 1) {
            throw new IllegalArgumentException("Usage: info <image.png>");
        }

        Path imagePath = Path.of(positional.get(0));
        BufferedImage image = readImage(imagePath);
        long capacity = LsbStego.maxCapacityBytes(image);
        long usable = Math.max(0, capacity - PayloadCodec.HEADER_BYTES - 16 - 32);
        PayloadCodec.HeaderInfo header = LsbStego.inspectHeader(image);

        System.out.println(ConsoleUi.bold("StegaVault Image Inspection"));
        System.out.println("  File       : " + imagePath.toAbsolutePath());
        System.out.println("  Dimensions : " + image.getWidth() + " x " + image.getHeight() + " px");
        System.out.println("  Alpha      : " + (image.getColorModel().hasAlpha() ? "Yes (ARGB)" : "No (RGB)"));
        System.out.println("  Capacity   : " + ConsoleUi.formatBytes(capacity) + " raw LSB (" + ConsoleUi.formatBytes(usable) + " usable)");
        if (header != null) {
            double pct = (header.totalEnvelopeBytes() * 100.0) / capacity;
            System.out.println("  Vault      : " + ConsoleUi.cyan("Detected (v" + header.version() + ")"));
            System.out.println("  Payload    : " + ConsoleUi.formatBytes(header.totalEnvelopeBytes())
                    + (header.isCompressed() ? " [compressed]" : " [raw]")
                    + String.format(Locale.ROOT, " (%.2f%% used)", pct));
        } else {
            System.out.println("  Vault      : " + ConsoleUi.dim("None detected"));
        }
    }

    private static BufferedImage readImage(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Image file not found: " + path);
        }
        BufferedImage image = ImageIO.read(path.toFile());
        if (image == null) {
            throw new IllegalArgumentException("Unsupported or unreadable image format: " + path);
        }
        return image;
    }

    private static String sanitizeFilename(String name) {
        if (name == null || name.isBlank()) {
            return "extracted.bin";
        }
        String normalized = name.replace('\\', '/');
        int lastSlash = normalized.lastIndexOf('/');
        String base = lastSlash >= 0 ? normalized.substring(lastSlash + 1) : normalized;
        if (base.isBlank() || ".".equals(base) || "..".equals(base)) {
            return "extracted.bin";
        }
        return base;
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }

    private static void printUsage() {
        System.out.println(ConsoleUi.bold("stegavault") + " " + VERSION + " - AES-256-GCM PNG LSB Steganography CLI");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar stegavault.jar hide <cover-image> <secret-file> <output.png> [--password <pass>] [--no-compress]");
        System.out.println("  java -jar stegavault.jar hide <cover-image> --text \"<message>\" <output.png> [--password <pass>]");
        System.out.println("  java -jar stegavault.jar extract <stego.png> [output-dir] [--password <pass>] [--force]");
        System.out.println("  java -jar stegavault.jar info <image.png>");
        System.out.println("  java -jar stegavault.jar version");
    }
}

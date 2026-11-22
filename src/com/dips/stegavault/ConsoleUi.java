package com.dips.stegavault;

import java.io.Console;
import java.util.Locale;

public final class ConsoleUi {
    private static boolean colorEnabled = System.getenv("NO_COLOR") == null;

    private ConsoleUi() {
    }

    public static void setColorEnabled(boolean enabled) {
        colorEnabled = enabled;
    }

    public static String bold(String text) {
        return wrap("1", text);
    }

    public static String dim(String text) {
        return wrap("2", text);
    }

    public static String green(String text) {
        return wrap("32", text);
    }

    public static String yellow(String text) {
        return wrap("33", text);
    }

    public static String red(String text) {
        return wrap("31", text);
    }

    public static String cyan(String text) {
        return wrap("36", text);
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024.0) {
            return String.format(Locale.ROOT, "%.2f KB", kb);
        }
        double mb = kb / 1024.0;
        return String.format(Locale.ROOT, "%.2f MB", mb);
    }

    public static char[] promptPassword(boolean confirm) {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("No interactive console available. Pass --password <pass>.");
        }
        char[] first = console.readPassword("Password: ");
        if (first == null || first.length == 0) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }
        if (confirm) {
            char[] second = console.readPassword("Confirm password: ");
            if (second == null || !java.util.Arrays.equals(first, second)) {
                java.util.Arrays.fill(first, '\0');
                if (second != null) {
                    java.util.Arrays.fill(second, '\0');
                }
                throw new IllegalArgumentException("Passwords do not match.");
            }
            java.util.Arrays.fill(second, '\0');
        }
        return first;
    }

    private static String wrap(String code, String text) {
        if (!colorEnabled) {
            return text;
        }
        return "\u001B[" + code + "m" + text + "\u001B[0m";
    }
}

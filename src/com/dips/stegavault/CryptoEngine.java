package com.dips.stegavault;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

public final class CryptoEngine {
    public static final int SALT_BYTES = 16;
    public static final int IV_BYTES = 12;
    public static final int KEY_BITS = 256;
    public static final int TAG_BITS = 128;
    public static final int PBKDF2_ITERATIONS = 200_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoEngine() {
    }

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    public static byte[] encrypt(byte[] plaintext, char[] password, byte[] salt, byte[] iv, byte[] aad)
            throws GeneralSecurityException {
        byte[] keyBytes = deriveKey(password, salt);
        try {
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public static byte[] decrypt(byte[] ciphertext, char[] password, byte[] salt, byte[] iv, byte[] aad)
            throws GeneralSecurityException {
        byte[] keyBytes = deriveKey(password, salt);
        try {
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Authentication failed: wrong password or corrupted image.", e);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}

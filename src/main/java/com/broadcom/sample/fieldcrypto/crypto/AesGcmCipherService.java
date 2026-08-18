package com.broadcom.sample.fieldcrypto.crypto;

import com.broadcom.sample.fieldcrypto.api.CipherService;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM based {@link CipherService}. Each call generates a fresh random
 * IV, which is stored alongside the ciphertext so decryption doesn't need
 * out-of-band IV management.
 *
 * Wire format (before base64): [12-byte IV][ciphertext + 16-byte GCM tag]
 *
 * <p>{@code Cipher} and {@code SecureRandom} instances are pooled one per
 * thread rather than created per call: {@code Cipher.getInstance(...)} does
 * a JCE provider lookup every time it's invoked, and a shared
 * {@code SecureRandom} is internally synchronized and becomes a contention
 * point under concurrent encryption. Reusing a thread-local {@code Cipher}
 * is safe here because every call fully {@code init}s it with a fresh IV
 * before calling {@code doFinal} - no state leaks between calls, even across
 * different {@code AesGcmCipherService} instances (different keys) sharing
 * the same thread.
 */
public final class AesGcmCipherService implements CipherService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final ThreadLocal<Cipher> CIPHER = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw new FieldEncryptionException("Unable to obtain an AES/GCM cipher", e);
        }
    });

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    private final SecretKey key;

    public AesGcmCipherService(SecretKey key) {
        this.key = key;
    }

    /** Generates a new random AES-256 key. Persist this securely (e.g. KMS/vault) and reuse it. */
    public static SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (GeneralSecurityException e) {
            throw new FieldEncryptionException("Unable to generate AES key", e);
        }
    }

    /** Rebuilds a SecretKey from a base64-encoded 256-bit key, e.g. loaded from an env var or vault. */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] raw = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(raw, "AES");
    }

    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            RANDOM.get().nextBytes(iv);

            Cipher cipher = CIPHER.get();
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length);
            buffer.put(iv).put(cipherText);
            return Base64.getEncoder().encodeToString(buffer.array());
        } catch (GeneralSecurityException e) {
            throw new FieldEncryptionException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        try {
            byte[] all = Base64.getDecoder().decode(ciphertext);
            ByteBuffer buffer = ByteBuffer.wrap(all);

            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            buffer.get(iv);
            byte[] cipherBytes = new byte[buffer.remaining()];
            buffer.get(cipherBytes);

            Cipher cipher = CIPHER.get();
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] plain = cipher.doFinal(cipherBytes);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new FieldEncryptionException("Decryption failed - wrong key or tampered data", e);
        }
    }
}

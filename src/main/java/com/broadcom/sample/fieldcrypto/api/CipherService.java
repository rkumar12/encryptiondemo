package com.broadcom.sample.fieldcrypto.api;

/**
 * Encrypts/decrypts a single value. Implementations are swappable behind
 * this interface so callers of {@link FieldEncryptionService} never depend
 * on a specific algorithm (e.g. AES-GCM).
 */
public interface CipherService {

    /**
     * @param plaintext value to encrypt, or {@code null}
     * @return the encoded ciphertext, or {@code null} if {@code plaintext} was {@code null}
     * @throws FieldEncryptionException if encryption fails
     */
    String encrypt(String plaintext);

    /**
     * @param ciphertext value produced by {@link #encrypt}, or {@code null}
     * @return the original plaintext, or {@code null} if {@code ciphertext} was {@code null}
     * @throws FieldEncryptionException if decryption fails (wrong key, tampered data, ...)
     */
    String decrypt(String ciphertext);
}

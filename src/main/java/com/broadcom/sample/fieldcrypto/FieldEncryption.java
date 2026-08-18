package com.broadcom.sample.fieldcrypto;

import com.broadcom.sample.fieldcrypto.api.CipherService;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;
import com.broadcom.sample.fieldcrypto.crypto.AesGcmCipherService;
import com.broadcom.sample.fieldcrypto.internal.ReflectionFieldEncryptionService;

import javax.crypto.SecretKey;

/**
 * Entry point for other modules to consume field-level encryption. This is
 * the only class consuming code should need to import to get started -
 * everything else lives behind {@link FieldEncryptionService} /
 * {@link CipherService} so the implementation can change without breaking
 * callers.
 *
 * <pre>{@code
 * SecretKey key = FieldEncryption.aesKeyFromBase64(loadKeyFromVault());
 * FieldEncryptionService encryption = FieldEncryption.aesGcm(key);
 *
 * encryption.encryptFields(customer); // before persisting / sending
 * encryption.decryptFields(customer); // after loading / receiving
 * }</pre>
 */
public final class FieldEncryption {

    private FieldEncryption() {
    }

    /** Builds a {@link FieldEncryptionService} backed by AES-256-GCM. */
    public static FieldEncryptionService aesGcm(SecretKey key) {
        return using(new AesGcmCipherService(key));
    }

    /** Builds a {@link FieldEncryptionService} backed by a custom {@link CipherService}. */
    public static FieldEncryptionService using(CipherService cipherService) {
        return new ReflectionFieldEncryptionService(cipherService);
    }

    /** Generates a new random AES-256 key. Persist it securely and reuse it - see {@link #aesKeyToBase64}. */
    public static SecretKey generateAesKey() {
        return AesGcmCipherService.generateKey();
    }

    /** Rebuilds an AES key previously serialized with {@link #aesKeyToBase64}. */
    public static SecretKey aesKeyFromBase64(String base64Key) {
        return AesGcmCipherService.keyFromBase64(base64Key);
    }

    /** Serializes an AES key for storage in a KMS/secrets vault. */
    public static String aesKeyToBase64(SecretKey key) {
        return AesGcmCipherService.keyToBase64(key);
    }
}

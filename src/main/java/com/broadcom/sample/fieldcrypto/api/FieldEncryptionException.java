package com.broadcom.sample.fieldcrypto.api;

/**
 * Unchecked exception for all failures raised by this library's public API
 * ({@link CipherService}, {@link FieldEncryptionService}), so consuming
 * modules can catch a single, stable exception type instead of depending
 * on implementation-specific exceptions (e.g. {@code GeneralSecurityException}).
 */
public class FieldEncryptionException extends RuntimeException {

    public FieldEncryptionException(String message) {
        super(message);
    }

    public FieldEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}

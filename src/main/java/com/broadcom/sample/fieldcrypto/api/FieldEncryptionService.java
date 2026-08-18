package com.broadcom.sample.fieldcrypto.api;

/**
 * Public API surface for field-level encryption. Obtain an instance via
 * {@code com.broadcom.sample.fieldcrypto.FieldEncryption} (the library's facade) -
 * callers should depend on this interface, not on any concrete implementation.
 */
public interface FieldEncryptionService {

    /**
     * Encrypts every {@link Encrypted}-annotated field on {@code target}, in place.
     * Supports {@code String} fields and {@link SecureField SecureField&lt;T&gt;} fields
     * of any other data type. Safe to call more than once - fields already
     * encrypted are left untouched.
     *
     * @throws FieldEncryptionException if a field marked {@link Encrypted} is neither a
     *                                   String nor a SecureField, or if the underlying cipher fails
     */
    void encryptFields(Object target);

    /**
     * Decrypts every {@link Encrypted}-annotated field on {@code target}, in place.
     * Safe to call on a target whose fields were never encrypted - they are left untouched.
     *
     * @throws FieldEncryptionException if a field marked {@link Encrypted} is neither a
     *                                   String nor a SecureField, or if the underlying cipher
     *                                   fails (wrong key, tampered data, ...)
     */
    void decryptFields(Object target);
}

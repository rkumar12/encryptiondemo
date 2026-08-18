package com.broadcom.sample.fieldcrypto.api;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Holds a value of any type T that can toggle between its plaintext form and
 * an encrypted form, in place, without ever changing the enclosing field's
 * declared type.
 *
 * <p>Reflection can only assign a value into a field if it's an instance of
 * the field's declared type - a base64 ciphertext String is never a valid
 * {@code Integer}, {@code LocalDate}, {@code BigDecimal}, etc. Wrapping the
 * value in {@code SecureField<T>} sidesteps that: the field always holds a
 * {@code SecureField} instance, so only what's inside it toggles between
 * plaintext and ciphertext.
 *
 * <p>Use one of the {@code of*} factory methods for common types, or
 * {@link #of(Object, ValueCodec)} with a custom {@link ValueCodec} for
 * anything else (e.g. an enum, or a domain type with its own String form).
 */
public final class SecureField<T> {

    private T value;
    private String cipherText;
    private final ValueCodec<T> codec;

    private SecureField(T value, String cipherText, ValueCodec<T> codec) {
        this.value = value;
        this.cipherText = cipherText;
        this.codec = Objects.requireNonNull(codec, "codec");
    }

    public static <T> SecureField<T> of(T value, ValueCodec<T> codec) {
        return new SecureField<>(value, null, codec);
    }

    public static SecureField<String> ofString(String value) {
        return of(value, ValueCodecs.STRING);
    }

    public static SecureField<Integer> ofInteger(Integer value) {
        return of(value, ValueCodecs.INTEGER);
    }

    public static SecureField<Long> ofLong(Long value) {
        return of(value, ValueCodecs.LONG);
    }

    public static SecureField<Double> ofDouble(Double value) {
        return of(value, ValueCodecs.DOUBLE);
    }

    public static SecureField<Boolean> ofBoolean(Boolean value) {
        return of(value, ValueCodecs.BOOLEAN);
    }

    public static SecureField<BigInteger> ofBigInteger(BigInteger value) {
        return of(value, ValueCodecs.BIG_INTEGER);
    }

    public static SecureField<BigDecimal> ofBigDecimal(BigDecimal value) {
        return of(value, ValueCodecs.BIG_DECIMAL);
    }

    public static SecureField<LocalDate> ofLocalDate(LocalDate value) {
        return of(value, ValueCodecs.LOCAL_DATE);
    }

    public static SecureField<LocalDateTime> ofLocalDateTime(LocalDateTime value) {
        return of(value, ValueCodecs.LOCAL_DATE_TIME);
    }

    public static SecureField<UUID> ofUuid(UUID value) {
        return of(value, ValueCodecs.UUID_CODEC);
    }

    /**
     * @return the plaintext value (may be {@code null} if none was ever set)
     * @throws FieldEncryptionException if this field is currently encrypted - call
     *                                    {@code FieldEncryptionService.decryptFields(...)} first
     */
    public T get() {
        if (cipherText != null) {
            throw new FieldEncryptionException("Value is still encrypted - call decryptFields() first");
        }
        return value;
    }

    public boolean isEncrypted() {
        return cipherText != null;
    }

    /**
     * Encrypts the current plaintext value in place using {@code cipherService}.
     * No-op if already encrypted or if the value is {@code null}.
     * Called by {@code FieldEncryptionService} - not typically invoked directly.
     */
    public void encryptInPlace(CipherService cipherService) {
        if (isEncrypted() || value == null) {
            return;
        }
        this.cipherText = cipherService.encrypt(codec.encode(value));
        this.value = null;
    }

    /**
     * Decrypts the current ciphertext in place using {@code cipherService}.
     * No-op if not currently encrypted.
     * Called by {@code FieldEncryptionService} - not typically invoked directly.
     */
    public void decryptInPlace(CipherService cipherService) {
        if (!isEncrypted()) {
            return;
        }
        String plaintext = cipherService.decrypt(cipherText);
        try {
            this.value = codec.decode(plaintext);
        } catch (RuntimeException e) {
            throw new FieldEncryptionException("Failed to decode decrypted value with codec " + codec, e);
        }
        this.cipherText = null;
    }

    @Override
    public String toString() {
        return isEncrypted() ? "SecureField{cipherText='" + cipherText + "'}" : "SecureField{value=" + value + "}";
    }
}

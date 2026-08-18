package com.broadcom.sample.fieldcrypto.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field as sensitive so a {@link FieldEncryptionService} will
 * encrypt it before persistence/transmission and decrypt it after.
 *
 * <p>Supported field types: {@code String}, or {@link SecureField
 * SecureField&lt;T&gt;} for any other data type (numbers, dates, booleans,
 * UUIDs, ...) - see {@link SecureField} for why non-String types need the
 * wrapper.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Encrypted {
}

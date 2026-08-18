package com.broadcom.sample.fieldcrypto.internal;

import com.broadcom.sample.fieldcrypto.api.CipherService;
import com.broadcom.sample.fieldcrypto.api.Encrypted;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionException;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;
import com.broadcom.sample.fieldcrypto.api.SecureField;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reflection-based {@link FieldEncryptionService}. Not part of the public
 * API - construct via {@code com.broadcom.sample.fieldcrypto.FieldEncryption}
 * instead of depending on this class directly, so implementation swaps
 * don't break callers.
 *
 * <p>Supports two kinds of {@link Encrypted} fields:
 * <ul>
 *   <li>{@code String} - ciphertext replaces the plaintext directly, marked
 *       with an {@code ENC::} prefix so both operations are idempotent.</li>
 *   <li>{@link SecureField SecureField&lt;T&gt;} - any other data type
 *       (numbers, dates, booleans, ...) wrapped so the field's declared type
 *       never has to change; see {@link SecureField} for why that's needed.</li>
 * </ul>
 *
 * <p>Which fields on a class are {@code @Encrypted}, and whether each is a
 * String or a SecureField, never changes at runtime - so that scan is done
 * once per class and cached, instead of re-walking {@code getDeclaredFields()}
 * and re-checking the annotation/type on every {@link #encryptFields}/
 * {@link #decryptFields} call.
 */
public final class ReflectionFieldEncryptionService implements FieldEncryptionService {

    private static final String ENC_PREFIX = "ENC::";

    private enum FieldKind { STRING, SECURE_FIELD }

    private static final class EncryptedField {
        final Field field;
        final FieldKind kind;

        EncryptedField(Field field, FieldKind kind) {
            this.field = field;
            this.kind = kind;
        }
    }

    private final CipherService cipherService;
    private final ConcurrentHashMap<Class<?>, List<EncryptedField>> metadataCache = new ConcurrentHashMap<>();

    public ReflectionFieldEncryptionService(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    @Override
    public void encryptFields(Object target) {
        process(target, true);
    }

    @Override
    public void decryptFields(Object target) {
        process(target, false);
    }

    /** Number of distinct classes whose {@code @Encrypted} fields have been scanned and cached so far. */
    int cachedClassCount() {
        return metadataCache.size();
    }

    private void process(Object target, boolean encrypting) {
        if (target == null) {
            return;
        }
        for (EncryptedField encryptedField : metadataCache.computeIfAbsent(target.getClass(), this::scanForEncryptedFields)) {
            Field field = encryptedField.field;
            try {
                if (encryptedField.kind == FieldKind.STRING) {
                    String current = (String) field.get(target);
                    field.set(target, encrypting ? encryptStringValue(current) : decryptStringValue(current));
                } else {
                    SecureField<?> secureField = (SecureField<?>) field.get(target);
                    if (secureField == null) {
                        continue;
                    }
                    if (encrypting) {
                        secureField.encryptInPlace(cipherService);
                    } else {
                        secureField.decryptInPlace(cipherService);
                    }
                }
            } catch (IllegalAccessException e) {
                throw new FieldEncryptionException("Unable to access field " + field.getName(), e);
            }
        }
    }

    private List<EncryptedField> scanForEncryptedFields(Class<?> targetClass) {
        List<EncryptedField> result = new ArrayList<>();
        for (Field field : targetClass.getDeclaredFields()) {
            if (!field.isAnnotationPresent(Encrypted.class)) {
                continue;
            }
            Class<?> type = field.getType();
            FieldKind kind;
            if (type == String.class) {
                kind = FieldKind.STRING;
            } else if (type == SecureField.class) {
                kind = FieldKind.SECURE_FIELD;
            } else {
                throw new FieldEncryptionException(
                        "@Encrypted only supports String or SecureField<?> fields, found "
                                + type.getName() + " on " + targetClass.getSimpleName() + "#" + field.getName());
            }
            field.setAccessible(true);
            result.add(new EncryptedField(field, kind));
        }
        return result;
    }

    private String encryptStringValue(String value) {
        if (value == null || value.startsWith(ENC_PREFIX)) {
            return value; // null or already encrypted - leave as is
        }
        return ENC_PREFIX + cipherService.encrypt(value);
    }

    private String decryptStringValue(String value) {
        if (value == null || !value.startsWith(ENC_PREFIX)) {
            return value; // null or not encrypted - leave as is
        }
        return cipherService.decrypt(value.substring(ENC_PREFIX.length()));
    }
}

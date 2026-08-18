package com.broadcom.sample.fieldcrypto.api;

import com.broadcom.sample.fieldcrypto.crypto.AesGcmCipherService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureFieldTest {

    private CipherService cipherService;

    @BeforeEach
    void setUp() {
        cipherService = new AesGcmCipherService(AesGcmCipherService.generateKey());
    }

    @Test
    void string_roundTrips() {
        assertRoundTrips(SecureField.ofString("secret-value"), "secret-value");
    }

    @Test
    void integer_roundTrips() {
        assertRoundTrips(SecureField.ofInteger(42), 42);
    }

    @Test
    void long_roundTrips() {
        assertRoundTrips(SecureField.ofLong(400123456789L), 400123456789L);
    }

    @Test
    void double_roundTrips() {
        assertRoundTrips(SecureField.ofDouble(3.14159), 3.14159);
    }

    @Test
    void boolean_roundTrips() {
        assertRoundTrips(SecureField.ofBoolean(true), true);
    }

    @Test
    void bigInteger_roundTrips() {
        assertRoundTrips(SecureField.ofBigInteger(new BigInteger("123456789012345678901234567890")),
                new BigInteger("123456789012345678901234567890"));
    }

    @Test
    void bigDecimal_roundTrips() {
        assertRoundTrips(SecureField.ofBigDecimal(new BigDecimal("18542.37")), new BigDecimal("18542.37"));
    }

    @Test
    void localDate_roundTrips() {
        assertRoundTrips(SecureField.ofLocalDate(LocalDate.of(1988, 7, 14)), LocalDate.of(1988, 7, 14));
    }

    @Test
    void localDateTime_roundTrips() {
        LocalDateTime now = LocalDateTime.of(2026, 8, 18, 10, 30, 0);
        assertRoundTrips(SecureField.ofLocalDateTime(now), now);
    }

    @Test
    void uuid_roundTrips() {
        UUID id = UUID.randomUUID();
        assertRoundTrips(SecureField.ofUuid(id), id);
    }

    @Test
    void get_whileEncrypted_throwsFieldEncryptionException() {
        SecureField<Integer> field = SecureField.ofInteger(42);
        field.encryptInPlace(cipherService);

        assertThrows(FieldEncryptionException.class, field::get);
    }

    @Test
    void encryptInPlace_calledTwice_doesNotDoubleEncrypt() {
        SecureField<Integer> field = SecureField.ofInteger(42);

        field.encryptInPlace(cipherService);
        String firstCipherText = field.toString();

        field.encryptInPlace(cipherService); // idempotency check
        assertEquals(firstCipherText, field.toString());

        field.decryptInPlace(cipherService);
        assertEquals(42, field.get());
    }

    @Test
    void decryptInPlace_onPlaintextField_isNoOp() {
        SecureField<Integer> field = SecureField.ofInteger(42);

        field.decryptInPlace(cipherService);

        assertFalse(field.isEncrypted());
        assertEquals(42, field.get());
    }

    @Test
    void encryptInPlace_withNullValue_leavesFieldDecryptedAndNull() {
        SecureField<Integer> field = SecureField.ofInteger(null);

        field.encryptInPlace(cipherService);

        assertFalse(field.isEncrypted());
        assertNull(field.get());
    }

    private <T> void assertRoundTrips(SecureField<T> field, T expectedValue) {
        assertEquals(expectedValue, field.get());
        assertFalse(field.isEncrypted());

        field.encryptInPlace(cipherService);
        assertTrue(field.isEncrypted());

        field.decryptInPlace(cipherService);
        assertFalse(field.isEncrypted());
        assertEquals(expectedValue, field.get());
    }
}

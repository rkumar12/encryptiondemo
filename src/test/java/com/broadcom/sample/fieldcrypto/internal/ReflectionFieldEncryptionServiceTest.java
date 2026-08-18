package com.broadcom.sample.fieldcrypto.internal;

import com.broadcom.sample.fieldcrypto.api.FieldEncryptionException;
import com.broadcom.sample.fieldcrypto.crypto.AesGcmCipherService;
import com.broadcom.sample.fieldcrypto.example.BankCustomer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReflectionFieldEncryptionServiceTest {

    private ReflectionFieldEncryptionService processor;

    @BeforeEach
    void setUp() {
        AesGcmCipherService cipherService = new AesGcmCipherService(AesGcmCipherService.generateKey());
        processor = new ReflectionFieldEncryptionService(cipherService);
    }

    private static BankCustomer newCustomer() {
        return new BankCustomer("C-1", "Jordan Blake", "123-45-6789", "4111111111111111",
                "021000021", 400123456789L, new BigDecimal("18542.37"), LocalDate.of(1988, 7, 14));
    }

    @Test
    void encryptFields_encryptsOnlyAnnotatedStringFields() {
        BankCustomer customer = newCustomer();

        processor.encryptFields(customer);

        assertEquals("C-1", customer.getCustomerId(), "unannotated field must stay untouched");
        assertEquals("Jordan Blake", customer.getFullName(), "unannotated field must stay untouched");
        assertNotEquals("123-45-6789", customer.getSsn());
        assertNotEquals("4111111111111111", customer.getCreditCardNumber());
        assertNotEquals("021000021", customer.getRoutingNumber());
        assertTrue(customer.getSsn().startsWith("ENC::"));
        assertTrue(customer.getCreditCardNumber().startsWith("ENC::"));
        assertTrue(customer.getRoutingNumber().startsWith("ENC::"));
    }

    @Test
    void encryptFields_encryptsSecureFieldsOfEveryWrappedType() {
        BankCustomer customer = newCustomer();

        processor.encryptFields(customer);

        assertTrue(customer.getAccountNumberField().isEncrypted());
        assertTrue(customer.getAccountBalanceField().isEncrypted());
        assertTrue(customer.getDateOfBirthField().isEncrypted());
        assertThrows(FieldEncryptionException.class, () -> customer.getAccountNumberField().get());
    }

    @Test
    void encryptThenDecryptFields_restoresOriginalValuesAcrossAllTypes() {
        BankCustomer customer = newCustomer();

        processor.encryptFields(customer);
        processor.decryptFields(customer);

        assertEquals("123-45-6789", customer.getSsn());
        assertEquals("4111111111111111", customer.getCreditCardNumber());
        assertEquals("021000021", customer.getRoutingNumber());
        assertEquals(400123456789L, customer.getAccountNumberField().get());
        assertEquals(new BigDecimal("18542.37"), customer.getAccountBalanceField().get());
        assertEquals(LocalDate.of(1988, 7, 14), customer.getDateOfBirthField().get());
        assertFalse(customer.getAccountNumberField().isEncrypted());
    }

    @Test
    void encryptFields_calledTwice_doesNotDoubleEncrypt() {
        BankCustomer customer = newCustomer();

        processor.encryptFields(customer);
        String firstPassSsn = customer.getSsn();
        String firstPassCipherText = customer.getAccountNumberField().toString();

        processor.encryptFields(customer); // idempotency check
        assertEquals(firstPassSsn, customer.getSsn());
        assertEquals(firstPassCipherText, customer.getAccountNumberField().toString());

        processor.decryptFields(customer);
        assertEquals("123-45-6789", customer.getSsn());
        assertEquals(400123456789L, customer.getAccountNumberField().get());
    }

    @Test
    void decryptFields_onPlaintextValue_leavesItUnchanged() {
        BankCustomer customer = newCustomer();

        // never encrypted - decrypt should be a no-op
        processor.decryptFields(customer);

        assertEquals("123-45-6789", customer.getSsn());
        assertEquals(400123456789L, customer.getAccountNumberField().get());
        assertFalse(customer.getAccountNumberField().isEncrypted());
    }

    @Test
    void encryptFields_withNullSensitiveValues_leavesThemNull() {
        BankCustomer customer = new BankCustomer("C-1", "Jordan Blake", null, null, null, null, null, null);

        processor.encryptFields(customer);

        assertNull(customer.getSsn());
        assertFalse(customer.getAccountNumberField().isEncrypted());
        assertNull(customer.getAccountNumberField().get());
    }

    @Test
    void encryptFields_onNonStringAnnotatedField_throwsFieldEncryptionException() {
        InvalidCustomer invalidCustomer = new InvalidCustomer(42);

        assertThrows(FieldEncryptionException.class, () -> processor.encryptFields(invalidCustomer));
    }

    @Test
    void encryptAndDecryptFields_onNullTarget_isNoOp() {
        processor.encryptFields(null);
        processor.decryptFields(null);
    }

    @Test
    void fieldMetadata_isScannedOncePerClassAndReused() {
        assertEquals(0, processor.cachedClassCount());

        processor.encryptFields(newCustomer());
        assertEquals(1, processor.cachedClassCount(), "first instance of a class should trigger one scan");

        processor.encryptFields(newCustomer());
        processor.decryptFields(newCustomer());
        assertEquals(1, processor.cachedClassCount(), "further instances of the same class must reuse the cached scan");

        // an invalid class throws every time rather than caching a broken/partial scan
        assertThrows(FieldEncryptionException.class, () -> processor.encryptFields(new InvalidCustomer(1)));
        assertThrows(FieldEncryptionException.class, () -> processor.encryptFields(new InvalidCustomer(2)));
        assertEquals(1, processor.cachedClassCount(), "a class that fails to scan must not be cached");
    }
}

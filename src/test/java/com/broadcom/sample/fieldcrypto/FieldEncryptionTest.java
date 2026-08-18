package com.broadcom.sample.fieldcrypto;

import com.broadcom.sample.fieldcrypto.api.CipherService;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;
import com.broadcom.sample.fieldcrypto.example.BankCustomer;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the library exactly as a consuming module would: only
 * {@link FieldEncryption} and {@code com.broadcom.sample.fieldcrypto.api.*} types
 * are referenced here, never {@code crypto}/{@code internal} classes.
 */
class FieldEncryptionTest {

    private static BankCustomer newCustomer() {
        return new BankCustomer("C-1", "Jordan Blake", "123-45-6789", "4111111111111111",
                "021000021", 400123456789L, new BigDecimal("18542.37"), LocalDate.of(1988, 7, 14));
    }

    @Test
    void aesGcm_encryptsAndDecryptsStringAndSecureFieldsAcrossTypes() {
        SecretKey key = FieldEncryption.generateAesKey();
        FieldEncryptionService encryption = FieldEncryption.aesGcm(key);
        BankCustomer customer = newCustomer();

        encryption.encryptFields(customer);
        assertNotEquals("123-45-6789", customer.getSsn());
        assertTrue(customer.getAccountNumberField().isEncrypted());
        assertTrue(customer.getAccountBalanceField().isEncrypted());
        assertTrue(customer.getDateOfBirthField().isEncrypted());

        encryption.decryptFields(customer);
        assertEquals("123-45-6789", customer.getSsn());
        assertEquals(400123456789L, customer.getAccountNumberField().get());
        assertEquals(new BigDecimal("18542.37"), customer.getAccountBalanceField().get());
        assertEquals(LocalDate.of(1988, 7, 14), customer.getDateOfBirthField().get());
    }

    @Test
    void aesKeyToBase64AndFromBase64_roundTrips() {
        SecretKey key = FieldEncryption.generateAesKey();
        String base64Key = FieldEncryption.aesKeyToBase64(key);

        FieldEncryptionService encryption = FieldEncryption.aesGcm(FieldEncryption.aesKeyFromBase64(base64Key));
        BankCustomer customer = newCustomer();

        encryption.encryptFields(customer);
        encryption.decryptFields(customer);

        assertEquals("123-45-6789", customer.getSsn());
        assertEquals(LocalDate.of(1988, 7, 14), customer.getDateOfBirthField().get());
    }

    @Test
    void using_acceptsACustomCipherService() {
        // A consuming module can plug in its own CipherService without touching this library's internals.
        CipherService reversingCipher = new CipherService() {
            @Override
            public String encrypt(String plaintext) {
                return plaintext == null ? null : new StringBuilder(plaintext).reverse().toString();
            }

            @Override
            public String decrypt(String ciphertext) {
                return ciphertext == null ? null : new StringBuilder(ciphertext).reverse().toString();
            }
        };

        FieldEncryptionService encryption = FieldEncryption.using(reversingCipher);
        BankCustomer customer = newCustomer();

        encryption.encryptFields(customer);
        assertTrue(customer.getSsn().startsWith("ENC::"));
        assertTrue(customer.getAccountBalanceField().isEncrypted());

        encryption.decryptFields(customer);
        assertEquals("123-45-6789", customer.getSsn());
        assertEquals(new BigDecimal("18542.37"), customer.getAccountBalanceField().get());
    }
}

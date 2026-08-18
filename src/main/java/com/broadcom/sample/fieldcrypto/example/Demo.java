package com.broadcom.sample.fieldcrypto.example;

import com.broadcom.sample.fieldcrypto.FieldEncryption;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;

import java.math.BigDecimal;
import java.time.LocalDate;
import javax.crypto.SecretKey;

/**
 * Shows how a consuming module would use this library: only
 * {@code com.broadcom.sample.fieldcrypto.FieldEncryption} and
 * {@code com.broadcom.sample.fieldcrypto.api.*} are touched here - never the
 * {@code crypto}/{@code internal} packages.
 */
public class Demo {

    public static void main(String[] args) {
        // In real code: load this key from a KMS/secrets vault - never generate
        // it fresh each run, or previously-encrypted data becomes undecryptable.
        SecretKey key = FieldEncryption.generateAesKey();
        System.out.println("Key (base64, store this securely): " + FieldEncryption.aesKeyToBase64(key));

        FieldEncryptionService encryption = FieldEncryption.aesGcm(key);

        BankCustomer customer = new BankCustomer(
                "C-1001", "Jordan Blake", "123-45-6789", "4111111111111111",
                "021000021", 400123456789L, new BigDecimal("18542.37"), LocalDate.of(1988, 7, 14));
        System.out.println("Original:  " + customer);

        encryption.encryptFields(customer);
        System.out.println("Encrypted: " + customer);

        encryption.decryptFields(customer);
        System.out.println("Decrypted: " + customer);
    }
}

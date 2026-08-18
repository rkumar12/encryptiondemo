package com.broadcom.sample.fieldcrypto.crypto;

import com.broadcom.sample.fieldcrypto.api.FieldEncryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCipherServiceTest {

    private AesGcmCipherService cipherService;

    @BeforeEach
    void setUp() {
        cipherService = new AesGcmCipherService(AesGcmCipherService.generateKey());
    }

    @Test
    void encryptThenDecrypt_returnsOriginalPlaintext() {
        String plaintext = "123-45-6789";

        String encrypted = cipherService.encrypt(plaintext);
        String decrypted = cipherService.decrypt(encrypted);

        assertNotEquals(plaintext, encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_sameInputTwice_producesDifferentCiphertext() {
        String plaintext = "4111111111111111";

        String first = cipherService.encrypt(plaintext);
        String second = cipherService.encrypt(plaintext);

        assertNotEquals(first, second, "each encryption should use a fresh random IV");
        assertEquals(plaintext, cipherService.decrypt(first));
        assertEquals(plaintext, cipherService.decrypt(second));
    }

    @Test
    void encrypt_nullInput_returnsNull() {
        assertNull(cipherService.encrypt(null));
    }

    @Test
    void decrypt_nullInput_returnsNull() {
        assertNull(cipherService.decrypt(null));
    }

    @Test
    void encrypt_emptyString_roundTrips() {
        String encrypted = cipherService.encrypt("");
        assertEquals("", cipherService.decrypt(encrypted));
    }

    @Test
    void decrypt_withWrongKey_throwsFieldEncryptionException() {
        String encrypted = cipherService.encrypt("sensitive-value");
        AesGcmCipherService otherService = new AesGcmCipherService(AesGcmCipherService.generateKey());

        assertThrows(FieldEncryptionException.class, () -> otherService.decrypt(encrypted));
    }

    @Test
    void decrypt_tamperedCiphertext_throwsFieldEncryptionException() {
        String encrypted = cipherService.encrypt("sensitive-value");
        byte[] raw = Base64.getDecoder().decode(encrypted);
        raw[raw.length - 1] ^= 0x01; // flip a bit in the GCM auth tag / ciphertext
        String tampered = Base64.getEncoder().encodeToString(raw);

        assertThrows(FieldEncryptionException.class, () -> cipherService.decrypt(tampered));
    }

    @Test
    void keyToBase64AndBack_roundTrips() {
        SecretKey original = AesGcmCipherService.generateKey();
        String encoded = AesGcmCipherService.keyToBase64(original);
        SecretKey restored = AesGcmCipherService.keyFromBase64(encoded);

        AesGcmCipherService serviceWithRestoredKey = new AesGcmCipherService(restored);
        String encrypted = new AesGcmCipherService(original).encrypt("round-trip-check");

        assertEquals("round-trip-check", serviceWithRestoredKey.decrypt(encrypted));
    }

    @Test
    void concurrentEncryptDecrypt_acrossThreadsAndDifferentKeys_isThreadSafe() throws Exception {
        // Cipher/SecureRandom are pooled one-per-thread for performance; this proves that
        // pooling doesn't leak state between concurrent callers or across different keys
        // sharing the same thread.
        int threadCount = 8;
        int iterationsPerThread = 500;
        AtomicInteger mismatches = new AtomicInteger();

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threadCount; t++) {
            int threadIndex = t;
            futures.add(executor.submit(() -> {
                for (int i = 0; i < iterationsPerThread; i++) {
                    // a fresh key/service every iteration maximizes cross-key interleaving on this thread
                    AesGcmCipherService service = new AesGcmCipherService(AesGcmCipherService.generateKey());
                    String plaintext = "thread-" + threadIndex + "-value-" + i;
                    String decrypted = service.decrypt(service.encrypt(plaintext));
                    if (!plaintext.equals(decrypted)) {
                        mismatches.incrementAndGet();
                    }
                }
            }));
        }

        for (Future<?> future : futures) {
            future.get(30, TimeUnit.SECONDS);
        }
        executor.shutdown();

        assertEquals(0, mismatches.get(), "every concurrent encrypt/decrypt round-trip must return its own plaintext");
    }
}

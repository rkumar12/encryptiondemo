package com.broadcom.sample.fieldcrypto;

import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;
import com.broadcom.sample.fieldcrypto.example.BankCustomer;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end throughput regression floor through the public API surface
 * only ({@link FieldEncryption} + {@code api.*}) - the same path a
 * consuming module would exercise. See {@code AesGcmCipherServicePerformanceTest}
 * for the caveat that this is a regression floor, not a rigorous benchmark.
 */
class FieldEncryptionPerformanceTest {

    private static final int WARMUP_ITERATIONS = 500;
    private static final int MEASURED_ITERATIONS = 5_000;
    private static final double MIN_ROUND_TRIPS_PER_SECOND = 500;

    @Test
    void aesGcm_sustainsMinimumThroughputForBankCustomer() {
        SecretKey key = FieldEncryption.generateAesKey();
        FieldEncryptionService encryption = FieldEncryption.aesGcm(key);

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            roundTrip(encryption);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURED_ITERATIONS; i++) {
            roundTrip(encryption);
        }
        long elapsedNanos = System.nanoTime() - start;

        double roundTripsPerSecond = MEASURED_ITERATIONS / (elapsedNanos / 1_000_000_000.0);
        System.out.printf("[perf] FieldEncryption.aesGcm end-to-end: %.0f round-trips/sec (%.1f ms total)%n",
                roundTripsPerSecond, elapsedNanos / 1_000_000.0);

        assertTrue(roundTripsPerSecond > MIN_ROUND_TRIPS_PER_SECOND,
                "expected at least " + MIN_ROUND_TRIPS_PER_SECOND + " round-trips/sec, got " + roundTripsPerSecond);
    }

    private void roundTrip(FieldEncryptionService encryption) {
        BankCustomer customer = new BankCustomer("C-1", "Jordan Blake", "123-45-6789", "4111111111111111",
                "021000021", 400123456789L, new BigDecimal("18542.37"), LocalDate.of(1988, 7, 14));
        encryption.encryptFields(customer);
        encryption.decryptFields(customer);
    }
}

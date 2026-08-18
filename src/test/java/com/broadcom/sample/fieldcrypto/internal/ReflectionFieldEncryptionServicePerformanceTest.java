package com.broadcom.sample.fieldcrypto.internal;

import com.broadcom.sample.fieldcrypto.crypto.AesGcmCipherService;
import com.broadcom.sample.fieldcrypto.example.BankCustomer;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Throughput regression floor for full-object field encryption across a
 * class mixing {@code String} and {@code SecureField<T>} fields
 * ({@link BankCustomer} has 6 {@code @Encrypted} fields spanning String,
 * Long, BigDecimal and LocalDate). Not a rigorous benchmark - see
 * {@code AesGcmCipherServicePerformanceTest} for that caveat in more detail.
 */
class ReflectionFieldEncryptionServicePerformanceTest {

    private static final int WARMUP_ITERATIONS = 500;
    private static final int MEASURED_ITERATIONS = 5_000;
    private static final double MIN_ROUND_TRIPS_PER_SECOND = 500;

    private static BankCustomer newCustomer() {
        return new BankCustomer("C-1", "Jordan Blake", "123-45-6789", "4111111111111111",
                "021000021", 400123456789L, new BigDecimal("18542.37"), LocalDate.of(1988, 7, 14));
    }

    @Test
    void encryptThenDecryptFields_sustainsMinimumThroughputAcrossAllFieldTypes() {
        ReflectionFieldEncryptionService processor =
                new ReflectionFieldEncryptionService(new AesGcmCipherService(AesGcmCipherService.generateKey()));

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            BankCustomer customer = newCustomer();
            processor.encryptFields(customer);
            processor.decryptFields(customer);
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURED_ITERATIONS; i++) {
            BankCustomer customer = newCustomer();
            processor.encryptFields(customer);
            processor.decryptFields(customer);
        }
        long elapsedNanos = System.nanoTime() - start;

        double roundTripsPerSecond = MEASURED_ITERATIONS / (elapsedNanos / 1_000_000_000.0);
        System.out.printf(
                "[perf] BankCustomer encryptFields+decryptFields (6 annotated fields): %.0f round-trips/sec (%.1f ms total)%n",
                roundTripsPerSecond, elapsedNanos / 1_000_000.0);

        assertTrue(roundTripsPerSecond > MIN_ROUND_TRIPS_PER_SECOND,
                "expected at least " + MIN_ROUND_TRIPS_PER_SECOND + " round-trips/sec, got " + roundTripsPerSecond);
        assertEquals(1, processor.cachedClassCount(),
                "every iteration should share the one cached field scan for BankCustomer");
    }
}

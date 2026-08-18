package com.broadcom.sample.fieldcrypto.crypto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Throughput regression floors for {@link AesGcmCipherService}, not a
 * rigorous benchmark (no JMH, no isolated JIT warm-up). These exist to catch
 * a gross regression - e.g. accidentally dropping the thread-local
 * {@code Cipher}/{@code SecureRandom} pooling and going back to
 * {@code Cipher.getInstance(...)} per call - not to track micro-optimizations.
 * Thresholds are set far below what any real machine should sustain, to
 * avoid flaking on a slow or shared CI runner.
 */
class AesGcmCipherServicePerformanceTest {

    private static final int WARMUP_ITERATIONS = 2_000;
    private static final int MEASURED_ITERATIONS = 20_000;
    private static final double MIN_ROUND_TRIPS_PER_SECOND = 2_000;

    @Test
    void encryptDecryptRoundTrip_sustainsMinimumThroughput() {
        AesGcmCipherService cipherService = new AesGcmCipherService(AesGcmCipherService.generateKey());
        String plaintext = "400123456789";

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            cipherService.decrypt(cipherService.encrypt(plaintext));
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURED_ITERATIONS; i++) {
            cipherService.decrypt(cipherService.encrypt(plaintext));
        }
        long elapsedNanos = System.nanoTime() - start;

        double roundTripsPerSecond = MEASURED_ITERATIONS / (elapsedNanos / 1_000_000_000.0);
        System.out.printf("[perf] AES-GCM encrypt+decrypt (1 thread): %.0f round-trips/sec (%d iterations in %.1f ms)%n",
                roundTripsPerSecond, MEASURED_ITERATIONS, elapsedNanos / 1_000_000.0);

        assertTrue(roundTripsPerSecond > MIN_ROUND_TRIPS_PER_SECOND,
                "expected at least " + MIN_ROUND_TRIPS_PER_SECOND + " round-trips/sec, got " + roundTripsPerSecond);
    }

    @Test
    void concurrentEncryptDecrypt_sustainsMinimumAggregateThroughput() throws Exception {
        // A single shared CipherService used from many threads is the realistic usage
        // pattern this pooling targets - this proves throughput actually scales with
        // threads instead of bottlenecking on a shared Cipher/SecureRandom.
        int threadCount = Math.max(2, Runtime.getRuntime().availableProcessors());
        int iterationsPerThread = 5_000;
        AesGcmCipherService cipherService = new AesGcmCipherService(AesGcmCipherService.generateKey());

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            cipherService.decrypt(cipherService.encrypt("warmup"));
        }

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();
        long start = System.nanoTime();
        for (int t = 0; t < threadCount; t++) {
            int threadIndex = t;
            futures.add(executor.submit(() -> {
                for (int i = 0; i < iterationsPerThread; i++) {
                    cipherService.decrypt(cipherService.encrypt("thread-" + threadIndex + "-value-" + i));
                }
            }));
        }
        for (Future<?> future : futures) {
            future.get(60, TimeUnit.SECONDS);
        }
        long elapsedNanos = System.nanoTime() - start;
        executor.shutdown();

        long totalOps = (long) threadCount * iterationsPerThread;
        double roundTripsPerSecond = totalOps / (elapsedNanos / 1_000_000_000.0);
        System.out.printf("[perf] AES-GCM encrypt+decrypt (%d threads): %.0f round-trips/sec aggregate%n",
                threadCount, roundTripsPerSecond);

        assertTrue(roundTripsPerSecond > MIN_ROUND_TRIPS_PER_SECOND,
                "expected concurrent aggregate throughput above the single-thread floor, got " + roundTripsPerSecond);
    }
}

package com.broadcom.sample.fieldcrypto.api;

/**
 * Converts a value of type T to/from its canonical String form so it can be
 * passed through a {@link CipherService}, which only operates on Strings.
 * Implement this for any type not already covered by {@link ValueCodecs}.
 */
public interface ValueCodec<T> {

    /** @return the canonical String form of {@code value}; never called with a null value */
    String encode(T value);

    /** @return the value parsed back out of {@code text}, as produced by {@link #encode} */
    T decode(String text);
}

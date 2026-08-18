package com.broadcom.sample.fieldcrypto.api;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.function.Function;

/**
 * Built-in {@link ValueCodec}s for the data types commonly needed on a PII
 * record - identifiers, monetary amounts, dates, flags. Use these with
 * {@link SecureField}'s {@code of*} factory methods, or reference them
 * directly when building a custom {@link SecureField}.
 */
public final class ValueCodecs {

    public static final ValueCodec<String> STRING = new ValueCodec<String>() {
        @Override
        public String encode(String value) {
            return value;
        }

        @Override
        public String decode(String text) {
            return text;
        }
    };

    public static final ValueCodec<Integer> INTEGER = simple(Integer::valueOf);
    public static final ValueCodec<Long> LONG = simple(Long::valueOf);
    public static final ValueCodec<Double> DOUBLE = simple(Double::valueOf);
    public static final ValueCodec<Boolean> BOOLEAN = simple(Boolean::valueOf);
    public static final ValueCodec<BigInteger> BIG_INTEGER = simple(BigInteger::new);
    public static final ValueCodec<BigDecimal> BIG_DECIMAL = simple(BigDecimal::new);
    public static final ValueCodec<LocalDate> LOCAL_DATE = simple(LocalDate::parse);
    public static final ValueCodec<LocalDateTime> LOCAL_DATE_TIME = simple(LocalDateTime::parse);
    public static final ValueCodec<UUID> UUID_CODEC = simple(UUID::fromString);

    private ValueCodecs() {
    }

    private static <T> ValueCodec<T> simple(Function<String, T> parser) {
        return new ValueCodec<T>() {
            @Override
            public String encode(T value) {
                return String.valueOf(value);
            }

            @Override
            public T decode(String text) {
                return parser.apply(text);
            }
        };
    }
}

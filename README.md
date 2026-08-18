# Field-Level Encryption Library (Java)

**Author:** Rajiv Kumar

A small library showing how to encrypt and decrypt **specific fields** of a
Java object (rather than the whole object) using an annotation plus
reflection, backed by AES-256-GCM — structured so it can be consumed as an
API by other modules, and supporting **multiple data types** (String,
numbers, dates, booleans, ...), not just String fields.

Typical use case: a bank customer record with sensitive fields (SSN,
account number, balance, date of birth) that must be encrypted at rest / in
transit, while other fields (customer ID, name) stay in plaintext for
querying and display.

## Package layout — the API boundary

```
com.broadcom.sample.fieldcrypto
├── FieldEncryption          <- facade: the ONE class other modules import to get started
├── api/                     <- public contract; depend on these types, not on impl classes
│   ├── Encrypted              annotation for sensitive fields
│   ├── SecureField<T>         wrapper enabling encryption of non-String field types
│   ├── ValueCodec<T> / ValueCodecs   String <-> T conversion for SecureField
│   ├── CipherService          interface: encrypt(String) / decrypt(String)
│   ├── FieldEncryptionService interface: encryptFields(Object) / decryptFields(Object)
│   └── FieldEncryptionException  single unchecked exception type for the whole API
├── crypto/
│   └── AesGcmCipherService   <- the default CipherService implementation (AES-256-GCM)
├── internal/
│   └── ReflectionFieldEncryptionService  <- the default FieldEncryptionService implementation
└── example/                 <- sample usage only, not part of the library
    ├── BankCustomer            bank PII record: String, Long, BigDecimal, LocalDate fields
    └── Demo
```

**Why split it this way:** `api` is the only package a consuming module should
import from directly (plus `FieldEncryption` to construct things). `crypto`
and `internal` hold swappable implementations — a consumer that wants a
different cipher algorithm implements `CipherService` and passes it to
`FieldEncryption.using(...)`, without ever touching `AesGcmCipherService` or
`ReflectionFieldEncryptionService`.

## How it works

| Type | Responsibility |
|---|---|
| `FieldEncryption` | Facade / static factory. `FieldEncryption.aesGcm(key)` or `FieldEncryption.using(customCipherService)` returns a ready-to-use `FieldEncryptionService`. Also has key generation/(de)serialization helpers. |
| `api.Encrypted` | Marker annotation you put on any supported field that should be protected. |
| `api.SecureField<T>` | Wraps a value of any type `T`, toggling between its plaintext form and ciphertext **without changing the enclosing field's declared type**. See below for why this exists. |
| `api.ValueCodec<T>` / `api.ValueCodecs` | Converts `T <-> String` for `SecureField`. Built-in codecs: `String`, `Integer`, `Long`, `Double`, `Boolean`, `BigInteger`, `BigDecimal`, `LocalDate`, `LocalDateTime`, `UUID`. Implement `ValueCodec<T>` yourself for anything else (enums, domain types, ...). |
| `api.CipherService` | Contract for encrypting/decrypting a single value. Implement this to plug in a different algorithm or an external KMS. |
| `api.FieldEncryptionService` | Contract for encrypting/decrypting all annotated fields on an object. This is the type consuming code should hold a reference to. |
| `api.FieldEncryptionException` | The single unchecked exception the API throws, so callers don't need to catch implementation-specific exceptions. |
| `crypto.AesGcmCipherService` | Default `CipherService`: AES/GCM/NoPadding. Generates a random 12-byte IV per call, prepends it to the ciphertext, base64-encodes the result. |
| `internal.ReflectionFieldEncryptionService` | Default `FieldEncryptionService`: scans an object's declared fields for `@Encrypted` and encrypts/decrypts them **in place** — handles both `String` fields and `SecureField<T>` fields. |
| `example.BankCustomer` / `example.Demo` | Sample bank PII record and runnable demo, kept separate from the library code. |

### Supporting multiple data types — why `SecureField<T>` exists

Reflection can only assign a value into a field if it's an instance of that
field's *declared* type. A base64 ciphertext `String` is never a valid
`Integer`, `LocalDate`, or `BigDecimal` — so a field declared as one of
those types can never hold ciphertext directly, no matter what the encryption
scheme is. This is a hard limitation of the JVM's type system, not a choice.

`SecureField<T>` sidesteps it: the *field* is always declared as
`SecureField<Long>`, `SecureField<BigDecimal>`, etc. — that never changes.
Only the *contents* of the wrapper toggle between the typed plaintext value
and an internal ciphertext string:

```java
@Encrypted
private SecureField<BigDecimal> accountBalance;         // constructed via SecureField.ofBigDecimal(...)

accountBalance.get();            // BigDecimal, e.g. 18542.37 — throws if still encrypted
accountBalance.isEncrypted();    // false until encryptFields() runs
```

`String` fields don't need the wrapper — a ciphertext string *is* a valid
`String`, so they keep working exactly as before: ciphertext replaces the
plaintext directly, prefixed with `ENC::` so both operations are idempotent.

### Wire format

`String` fields: `ENC::<base64( 12-byte IV || ciphertext || 16-byte GCM auth tag )>`

`SecureField<T>` fields: the wrapper holds *either* the typed value or the
raw base64 ciphertext (no `ENC::` prefix needed — `SecureField.isEncrypted()`
tracks the state explicitly instead of inferring it from a string prefix).

Both mechanisms are idempotent:
- calling `encryptFields()` twice won't double-encrypt an already-encrypted value
- calling `decryptFields()` on a value that was never encrypted is a no-op

## Requirements

- Java 8+
- Maven 3.6+

## Build & run the demo

```bash
mvn compile
java -cp target/classes com.broadcom.sample.fieldcrypto.example.Demo
```

Sample output:

```
Key (base64, store this securely): 1ftWXbCwXTf+xUfvV81PWe2l1j8SxSyNiU3mmx28Q5U=
Original:  BankCustomer{customerId='C-1001', fullName='Jordan Blake', ssn='123-45-6789', creditCardNumber='4111111111111111', routingNumber='021000021', accountNumber=SecureField{value=400123456789}, accountBalance=SecureField{value=18542.37}, dateOfBirth=SecureField{value=1988-07-14}}
Encrypted: BankCustomer{..., ssn='ENC::...', accountNumber=SecureField{cipherText='...'}, accountBalance=SecureField{cipherText='...'}, dateOfBirth=SecureField{cipherText='...'}}
Decrypted: BankCustomer{customerId='C-1001', fullName='Jordan Blake', ssn='123-45-6789', ..., accountNumber=SecureField{value=400123456789}, accountBalance=SecureField{value=18542.37}, dateOfBirth=SecureField{value=1988-07-14}}
```

## Run the tests

```bash
mvn test
```

39 JUnit 5 tests across seven suites:

**`crypto.AesGcmCipherServiceTest`** — encrypt/decrypt round-trip, random IV per call, null handling, wrong-key and tampered-ciphertext failures, key (de)serialization round-trip, plus a concurrency test that hammers the pooled `Cipher`/`SecureRandom` from 8 threads using a fresh key per iteration to prove no state leaks between threads or keys.

**`api.SecureFieldTest`** — round-trip for every built-in type (`String`, `Integer`, `Long`, `Double`, `Boolean`, `BigInteger`, `BigDecimal`, `LocalDate`, `LocalDateTime`, `UUID`), `get()` throws while encrypted, idempotent `encryptInPlace`, no-op `decryptInPlace` on plaintext, null-value handling.

**`internal.ReflectionFieldEncryptionServiceTest`** — only `@Encrypted` fields are touched, both `String` and `SecureField<T>` fields encrypt/decrypt correctly across all wrapped types, idempotency, null handling, unsupported field type throws `FieldEncryptionException`, null target is a no-op, and that the per-class field scan runs once and is reused (not repeated) across multiple instances of the same class.

**`FieldEncryptionTest`** (the API-consumer perspective — only imports `FieldEncryption` + `api.*`) — end-to-end encrypt/decrypt of a `BankCustomer` across every field type, AES key base64 round-trip, a custom `CipherService` plugged in via `FieldEncryption.using(...)`.

**Performance tests** (one per layer — see below): `crypto.AesGcmCipherServicePerformanceTest`, `internal.ReflectionFieldEncryptionServicePerformanceTest`, `FieldEncryptionPerformanceTest`.

## Performance

Two things dominate the cost of `encryptFields`/`decryptFields` and were optimized without changing behavior:

- **Reflection scan caching.** Which fields on a class are `@Encrypted`, and whether each is a `String` or a `SecureField`, never changes at runtime. `ReflectionFieldEncryptionService` scans a class's fields (`getDeclaredFields()`, annotation check, `setAccessible(true)`) exactly once per class, in a `ConcurrentHashMap<Class<?>, List<...>>`, and reuses that scan for every subsequent instance of the same class. A class whose scan fails (unsupported field type) is *not* cached, so it fails the same way on every call rather than caching a broken result.
- **Cipher/SecureRandom pooling.** `Cipher.getInstance(...)` performs a JCE provider lookup on every call; a shared `SecureRandom` is internally synchronized and becomes a contention point under concurrent encryption. `AesGcmCipherService` now keeps one `Cipher` and one `SecureRandom` per thread (`ThreadLocal`) instead of creating them per call. This is safe because every call fully `init()`s the cipher with a fresh IV immediately before `doFinal()` — no state survives between calls, even across different `AesGcmCipherService` instances (different keys) sharing a thread. Verified under concurrent, multi-key load by the test noted above.

Neither change is visible from the public API — `FieldEncryptionService`/`CipherService` behavior and the `ENC::`/`SecureField` wire formats are unchanged.

### Performance tests

Three tests, one per layer, each warms up (JIT + class-scan cache) then measures a batch of operations and prints throughput to stdout:

| Test | What it measures |
|---|---|
| `crypto.AesGcmCipherServicePerformanceTest#encryptDecryptRoundTrip_sustainsMinimumThroughput` | Single-threaded raw AES-GCM encrypt+decrypt throughput. |
| `crypto.AesGcmCipherServicePerformanceTest#concurrentEncryptDecrypt_sustainsMinimumAggregateThroughput` | Aggregate throughput of one shared `CipherService` driven by `availableProcessors()` threads — validates the `Cipher`/`SecureRandom` pooling actually scales with concurrency rather than serializing on a shared lock. |
| `internal.ReflectionFieldEncryptionServicePerformanceTest#encryptThenDecryptFields_sustainsMinimumThroughputAcrossAllFieldTypes` | Full `encryptFields`+`decryptFields` throughput on `BankCustomer` (6 annotated fields spanning `String`, `Long`, `BigDecimal`, `LocalDate`), plus an assertion that all iterations share one cached field scan. |
| `FieldEncryptionPerformanceTest#aesGcm_sustainsMinimumThroughputForBankCustomer` | The same, but only through the public `FieldEncryption` facade + `api.*` — the path a consuming module actually exercises. |

These are **regression floors, not benchmarks**: each asserts throughput stays above a threshold set far below what any real machine should sustain (verified locally at 280K–475K round-trips/sec for raw AES-GCM and 55K–70K round-trips/sec for full `BankCustomer` round-trips, against floors of 2,000 and 500 respectively). The floors exist to catch a gross regression — e.g. reverting the `Cipher`/`SecureRandom` pooling or the field-scan cache — not to track micro-optimizations. They run as part of `mvn test` like any other test; there's no separate benchmark harness (no JMH) to keep the build simple.

## Using this as a dependency from another module

Install it to your local Maven repository:

```bash
mvn install
```

Then depend on it from another module's `pom.xml`:

```xml
<dependency>
    <groupId>com.broadcom.sample</groupId>
    <artifactId>field-crypto-demo</artifactId>
    <version>1.0.0</version>
</dependency>
```

And consume it through the facade + `api` types only:

```java
import com.broadcom.sample.fieldcrypto.FieldEncryption;
import com.broadcom.sample.fieldcrypto.api.Encrypted;
import com.broadcom.sample.fieldcrypto.api.FieldEncryptionService;
import com.broadcom.sample.fieldcrypto.api.SecureField;

import java.math.BigDecimal;
import java.time.LocalDate;

public class Account {
    private String id;

    @Encrypted
    private String taxId;                       // String - stored/encrypted directly

    @Encrypted
    private SecureField<LocalDate> openedOn;     // any other type - wrapped

    @Encrypted
    private SecureField<BigDecimal> balance;

    public Account(String id, String taxId, LocalDate openedOn, BigDecimal balance) {
        this.id = id;
        this.taxId = taxId;
        this.openedOn = SecureField.ofLocalDate(openedOn);
        this.balance = SecureField.ofBigDecimal(balance);
    }
}

SecretKey key = FieldEncryption.aesKeyFromBase64(loadKeyFromVault()); // don't generate a fresh key each run
FieldEncryptionService encryption = FieldEncryption.aesGcm(key);

encryption.encryptFields(account); // before persisting / sending
// ...
encryption.decryptFields(account); // after loading / receiving
account.balance.get();             // BigDecimal, e.g. 18542.37
```

To use a different cipher (e.g. call out to a cloud KMS instead of doing AES
locally), implement `CipherService` and use `FieldEncryption.using(...)`
instead of `aesGcm(...)` — no other code changes. To support a data type
with no built-in codec (an enum, a domain value object, ...), implement
`ValueCodec<T>` and use `SecureField.of(value, myCodec)`.

## Notes & limitations (this is a sample, not a hardened production library)

- **Key management**: `Demo` generates a throw-away key on every run purely
  for illustration. In production, load the key from a KMS or secrets vault
  and never regenerate it — doing so makes previously-encrypted data
  permanently undecryptable.
- **Field type requirement**: `@Encrypted` supports `String` fields directly,
  and any other type via `SecureField<T>` (see above for why the wrapper is
  necessary). Annotating a plain non-`String` field (e.g. `private Integer
  age;` without the wrapper) throws `FieldEncryptionException` at process
  time.
- **Key rotation** isn't handled here — a real system would need to track
  which key version encrypted each value (e.g. by embedding a key ID
  alongside the ciphertext) to support rotation without re-encrypting
  everything at once.
- **No annotation processor / bytecode weaving**: fields are read via plain
  reflection (`Field.setAccessible(true)`), which is simple but has a
  (typically negligible) performance cost versus generated
  getters/setters — fine for this sample's scale.

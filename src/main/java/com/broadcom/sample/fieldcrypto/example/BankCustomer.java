package com.broadcom.sample.fieldcrypto.example;

import com.broadcom.sample.fieldcrypto.api.Encrypted;
import com.broadcom.sample.fieldcrypto.api.SecureField;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * Bank personal information record demonstrating {@code @Encrypted} across
 * several data types: {@code String} (SSN, routing/card numbers), a boxed
 * numeric type ({@code Long} account number), a monetary type
 * ({@code BigDecimal} balance), and a temporal type ({@code LocalDate} date
 * of birth).
 */
public class BankCustomer {

    private String customerId;
    private String fullName;

    @Encrypted
    private String ssn;

    @Encrypted
    private String creditCardNumber;

    @Encrypted
    private String routingNumber;

    @Encrypted
    private SecureField<Long> accountNumber;

    @Encrypted
    private SecureField<BigDecimal> accountBalance;

    @Encrypted
    private SecureField<LocalDate> dateOfBirth;

    public BankCustomer(String customerId, String fullName, String ssn, String creditCardNumber,
                         String routingNumber, Long accountNumber, BigDecimal accountBalance,
                         LocalDate dateOfBirth) {
        this.customerId = customerId;
        this.fullName = fullName;
        this.ssn = ssn;
        this.creditCardNumber = creditCardNumber;
        this.routingNumber = routingNumber;
        this.accountNumber = SecureField.ofLong(accountNumber);
        this.accountBalance = SecureField.ofBigDecimal(accountBalance);
        this.dateOfBirth = SecureField.ofLocalDate(dateOfBirth);
    }

    public String getCustomerId() {
        return customerId;
    }

    public String getFullName() {
        return fullName;
    }

    public String getSsn() {
        return ssn;
    }

    public String getCreditCardNumber() {
        return creditCardNumber;
    }

    public String getRoutingNumber() {
        return routingNumber;
    }

    public SecureField<Long> getAccountNumberField() {
        return accountNumber;
    }

    public SecureField<BigDecimal> getAccountBalanceField() {
        return accountBalance;
    }

    public SecureField<LocalDate> getDateOfBirthField() {
        return dateOfBirth;
    }

    @Override
    public String toString() {
        return "BankCustomer{customerId='" + customerId + "', fullName='" + fullName
                + "', ssn='" + ssn
                + "', creditCardNumber='" + creditCardNumber
                + "', routingNumber='" + routingNumber
                + "', accountNumber=" + accountNumber
                + ", accountBalance=" + accountBalance
                + ", dateOfBirth=" + dateOfBirth + "}";
    }
}

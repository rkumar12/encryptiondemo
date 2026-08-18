package com.broadcom.sample.fieldcrypto.internal;

import com.broadcom.sample.fieldcrypto.api.Encrypted;

/** Test fixture: misuses @Encrypted on a non-String field to verify the type guard. */
class InvalidCustomer {

    @Encrypted
    private Integer age;

    InvalidCustomer(Integer age) {
        this.age = age;
    }
}

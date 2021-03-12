package com.cybxsecurity.jwt;

/**
 * All supported jwt encryption algorithms.
 * @author Tyler Suehr
 */
public enum EncryptionType {
    AES_CBC("AES/CBC/PKCS7Padding"),
    AES_CTS("AES/CTS/PKCS7Padding"),
    AES_CTR("AES/CTR/NoPadding")
    ;
    private final String algorithm;

    EncryptionType(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return this.algorithm;
    }
}

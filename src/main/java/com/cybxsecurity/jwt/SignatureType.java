package com.cybxsecurity.jwt;

/**
 * All supported jwt signature algorithms.
 * @author Tyler Suehr
 */
public enum SignatureType {
    // Supported MAC algorithms
    HS256("HMAC-SHA256", true),
    HS384("HMAC-SHA384", true),
    HS512("HMAC-SHA512", true),
    HS3_256("HMAC-SHA3-256", true), // not in RFC
    HS3_384("HMAC-SHA3-384", true), // not in RFC
    HS3_512("HMAC-SHA3-512", true), // not in RFC
    // Supported signature algorithms
    EC256("SHA256withECDSA", false),
    EC384("SHA384withECDSA", false),
    EC512("SHA512withECDSA", false),
    RS256("SHA256withRSA", false),
    RS384("SHA384withRSA", false),
    RS512("SHA512withRSA", false),
    PS256("SHA256withRSAandMGF1", false),
    PS384("SHA384withRSAandMGF1", false),
    PS512("SHA512withRSAandMGF1", false)
    ;
    private final String algorithm;
    private final boolean mac;

    SignatureType(String algorithm, boolean mac) {
        this.algorithm = algorithm;
        this.mac = mac;
    }

    @Override
    public String toString() {
        return this.algorithm;
    }

    public boolean isMac() {
        return mac;
    }
}

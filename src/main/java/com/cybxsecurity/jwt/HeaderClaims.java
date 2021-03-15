package com.cybxsecurity.jwt;

/**
 * Represents the restricted claims of a jwt.
 * @author Tyler Suehr
 */
public class HeaderClaims extends Claims {
    static final String SIGNATURE = "sig";
    static final String ENCRYPTION = "enc";
    static final String ISSUER = "iss";
    static final String AUDIENCE = "aud";
    static final String SUBJECT = "sub";
    static final String NOT_BEFORE = "nbf";
    static final String NOT_AFTER = "exp";
    static final String TIMESTAMP = "iat";
    static final String ID = "jti";

    public String getSignature() {
        return (String) get(SIGNATURE);
    }

    public void setSignature(String signature) {
        put(SIGNATURE, signature);
    }

    public String getEncryption() {
        return (String) get(ENCRYPTION);
    }

    public void setEncryption(String encryption) {
        put(ENCRYPTION, encryption);
    }

    public String getIssuer() {
        return (String) get(ISSUER);
    }

    public void setIssuer(String issuer) {
        put(ISSUER, issuer);
    }

    public String getAudience() {
        return (String) get(AUDIENCE);
    }

    public void setAudience(String audience) {
        put(AUDIENCE, audience);
    }

    public String getSubject() {
        return (String) get(SUBJECT);
    }

    public void setSubject(String subject) {
        put(SUBJECT, subject);
    }

    public Long getNotBefore() {
        final Object val = get(NOT_BEFORE);
        if (val instanceof Number) {
            return ((Number) val).longValue();
        }
        return null;
    }

    public void setNotBefore(Long timestampSecs) {
        put(NOT_BEFORE, timestampSecs);
    }

    public Long getNotAfter() {
        final Object val = get(NOT_AFTER);
        if (val instanceof Number) {
            return ((Number) val).longValue();
        }
        return null;
    }

    public void setNotAfter(Long timestampSecs) {
        put(NOT_AFTER, timestampSecs);
    }

    public Long getTimestamp() {
        final Object val = get(TIMESTAMP);
        if (val instanceof Number) {
            return ((Number) val).longValue();
        }
        return null;
    }

    public void setTimestamp(Long timestamp) {
        put(TIMESTAMP, timestamp);
    }

    public String getId() {
        return (String) get(ID);
    }

    public void setId(String jti) {
        put(ID, jti);
    }
}

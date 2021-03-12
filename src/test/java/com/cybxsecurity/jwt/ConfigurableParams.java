package com.cybxsecurity.jwt;

/**
 * @author Tyler Suehr
 */
class ConfigurableParams implements Jwt.Params {
    private String issuer;
    private String audience;
    private String subject;
    private Long notBefore;
    private Long notAfter;
    private boolean generateId;
    private boolean generateIat;
    private EncryptionType encryption;
    private SignatureType signature = SignatureType.HS256;

    @Override
    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    @Override
    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    @Override
    public Long getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Long notBefore) {
        this.notBefore = notBefore;
    }

    @Override
    public Long getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Long notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public boolean isGenerateId() {
        return generateId;
    }

    public void setGenerateId(boolean generateId) {
        this.generateId = generateId;
    }

    @Override
    public boolean isGenerateIat() {
        return generateIat;
    }

    public void setGenerateIat(boolean generateIat) {
        this.generateIat = generateIat;
    }

    @Override
    public EncryptionType getEncryption() {
        return encryption;
    }

    public void setEncryption(EncryptionType encryption) {
        this.encryption = encryption;
    }

    @Override
    public SignatureType getSignature() {
        return signature;
    }

    public void setSignature(SignatureType signature) {
        this.signature = signature;
    }
}

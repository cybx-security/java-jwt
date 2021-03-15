package com.cybxsecurity.jwt;

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a JSON Web Token.
 * @author Tyler Suehr
 */
public class Jwt {
    static final Base64.Encoder ENCODER = Base64.getUrlEncoder();
    static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    static final Gson GSON = new Gson();

    private final Claims payload = new Claims();
    private final HeaderClaims header = new HeaderClaims();
    private Params params;

    private Unverified unverified;
    private byte[] encryptedPayload;

    /**
     * Checks if this jwt has been verified.
     * @return true if verified, otherwise false
     */
    public boolean isNotVerified() {
        return this.unverified != null;
    }

    /**
     * Checks if this jwt has encrypted payload.
     * @return true if encrypted, otherwise false
     */
    public boolean isEncrypted() {
        return this.encryptedPayload != null;
    }

    /**
     * Gets the payload claims of this jwt.
     * @return the claims
     */
    public Claims getPayloadClaims() {
        if (isEncrypted())
            throw new IllegalStateException("Payload is encrypted!");
        if (isNotVerified())
            System.out.println("WARNING: Accessing unverified jwt payload!");
        return this.payload;
    }

    /**
     * Gets the header claims of this jwt.
     * @return the claims
     */
    public HeaderClaims getHeaderClaims() {
        if (isNotVerified())
            System.out.println("WARNING: Accessing unverified jwt header!");
        return this.header;
    }

    /**
     * Gets the configurable parameters of this jwt.
     * @return the parameters
     */
    public Params getParameters() {
        return params;
    }

    /**
     * Sets the configurable parameters of this jwt.
     * @param params the parameters
     */
    public void setParameters(Params params) {
        this.params = params;
    }

    /**
     * Creates a signed jwt string.
     *
     * @param signKey the key to sign jwt with
     * @return the jwt
     */
    public String compact(Key signKey) {
        return compact(signKey, null);
    }

    /**
     * Encrypts payload claims and creates signed jwt string.
     *
     * @param signKey the key to sign jwt with
     * @param encryptKey the key to encrypt payload with
     * @return the jwt
     */
    public String compact(Key signKey, Key encryptKey) {
        final SnapshotParams sp = snapshotParams(this.params);

        // Process the header claims of the token
        final String headerJsonStr = GSON.toJson(this.header);
        final byte[] headerJsonUtf8 = headerJsonStr.getBytes(StandardCharsets.UTF_8);
        final String encodedHeader = ENCODER.encodeToString(headerJsonUtf8);

        // Process the payload claims of the token
        final String payloadJsonStr = GSON.toJson(this.payload);
        final byte[] payloadJsonUtf8 = payloadJsonStr.getBytes(StandardCharsets.UTF_8);
        final String encodedPayload;
        if (encryptKey != null) {
            Objects.requireNonNull(sp.encryption, "An encryption key was given but no algorithm was configured!");
            final byte[] encrypted = Crypto.encrypt(sp.encryption, encryptKey, payloadJsonUtf8);
            encodedPayload = ENCODER.encodeToString(encrypted);
        } else {
            encodedPayload = ENCODER.encodeToString(payloadJsonUtf8);
        }

        // Compute the signature
        final byte[] contentUtf8 = (encodedHeader + '.' + encodedPayload).getBytes(StandardCharsets.UTF_8);
        final byte[] signature = Crypto.sign(sp.signature, signKey, contentUtf8);
        final String encodedSignature = ENCODER.encodeToString(signature);

        return encodedHeader + '.' + encodedPayload + '.' + encodedSignature;
    }

    /**
     * Parses a jwt-formatted string value.
     * @param jwtStr the jwt
     */
    public void parse(String jwtStr) {
        // Split the 3 jwt segments
        final String[] segments = jwtStr.split("\\.");
        if (segments.length != 3)
            throw new IllegalStateException("Malformed jwt!");

        final String encodedHeader = segments[0];
        final String encodedPayload = segments[1];
        final String encodedSignature = segments[2];

        // Convert the encoded header to claims
        final byte[] headerJsonUtf8 = DECODER.decode(encodedHeader);
        final String headerJsonStr = new String(headerJsonUtf8, StandardCharsets.UTF_8);
        this.header.clear();
        this.header.putAll(GSON.fromJson(headerJsonStr, HeaderClaims.class));

        // Convert the encoded payload to claims
        final byte[] payloadBytes = DECODER.decode(encodedPayload);
        if (this.header.containsKey(HeaderClaims.ENCRYPTION)) {
            this.encryptedPayload = payloadBytes;
        } else {
            final String payloadJsonStr = new String(payloadBytes, StandardCharsets.UTF_8);
            this.payload.clear();
            this.payload.putAll(GSON.fromJson(payloadJsonStr, Claims.class));
        }

        // Create the unverified object
        final byte[] content = (encodedHeader + '.' + encodedPayload).getBytes(StandardCharsets.UTF_8);
        final byte[] signature = DECODER.decode(encodedSignature);
        this.unverified = new Unverified(content, signature);
    }

    /**
     * Decrypts the encrypted payload claims of this jwt.
     * @param decryptKey the key to decrypt claims with
     */
    public void decrypt(Key decryptKey) {
        if (isEncrypted()) {
            final EncryptionType algorithm = readEncryption(this.header);
            if (algorithm != null) {
                final byte[] payloadJsonUtf8 = Crypto.decrypt(algorithm, decryptKey, this.encryptedPayload);
                final String payloadJsonStr = new String(payloadJsonUtf8, StandardCharsets.UTF_8);
                this.payload.clear();
                this.payload.putAll(GSON.fromJson(payloadJsonStr, Claims.class));
                this.encryptedPayload = null;
            }
        }
    }

    /**
     * Verifies the integrity of this jwt.
     * @param verifyKey the key to verify claims with
     *
     * @throws JwtSignatureException if signature was not verified
     * @throws JwtClaimException if configured claim was invalid
     * @throws JwtExpirationException if used before the not before timestamp
     * @throws JwtExpirationException if used after the not after timestamp
     */
    public void verify(Key verifyKey) {
        if (isNotVerified()) {
            // Verify the signature firstly
            final SignatureType algorithm = readSignature(this.header);
            if (!Crypto.verify(algorithm, verifyKey, unverified.content, unverified.signature))
                throw new JwtSignatureException();

            // Verifies all other configured parameters
            final Params p = this.params;
            if (p != null) {
                final String issuer = p.getIssuer();
                if (issuer != null && !issuer.equals(this.header.getIssuer()))
                    throw new JwtClaimException("issuer");
                final String audience = p.getAudience();
                if (audience != null && !audience.equals(this.header.getAudience()))
                    throw new JwtClaimException("audience");
                final String subject = p.getSubject();
                if (subject != null && !subject.equals(this.header.getSubject()))
                    throw new JwtClaimException("subject");
                final Long tokenNotBefore = this.header.getNotBefore();
                if (tokenNotBefore != null) {
                    final long nowSecs = System.currentTimeMillis() / 1000L;
                    if (nowSecs < tokenNotBefore)
                        throw JwtExpirationException.notBefore(tokenNotBefore);
                }
                final Long tokenNotAfter = this.header.getNotAfter();
                if (tokenNotAfter != null) {
                    final long nowSecs = System.currentTimeMillis() / 1000L;
                    if (nowSecs > tokenNotAfter)
                        throw JwtExpirationException.notAfter(tokenNotAfter);
                }
            }

            this.unverified = null;
        }
    }

    /**
     * Puts configured parameters into jwt header claims.
     * Returns typed signature and encryption algorithms.
     *
     * @param p the configured parameters
     * @return the snapshot algorithms
     */
    SnapshotParams snapshotParams(Params p) {
        if (p == null) {
            return new SnapshotParams(SignatureType.HS256, null);
        } else {
            final SignatureType signature = p.getSignature();
            if (signature != null)
                this.header.setSignature(signature.name());
            final EncryptionType encryption = p.getEncryption();
            if (encryption != null)
                this.header.setEncryption(encryption.name());
            final String issuer = p.getIssuer();
            if (issuer != null)
                this.header.setIssuer(issuer);
            final String audience = p.getAudience();
            if (audience != null)
                this.header.setAudience(audience);
            final String subject = p.getSubject();
            if (subject != null)
                this.header.setSubject(subject);
            final Long notBeforeSecs = p.getNotBefore();
            if (notBeforeSecs != null) {
                final long nowSecs = System.currentTimeMillis() / 1000L;
                this.header.setNotBefore(nowSecs + notBeforeSecs);
            }
            final Long notAfterSecs = p.getNotAfter();
            if (notAfterSecs != null) {
                final long nowSecs = System.currentTimeMillis() / 1000L;
                this.header.setNotAfter(nowSecs + notAfterSecs);
            }
            if (p.isGenerateIat()) {
                final long nowSecs = System.currentTimeMillis() / 1000L;
                this.header.setTimestamp(nowSecs);
            }
            if (p.isGenerateId()) {
                final String jti = UUID.randomUUID().toString();
                this.header.setId(jti);
            }
            return new SnapshotParams(signature, encryption);
        }
    }

    SignatureType readSignature(HeaderClaims claims) {
        final String algorithm = claims.getSignature();
        if (algorithm == null)
            throw new IllegalStateException("No signature algorithm is not supported!");
        return SignatureType.valueOf(algorithm);
    }

    EncryptionType readEncryption(HeaderClaims claims) {
        final String algorithm = claims.getEncryption();
        return algorithm == null ? null : EncryptionType.valueOf(algorithm);
    }

    /**
     * Defines configurable parameters for a jwt.
     */
    public interface Params {
        default SignatureType getSignature() { return SignatureType.HS256; }
        default EncryptionType getEncryption() { return null; }
        default String getIssuer() { return null; }
        default String getAudience() { return null; }
        default String getSubject() { return null; }
        default Long getNotBefore() { return null; }
        default Long getNotAfter() { return null; }
        default boolean isGenerateId() { return false; }
        default boolean isGenerateIat() { return false; }
    }

    /**
     * Structure holding unverified data.
     */
    static class Unverified {
        final byte[] content;
        final byte[] signature;

        Unverified(byte[] c, byte[] s) {
            this.content = c;
            this.signature = s;
        }
    }

    /**
     * Contains a snapshot of configured parameters.
     */
    static class SnapshotParams {
        final SignatureType signature;
        final EncryptionType encryption;

        SnapshotParams(SignatureType s, EncryptionType e) {
            this.signature = s;
            this.encryption = e;
        }
    }
}

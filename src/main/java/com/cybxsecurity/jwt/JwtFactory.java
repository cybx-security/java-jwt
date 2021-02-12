/*
 * Copyright (c) 2021 CybXSecurity LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cybxsecurity.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * A factory for producing and parsing json web tokens.
 * @author Tyler Suehr
 */
public final class JwtFactory {
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private JwtFactoryParams mParams;

    /**
     * Gets the parameters of this factory.
     * @return the params
     */
    public JwtFactoryParams getParams() {
        return mParams;
    }

    /**
     * Sets the parameters of this factory.
     * @param params the params
     */
    public void setParams(JwtFactoryParams params) {
        mParams = params;
    }

    /**
     * Creates, signs, and encodes a jwt.
     *
     * @param header the header claims
     * @param payload the payload claims
     * @param signKey the key to sign the claims
     *
     * @return the jwt
     */
    public String create(JwtHeaderClaims header, JwtClaims payload, Key signKey) {
        return create(header, payload, signKey, null);
    }

    /**
     * Creates, signs, encrypts the payload, and encodes a jwt.
     *
     * @param header the header claims
     * @param payload the payload claims
     * @param signKey the key to sign the claims
     * @param encryptKey the key to encrypt the payload
     *
     * @return the encrypted jwt
     */
    public String create(JwtHeaderClaims header, JwtClaims payload, Key signKey, Key encryptKey) {
        addConfiguredHeaders(header);

        // Convert header and payload to json UTF8 bytes
        final byte[] headerBytes = header.toJsonStringBytes();
        byte[] payloadBytes = payload.toJsonStringBytes();

        // If an encryption algorithm was configured, then encrypt the payload
        final JwtEncryption encAlg = getEncryptionAlg();
        if (encAlg != null) {
            Objects.requireNonNull(encryptKey, "Please specify an encryption key!");
            payloadBytes = JwtCrypto.encrypt(encAlg, encryptKey, payloadBytes);
        }

        // Encode the header and payload with Base64 URL-safe
        final String encodedHeader = ENCODER.encodeToString(headerBytes);
        final String encodedPayload = ENCODER.encodeToString(payloadBytes);

        // Create the content segment and sign it
        // Encode the signature with Base64 URL-safe
        final byte[] contentBytes = (encodedHeader + '.' + encodedPayload).getBytes(StandardCharsets.UTF_8);
        final byte[] signature = JwtCrypto.sign(getSignatureAlg(), signKey, contentBytes);
        final String encodedSignature = ENCODER.encodeToString(signature);

        return encodedHeader + '.' + encodedPayload + '.' + encodedSignature;
    }

    /**
     * Parses an encoded jwt string value.
     *
     * @param encoded the jwt
     * @return the unverified claims
     */
    public UnverifiedClaims parse(String encoded) {
        return parse(encoded, null);
    }

    /**
     * Parses an encrypted encoded jwt string value.
     *
     * @param encoded the jwt
     * @param decryptKey the key to decrypt payload
     * @return the unverified claims
     */
    public UnverifiedClaims parse(String encoded, Key decryptKey) {
        // Parse the 3 token segments (signatures are required)
        final String[] segments = encoded.split("\\.");
        if (segments.length != 3)
            throw new IllegalArgumentException("Malformed jwt!");

        final String encodedHeader = segments[0];
        final String encodedPayload = segments[1];
        final String encodedSignature = segments[2];

        // Decode the signature segment
        // Create the 'unverified' segment that signature can verify
        final byte[] signature = DECODER.decode(encodedSignature);
        final byte[] unverified = (encodedHeader + '.' + encodedPayload).getBytes(StandardCharsets.UTF_8);

        // Decode the header and payload segments to a json string value
        final String decodedHeader = new String(DECODER.decode(encodedHeader), StandardCharsets.UTF_8);
        final String decodedPayload;

        // If an encryption algorithm was configured, then decrypt the payload
        final JwtEncryption encAlg = getEncryptionAlg();
        if (encAlg != null) {
            Objects.requireNonNull(decryptKey, "Please specify a decryption key!");
            final byte[] encryptedPayload = DECODER.decode(encodedPayload);
            final byte[] payloadBytes = JwtCrypto.decrypt(encAlg, decryptKey, encryptedPayload);
            decodedPayload = new String(payloadBytes, StandardCharsets.UTF_8);
        } else {
            decodedPayload = new String(DECODER.decode(encodedPayload), StandardCharsets.UTF_8);
        }

        // Create the unverified claims object
        final UnverifiedClaims claims = new UnverifiedClaims();
        claims.setHeaderClaims(JwtClaims.fromJsonString(decodedHeader, JwtHeaderClaims.class));
        claims.setPayloadClaims(JwtClaims.fromJsonString(decodedPayload, JwtClaims.class));
        claims.setSignature(signature);
        claims.setUnverified(unverified);
        return claims;
    }

    /**
     * Verifies signature and validates unverified claims.
     *
     * @param claims the claims to be verified and validated
     * @param verifyKey the key to verify the claims
     */
    public void verify(UnverifiedClaims claims, Key verifyKey) {
        final byte[] unverified = claims.getUnverified();
        final byte[] signature = claims.getSignature();
        if (!JwtCrypto.verify(getSignatureAlg(), verifyKey, unverified, signature))
            throw new JwtSignatureException();
        validateConfiguredHeaders(claims.getHeaderClaims());
    }

    /**
     * Gets the configured signature algorithm.
     * @return the signature algorithm (or default if none)
     */
    private JwtSignature getSignatureAlg() {
        final JwtFactoryParams params = mParams;
        final JwtSignature alg = params == null ? null : params.getSignature();
        return alg == null ? JwtSignature.HS256 : alg;
    }

    /**
     * Gets the configured encryption algorithm.
     * @return the encryption algorithm (or null if none)
     */
    private JwtEncryption getEncryptionAlg() {
        final JwtFactoryParams params = mParams;
        return params == null ? null : params.getEncryption();
    }

    /**
     * Adds all configured headers into the claims.
     * @param claims the claims to be inserted into
     */
    private void addConfiguredHeaders(JwtHeaderClaims claims) {
        final JwtFactoryParams params = mParams;
        if (params != null) {
            // Add a configured issuer
            final String issuer = params.getIssuer();
            if (issuer != null)
                claims.setIssuer(issuer);

            // Add a configured audience
            final String audience = params.getAudience();
            if (audience != null)
                claims.setAudience(audience);

            // Add a configured subject
            final String subject = params.getSubject();
            if (subject != null)
                claims.setSubject(subject);

            // Add a configured expiration timestamp
            final long notAfterSecs = params.getNotAfter();
            if (notAfterSecs > 0L)
                claims.getExpiration().setFutureSecs(notAfterSecs);

            // Add a configured not before timestamp
            final long notBeforeSecs = params.getNotBefore();
            if (notBeforeSecs <= 0L)
                claims.getNotBefore().setPastSecs(notBeforeSecs);

            // Generate and add a uuid if specified
            if (params.isGenerateId())
                claims.setId(UUID.randomUUID().toString());
        }
    }

    /**
     * Validates header claims against configured parameters.
     * @param claims the claims to be validated
     */
    private void validateConfiguredHeaders(JwtHeaderClaims claims) {
        final JwtFactoryParams params = mParams;
        if (params != null) {
            // Validate the issuer
            final String issuer = params.getIssuer();
            if (issuer != null && !issuer.equals(claims.getIssuer()))
                throw new JwtClaimException("issuer");

            // Validate the audience
            final String audience = params.getAudience();
            if (audience != null && !audience.equals(claims.getAudience()))
                throw new JwtClaimException("audience");

            // Validate the subject
            final String subject = params.getSubject();
            if (subject != null && !subject.equals(claims.getSubject()))
                throw new JwtClaimException("subject");

            // Validate the expiration timestamp
            if (params.getNotAfter() > 0L) {
                final long expiration = claims.getExpiration().get();
                final long nowSecs = System.currentTimeMillis() / 1000L;
                if (nowSecs > expiration)
                    throw new JwtExpirationException(expiration);
            }

            // Validate the not before timestamp
            if (params.getNotBefore() <= 0L) {
                final long notBefore = claims.getNotBefore().get();
                final long nowSecs = System.currentTimeMillis() / 1000L;
                if (nowSecs < notBefore)
                    throw new JwtClaimException("not before");
            }

            // Validate an id exists if allowed
            if (params.isGenerateId() && claims.getId() == null)
                throw new JwtClaimException("jwt id");
        }
    }
}

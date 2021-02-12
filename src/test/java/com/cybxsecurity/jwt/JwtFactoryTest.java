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

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link JwtFactory}.
 * @author Tyler Suehr
 */
class JwtFactoryTest {
    static final SecretKey signKey = new SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC");
    static final SecretKey cryptKey = new SecretKeySpec(Hex.decode("00112233445566778899AABBCCDDEEFF"), "AES");

    @Test
    void getParams() {
        final JwtFactoryParams params = new InMemParams();
        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);
        assertEquals(params, factory.getParams());
    }

    @Test
    void createParseVerifyNotEncrypted() {
        final JwtHeaderClaims header = new JwtHeaderClaims();
        header.setIssuer("Something");
        header.put("custom", "abc");

        final JwtClaims payload = new JwtClaims();
        payload.put("customA", 1234);
        payload.put("customB", "abc");

        final JwtFactory factory = new JwtFactory();

        final String jwt = factory.create(header, payload, signKey, null);
        assertNotNull(jwt);
        System.out.printf("JWT: %s\n", jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);
        System.out.printf("Unverified: %s\n", unverified);

        factory.verify(unverified, signKey);
    }

    @Test
    void createParseVerifyEncrypted() {
        final InMemParams params = new InMemParams();
        params.setEncryption(JwtEncryption.AES_CTS);

        final JwtHeaderClaims header = new JwtHeaderClaims();
        header.setIssuer("Something");
        header.put("custom", "abc");

        final JwtClaims payload = new JwtClaims();
        payload.put("customA", 1234);
        payload.put("customB", "abc");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(header, payload, signKey, cryptKey);
        assertNotNull(jwt);
        System.out.printf("JWT: %s\n", jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, cryptKey);
        assertNotNull(unverified);
        System.out.printf("Unverified: %s\n", unverified);

        factory.verify(unverified, signKey);
    }

    @Test
    void parseInvalidIssuer() {
        final InMemParams params = new InMemParams();
        params.setIssuer("Something");

        final JwtClaims payload = new JwtClaims();
        payload.put("a", "ab");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(new JwtHeaderClaims(), payload, signKey, null);
        assertNotNull(jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);

        params.setIssuer("something different");
        assertThrows(JwtClaimException.class, () -> factory.verify(unverified, signKey));
    }

    @Test
    void parseInvalidAudience() {
        final InMemParams params = new InMemParams();
        params.setAudience("Something");

        final JwtClaims payload = new JwtClaims();
        payload.put("a", "ab");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(new JwtHeaderClaims(), payload, signKey, null);
        assertNotNull(jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);

        params.setAudience("something different");
        assertThrows(JwtClaimException.class, () -> factory.verify(unverified, signKey));
    }

    @Test
    void parseInvalidSubject() {
        final InMemParams params = new InMemParams();
        params.setSubject("Something");

        final JwtClaims payload = new JwtClaims();
        payload.put("a", "ab");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(new JwtHeaderClaims(), payload, signKey, null);
        assertNotNull(jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);

        params.setSubject("something different");
        assertThrows(JwtClaimException.class, () -> factory.verify(unverified, signKey));
    }

    @Test
    void parseInvalidNotBefore() {
        final InMemParams params = new InMemParams();
        params.setNotBefore(-1000); // puts not before into the future

        final JwtClaims payload = new JwtClaims();
        payload.put("a", "ab");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(new JwtHeaderClaims(), payload, signKey, null);
        assertNotNull(jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);

        assertThrows(JwtClaimException.class, () -> factory.verify(unverified, signKey));
    }

    @Test
    void parseInvalidNotAfter() throws InterruptedException {
        final InMemParams params = new InMemParams();
        params.setNotAfter(1); // puts not after into the past

        final JwtClaims payload = new JwtClaims();
        payload.put("a", "ab");

        final JwtFactory factory = new JwtFactory();
        factory.setParams(params);

        final String jwt = factory.create(new JwtHeaderClaims(), payload, signKey, null);
        assertNotNull(jwt);

        final UnverifiedClaims unverified = factory.parse(jwt, null);
        assertNotNull(unverified);

        factory.verify(unverified, signKey);
        Thread.sleep(2000);
        assertThrows(JwtExpirationException.class, () -> factory.verify(unverified, signKey));
    }



    static class InMemParams implements JwtFactoryParams {
        private String mIssuer;
        private String mAudience;
        private String mSubject;
        private JwtSignature mSignature;
        private JwtEncryption mEncryption;
        private long mNotBefore;
        private long mNotAfter;
        private boolean mGenerateId;

        @Override
        public String getIssuer() {
            return mIssuer;
        }

        public void setIssuer(String issuer) {
            mIssuer = issuer;
        }

        @Override
        public String getAudience() {
            return mAudience;
        }

        public void setAudience(String audience) {
            mAudience = audience;
        }

        @Override
        public String getSubject() {
            return mSubject;
        }

        public void setSubject(String subject) {
            mSubject = subject;
        }

        @Override
        public JwtSignature getSignature() {
            return mSignature;
        }

        public void setSignature(JwtSignature signature) {
            mSignature = signature;
        }

        @Override
        public JwtEncryption getEncryption() {
            return mEncryption;
        }

        public void setEncryption(JwtEncryption encryption) {
            mEncryption = encryption;
        }

        @Override
        public long getNotBefore() {
            return mNotBefore;
        }

        public void setNotBefore(long notBefore) {
            mNotBefore = notBefore;
        }

        @Override
        public long getNotAfter() {
            return mNotAfter;
        }

        public void setNotAfter(long notAfter) {
            mNotAfter = notAfter;
        }

        @Override
        public boolean isGenerateId() {
            return mGenerateId;
        }

        public void setGenerateId(boolean generateId) {
            mGenerateId = generateId;
        }
    }
}
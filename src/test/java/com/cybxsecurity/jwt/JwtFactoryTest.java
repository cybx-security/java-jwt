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
        final JwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
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
}
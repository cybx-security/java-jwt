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

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the {@link JwtHeaderClaims}.
 * @author Tyler Suehr
 */
class JwtHeaderClaimsTest {
    @Test
    void getType() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setType(expected);
        assertEquals(expected, claims.getType());
    }

    @Test
    void getContentType() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setContentType(expected);
        assertEquals(expected, claims.getContentType());
    }

    @Test
    void getIssuer() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setIssuer(expected);
        assertEquals(expected, claims.getIssuer());
    }

    @Test
    void getSubject() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setSubject(expected);
        assertEquals(expected, claims.getSubject());
    }

    @Test
    void getAudience() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setAudience(expected);
        assertEquals(expected, claims.getAudience());
    }

    @Test
    void getExpiration() {
        final long expected = System.currentTimeMillis() / 1000L;
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.getExpiration().set(expected);
        assertEquals(expected, claims.getExpiration().get());
    }

    @Test
    void getNotBefore() {
        final long expected = System.currentTimeMillis() / 1000L;
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.getNotBefore().set(expected);
        assertEquals(expected, claims.getNotBefore().get());
    }

    @Test
    void getIssuedAt() {
        final long expected = System.currentTimeMillis() / 1000L;
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.getIssuedAt().set(expected);
        assertEquals(expected, claims.getIssuedAt().get());
    }

    @Test
    void getId() {
        final String expected = UUID.randomUUID().toString();
        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setId(expected);
        assertEquals(expected, claims.getId());
    }
}

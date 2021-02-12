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

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link UnverifiedClaims}.
 * @author Tyler Suehr
 */
class UnverifiedClaimsTest {
    @Test
    void getHeaderClaims() {
        final JwtHeaderClaims expected = new JwtHeaderClaims();
        final UnverifiedClaims claims = new UnverifiedClaims();
        claims.setHeaderClaims(expected);
        assertEquals(expected, claims.getHeaderClaims());
    }

    @Test
    void getPayloadClaims() {
        final JwtClaims expected = new JwtClaims();
        final UnverifiedClaims claims = new UnverifiedClaims();
        claims.setPayloadClaims(expected);
        assertEquals(expected, claims.getPayloadClaims());
    }

    @Test
    void getUnverified() {
        final byte[] expected = new byte[128];
        new Random().nextBytes(expected);

        final UnverifiedClaims claims = new UnverifiedClaims();
        claims.setUnverified(expected);

        assertArrayEquals(expected, claims.getUnverified());
    }

    @Test
    void getSignature() {
        final byte[] expected = new byte[512];
        new Random().nextBytes(expected);

        final UnverifiedClaims claims = new UnverifiedClaims();
        claims.setSignature(expected);

        assertArrayEquals(expected, claims.getSignature());
    }
}
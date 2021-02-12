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

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the {@link JwtClaims}.
 * @author Tyler Suehr
 */
class JwtClaimsTest {
    @Test
    void toJsonString() {
        final String expected = "{\"custom\":43,\"iss\":\"Tester\"}";

        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setIssuer("Tester");
        claims.put("custom", (int) 43);

        final String result = claims.toJsonString();
        assertNotNull(result);

        System.out.printf("Expected: %s\n", expected);
        System.out.printf("Result:   %s\n", result);

        assertEquals(expected, result);
    }

    @Test
    void toJsonStringBytes() {
        final String expected = "{\"custom\":43,\"iss\":\"Tester\"}";
        final byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        System.out.printf("(%d bytes) Expected: %s\n", expectedBytes.length, Hex.toHexString(expectedBytes));

        final JwtHeaderClaims claims = new JwtHeaderClaims();
        claims.setIssuer("Tester");
        claims.put("custom", (int) 43);

        final byte[] result = claims.toJsonStringBytes();
        assertNotNull(result);
        System.out.printf("(%d bytes) Result:   %s\n", result.length, Hex.toHexString(result));

        assertArrayEquals(expectedBytes, result);
    }

    @Test
    void fromJsonString() {
        final String expected = "{\"custom\":43,\"iss\":\"Tester\"}";
        final JwtHeaderClaims claims = JwtClaims.fromJsonString(expected, JwtHeaderClaims.class);
        assertNotNull(claims);
        assertEquals(43, ((Number) claims.get("custom")).intValue());
        assertEquals("Tester", claims.getIssuer());
    }
}

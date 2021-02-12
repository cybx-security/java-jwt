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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link ConfigurableJwtFactoryParams}.
 * @author Tyler Suehr
 */
class ConfigurableJwtFactoryParamsTest {
    @Test
    void getSignature() {
        final JwtSignature expected = JwtSignature.EC256;
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setSignature(expected);
        assertEquals(expected, params.getSignature());
    }

    @Test
    void getEncryption() {
        final JwtEncryption expected = JwtEncryption.AES_CBC;
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setEncryption(expected);
        assertEquals(expected, params.getEncryption());
    }

    @Test
    void getIssuer() {
        final String expected = UUID.randomUUID().toString();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setIssuer(expected);
        assertEquals(expected, params.getIssuer());
    }

    @Test
    void getAudience() {
        final String expected = UUID.randomUUID().toString();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setAudience(expected);
        assertEquals(expected, params.getAudience());
    }

    @Test
    void getSubject() {
        final String expected = UUID.randomUUID().toString();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setSubject(expected);
        assertEquals(expected, params.getSubject());
    }

    @Test
    void getNotAfter() {
        final long expected = System.currentTimeMillis();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setNotAfter(expected);
        assertEquals(expected, params.getNotAfter());
    }

    @Test
    void getNotBefore() {
        final long expected = System.currentTimeMillis();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setNotBefore(expected);
        assertEquals(expected, params.getNotBefore());
    }

    @Test
    void isGenerateId() {
        final boolean expected = new Random().nextBoolean();
        final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
        params.setGenerateId(expected);
        assertEquals(expected, params.isGenerateId());
    }
}
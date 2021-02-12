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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Signature;

/**
 * Unit tests for the supported algorithms.
 * @author Tyler Suehr
 */
class JwtAlgorithmTest {
    @Test
    void testSupportedEncryption() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        for (JwtEncryption c : JwtEncryption.values())
            Cipher.getInstance(c.toString(), BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    void testSupportedSignature() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());
        for (JwtSignature s : JwtSignature.values()) {
            final String algorithm = s.toString();
            if (algorithm.contains("HMAC") || algorithm.contains("HS"))
                Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            else
                Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}

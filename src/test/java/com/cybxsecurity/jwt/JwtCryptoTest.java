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

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link JwtCrypto}.
 * @author Tyler Suehr
 */
class JwtCryptoTest {
    @Test
    void testSignVerify() {
        final byte[] contentBytes = "Hello world\n".getBytes();

        final Key key = new SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC");
        final JwtSignature alg = JwtSignature.HS3_256;

        final byte[] signature = JwtCrypto.sign(alg, key, contentBytes);
        assertNotNull(signature);
        assertFalse(Arrays.equals(contentBytes, signature));
        assertTrue(JwtCrypto.verify(alg, key, contentBytes, signature));

        System.out.printf("(%d bytes) Content:   %s\n", contentBytes.length, Hex.toHexString(contentBytes));
        System.out.printf("(%d bytes) Signature: %s\n", signature.length, Hex.toHexString(signature));
    }

    @Test
    void testSignVerifyTampered() {
        final byte[] contentBytes = "Hello world\n".getBytes();

        final Key key = new SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC");
        final JwtSignature alg = JwtSignature.HS3_256;

        final byte[] signature = JwtCrypto.sign(alg, key, contentBytes);
        assertNotNull(signature);
        assertFalse(Arrays.equals(contentBytes, signature));

        contentBytes[2] ^= 1; // tamper the content
        assertFalse(JwtCrypto.verify(alg, key, contentBytes, signature));
    }

    @Test
    void testEncryptDecrypt() {
        final byte[] contentBytes = "Hello world\n".getBytes();

        final Key key = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
        final JwtEncryption alg = JwtEncryption.AES_CTR;

        final byte[] encrypted = JwtCrypto.encrypt(alg, key, contentBytes);
        assertNotNull(encrypted);
        assertFalse(Arrays.equals(contentBytes, encrypted));

        final byte[] decrypted = JwtCrypto.decrypt(alg, key, encrypted);
        assertNotNull(decrypted);
        assertTrue(Arrays.equals(contentBytes, decrypted));

        System.out.printf("(%d bytes) Plaintext:  %s\n", contentBytes.length, Hex.toHexString(contentBytes));
        System.out.printf("(%d bytes) Ciphertext: %s\n", encrypted.length, Hex.toHexString(encrypted));
    }

    @Test
    void testRandomIv() {
        final byte[] iv = JwtCrypto.generateRandomIv();
        assertNotNull(iv);
        assertEquals(JwtCrypto.IV_LENGTH, iv.length);
        System.out.printf("(%d bytes) IV: %s\n", iv.length, Hex.toHexString(iv));
    }
}
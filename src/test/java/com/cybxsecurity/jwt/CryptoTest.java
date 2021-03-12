package com.cybxsecurity.jwt;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link Crypto}.
 * @author Tyler Suehr
 */
class CryptoTest {
    @Test
    void testSignVerify() {
        final Key signKey = new SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC");
        final byte[] contentBytes = "Hello world!\n".getBytes();
        final SignatureType type = SignatureType.HS256;

        final byte[] signature = Crypto.sign(type, signKey, contentBytes);
        assertNotNull(signature);
        assertTrue(Crypto.verify(type, signKey, contentBytes, signature));

        System.out.printf("Plaintext: %s\n", Hex.toHexString(contentBytes));
        System.out.printf("Signature: %s\n", Hex.toHexString(signature));
    }

    @Test
    void testEncryptDecrypt() {
        final Key encryptKey = new SecretKeySpec(Hex.decode("00112233445566778899AABBCCDDEEFF"), "AES");
        final byte[] contentBytes = "Hello world!\n".getBytes();
        final EncryptionType type = EncryptionType.AES_CTR;

        final byte[] encrypted = Crypto.encrypt(type, encryptKey, contentBytes);
        assertNotNull(encrypted);

        final byte[] decrypted = Crypto.decrypt(type, encryptKey, encrypted);
        assertNotNull(decrypted);
        assertArrayEquals(contentBytes, decrypted);

        System.out.printf("Plaintext: %s\n", Hex.toHexString(contentBytes));
        System.out.printf("Encrypted: %s\n", Hex.toHexString(encrypted));
    }

    @Test
    void generateRandomIv() {
        final byte[] iv = Crypto.generateRandomIv();
        assertEquals(iv.length, Crypto.IV_LENGTH);
    }
}
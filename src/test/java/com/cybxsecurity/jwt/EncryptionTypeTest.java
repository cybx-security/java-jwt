package com.cybxsecurity.jwt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.Security;

/**
 * Unit tests for the {@link EncryptionType}.
 * @author Tyler Suehr
 */
class EncryptionTypeTest {
    @Test
    void testAllAlgorithms() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        for (EncryptionType e : EncryptionType.values()) {
            Cipher.getInstance(e.toString(), BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}
package com.cybxsecurity.jwt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import java.security.Security;
import java.security.Signature;

/**
 * Unit tests for the {@link SignatureType}.
 * @author Tyler Suehr
 */
class SignatureTypeTest {
    @Test
    void testAllAlgorithms() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        for (SignatureType s : SignatureType.values()) {
            if (s.isMac())
                Mac.getInstance(s.toString(), BouncyCastleProvider.PROVIDER_NAME);
            else
                Signature.getInstance(s.toString(), BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}
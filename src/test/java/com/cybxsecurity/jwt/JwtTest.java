package com.cybxsecurity.jwt;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the {@link Jwt}.
 * @author Tyler Suehr
 */
class JwtTest {
    static final Key signKey = new SecretKeySpec(Hex.decode("00112233445566778899AABBCCDDEEFF"), "HMAC");
    static final Key encryptKey = new SecretKeySpec(Hex.decode("00112233445566778899AABBCCDDEEFF"), "AES");

    @Test
    void getPayloadClaims() {
        final Jwt jwt = new Jwt();
        assertNotNull(jwt.getPayloadClaims());
    }

    @Test
    void getHeaderClaims() {
        final Jwt jwt = new Jwt();
        assertNotNull(jwt.getHeaderClaims());
    }

    @Test
    void getParameters() {
        final Jwt.Params params = new Jwt.Params() {};
        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        assertEquals(params, jwt.getParameters());
    }

    @Test
    void compactNonEncrypted() {
        final Jwt jwt = new Jwt();
        jwt.getHeaderClaims().setIssuer("com.tylersuehr");
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey);
        assertNotNull(token);

        System.out.printf("Non-encrypted: %s\n", token);
    }

    @Test
    void compactEncrypted() {
        final Jwt jwt = new Jwt();
        jwt.getHeaderClaims().setIssuer("com.tylersuehr");
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);
        jwt.setParameters(new Jwt.Params() {
            @Override
            public EncryptionType getEncryption() {
                return EncryptionType.AES_CTR;
            }
        });

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        System.out.printf("Encrypted: %s\n", token);
    }

    @Test
    void parseNonEncrypted() {
        final ConfigurableParams params = new ConfigurableParams();

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(token);

        assertTrue(parsedJwt.isNotVerified());
        assertFalse(parsedJwt.isEncrypted());
    }

    @Test
    void parseEncrypted() {
        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(token);

        assertTrue(parsedJwt.isNotVerified());
        assertTrue(parsedJwt.isEncrypted());

        parsedJwt.decrypt(encryptKey);
        assertFalse(parsedJwt.isEncrypted());
    }

    @Test
    void verifyNonEncrypted() {
        final ConfigurableParams params = new ConfigurableParams();

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(token);
        parsedJwt.verify(signKey);
    }

    @Test
    void verifyEncrypted() {
        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(token);

        assertTrue(parsedJwt.isNotVerified());
        assertTrue(parsedJwt.isEncrypted());

        parsedJwt.decrypt(encryptKey);
        assertFalse(parsedJwt.isEncrypted());

        parsedJwt.verify(signKey);
    }

    @Test
    void verifyNonEncryptedTampered() {
        final ConfigurableParams params = new ConfigurableParams();

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey);
        assertNotNull(token);

        final char[] tokenChars = token.toCharArray();
        tokenChars[23] ^= 1;
        final String tamperedToken = new String(tokenChars);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(tamperedToken);

        assertThrows(JwtSignatureException.class, () -> parsedJwt.verify(signKey));
    }

    @Test
    void verifyEncryptionGetFail() {
        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.parse(token);

        assertThrows(IllegalStateException.class, parsedJwt::getPayloadClaims);
    }

    @Test
    void verifyInvalidIssuer() {
        final String issuer = "com.tylersuehr";

        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);
        params.setIssuer(issuer);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        params.setIssuer("something else");

        final Jwt parsedJwt = new Jwt();
        parsedJwt.setParameters(params);
        parsedJwt.parse(token);

        assertThrows(JwtClaimException.class, () -> parsedJwt.verify(signKey));
    }

    @Test
    void verifyInvalidAudience() {
        final String audience = "com.tylersuehr";

        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);
        params.setAudience(audience);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        params.setAudience("something else");

        final Jwt parsedJwt = new Jwt();
        parsedJwt.setParameters(params);
        parsedJwt.parse(token);

        assertThrows(JwtClaimException.class, () -> parsedJwt.verify(signKey));
    }

    @Test
    void verifyInvalidSubject() {
        final String subject = "com.tylersuehr";

        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);
        params.setSubject(subject);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        params.setSubject("something else");

        final Jwt parsedJwt = new Jwt();
        parsedJwt.setParameters(params);
        parsedJwt.parse(token);

        assertThrows(JwtClaimException.class, () -> parsedJwt.verify(signKey));
    }

    @Test
    void verifyExpired() throws Exception {
        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);
        params.setNotAfter(1L);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.setParameters(params);
        parsedJwt.parse(token);

        assertThrows(JwtExpirationException.class, () -> {
            Thread.sleep(2000);
            parsedJwt.verify(signKey);
        });
    }

    @Test
    void verifyInvalidNotBefore() throws Exception {
        final ConfigurableParams params = new ConfigurableParams();
        params.setEncryption(EncryptionType.AES_CTR);
        params.setNotBefore(7200L);

        final Jwt jwt = new Jwt();
        jwt.setParameters(params);
        jwt.getPayloadClaims().put("a", "{123}");
        jwt.getPayloadClaims().put("b", true);
        jwt.getPayloadClaims().put("c", 342L);

        final String token = jwt.compact(signKey, encryptKey);
        assertNotNull(token);

        final Jwt parsedJwt = new Jwt();
        parsedJwt.setParameters(params);
        parsedJwt.parse(token);

        assertThrows(JwtExpirationException.class, () -> parsedJwt.verify(signKey));
    }
}

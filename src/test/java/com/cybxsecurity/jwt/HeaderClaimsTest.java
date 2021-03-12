package com.cybxsecurity.jwt;

import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the {@link HeaderClaims}.
 * @author Tyler Suehr
 */
class HeaderClaimsTest {
    @org.junit.jupiter.api.Test
    void getSignature() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setSignature(expected);
        assertEquals(expected, result.getSignature());
    }

    @org.junit.jupiter.api.Test
    void getEncryption() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setEncryption(expected);
        assertEquals(expected, result.getEncryption());
    }

    @org.junit.jupiter.api.Test
    void getIssuer() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setIssuer(expected);
        assertEquals(expected, result.getIssuer());
    }

    @org.junit.jupiter.api.Test
    void getAudience() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setAudience(expected);
        assertEquals(expected, result.getAudience());
    }

    @org.junit.jupiter.api.Test
    void getSubject() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setSubject(expected);
        assertEquals(expected, result.getSubject());
    }

    @org.junit.jupiter.api.Test
    void getNotBefore() {
        final Long expected = new Random().nextLong();
        final HeaderClaims result = new HeaderClaims();
        result.setNotBefore(expected);
        assertEquals(expected, result.getNotBefore());
    }

    @org.junit.jupiter.api.Test
    void getNotAfter() {
        final Long expected = new Random().nextLong();
        final HeaderClaims result = new HeaderClaims();
        result.setNotAfter(expected);
        assertEquals(expected, result.getNotAfter());
    }

    @org.junit.jupiter.api.Test
    void getTimestamp() {
        final Long expected = new Random().nextLong();
        final HeaderClaims result = new HeaderClaims();
        result.setTimestamp(expected);
        assertEquals(expected, result.getTimestamp());
    }

    @org.junit.jupiter.api.Test
    void getId() {
        final String expected = UUID.randomUUID().toString();
        final HeaderClaims result = new HeaderClaims();
        result.setId(expected);
        assertEquals(expected, result.getId());
    }
}
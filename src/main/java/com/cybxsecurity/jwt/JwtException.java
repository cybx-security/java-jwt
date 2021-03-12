package com.cybxsecurity.jwt;

/**
 * Parent exception of all exceptions in this package.
 * @author Tyler Suehr
 */
public class JwtException extends SecurityException {
    JwtException(String message) {
        super(message);
    }
}

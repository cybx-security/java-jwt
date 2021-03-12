package com.cybxsecurity.jwt;

/**
 * Thrown when the signature of a jwt could not be verified.
 * @author Tyler Suehr
 */
public class JwtSignatureException extends JwtException {
    JwtSignatureException() {
        super("Jwt signature could not be verified!");
    }
}

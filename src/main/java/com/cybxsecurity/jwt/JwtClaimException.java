package com.cybxsecurity.jwt;

/**
 * Thrown when jwt claim doesn't matched configured parameter.
 * @author Tyler Suehr
 */
public class JwtClaimException extends JwtException {
    JwtClaimException(String claim) {
        super("Jwt '" + claim + "' is invalid!");
    }
}

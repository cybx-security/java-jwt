package com.cybxsecurity.jwt;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Thrown when a jwt has expired not before or not after.
 * @author Tyler Suehr
 */
public class JwtExpirationException extends JwtException {
    static final DateFormat DF = new SimpleDateFormat("MM/dd/yyyy'@'hh:mm:ss a");

    static JwtExpirationException notAfter(long timestampSecs) {
        final Date timestamp = new Date(timestampSecs * 1000L);
        final String msg = String.format("Jwt expired on '%s'", DF.format(timestamp));
        return new JwtExpirationException(msg);
    }

    static JwtExpirationException notBefore(long timestampSecs) {
        final Date timestamp = new Date(timestampSecs * 1000L);
        final String msg = String.format("Jwt cannot be used before '%s'", DF.format(timestamp));
        return new JwtExpirationException(msg);
    }

    private JwtExpirationException(String message) {
        super(message);
    }
}

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

/**
 * Subclass of {@link JwtClaims}.
 * Contains additional restricted claims defined in RFC 7519.
 *
 * @author Tyler Suehr
 */
public class JwtHeaderClaims extends JwtClaims {
    private static final String TYPE = "typ"; // JOSE header
    private static final String CONTENT_TYPE = "cty"; // JOSE header
    private static final String ISSUER = "iss";
    private static final String SUBJECT = "sub";
    private static final String AUDIENCE = "aud";
    private static final String EXPIRATION = "exp";
    private static final String NOT_BEFORE = "nbf";
    private static final String ISSUED_AT = "iat";
    private static final String JWT_ID = "jti";

    /**
     * Gets the JOSE header type of this token.
     * @return the type
     */
    public String getType() {
        return (String) get(TYPE);
    }

    /**
     * Sets the JOSE header type of this token.
     * @param type the type
     */
    public void setType(String type) {
        put(TYPE, type);
    }

    /**
     * Gets the JOSE header content-type of this token.
     * @return the content-type
     */
    public String getContentType() {
        return (String) get(CONTENT_TYPE);
    }

    /**
     * Sets the JOSE header content-type of this token.
     * @param contentType the content-type
     */
    public void setContentType(String contentType) {
        put(CONTENT_TYPE, contentType);
    }

    /**
     * Gets the issuer of this token.
     * @return the issuer
     */
    public String getIssuer() {
        return (String) get(ISSUER);
    }

    /**
     * Sets the issuer of this token.
     * @param issuer the issuer
     */
    public void setIssuer(String issuer) {
        put(ISSUER, issuer);
    }

    /**
     * Gets the subject of this token.
     * @return the subject
     */
    public String getSubject() {
        return (String) get(SUBJECT);
    }

    /**
     * Sets the subject of this token.
     * @param subject the subject
     */
    public void setSubject(String subject) {
        put(SUBJECT, subject);
    }

    /**
     * Gets the audience of this token.
     * @return the audience
     */
    public String getAudience() {
        return (String) get(AUDIENCE);
    }

    /**
     * Sets the audience of this token.
     * @param audience the audience
     */
    public void setAudience(String audience) {
        put(AUDIENCE, audience);
    }

    /**
     * Gets the mutable expiration of this token.
     * @return the expiration
     */
    public TimeSecs getExpiration() {
        return new TimeSecs(EXPIRATION);
    }

    /**
     * Gets the mutable not-before timestamp of this token.
     * @return the not-before timestamp
     */
    public TimeSecs getNotBefore() {
        return new TimeSecs(NOT_BEFORE);
    }

    /**
     * Gets the mutable issued at timestamp of this token.
     * @return the issued at timestamp
     */
    public TimeSecs getIssuedAt() {
        return new TimeSecs(ISSUED_AT);
    }

    /**
     * Gets the identifier of this token.
     * @return the jwt id
     */
    public String getId() {
        return (String) get(JWT_ID);
    }

    /**
     * Sets the identifier of this token.
     * @param jwtId the jwt id
     */
    public void setId(String jwtId) {
        put(JWT_ID, jwtId);
    }


    /**
     * Helper for modifying normalized timestamps in seconds.
     */
    public class TimeSecs {
        private final String key;

        /**
         * Constructs with reference to claim to modify.
         * @param key the key value of claim
         */
        TimeSecs(String key) {
            this.key = key;
        }

        /**
         * Gets this timestamp value in seconds.
         * @return the timestamp (seconds)
         */
        public long get() {
            final Object val = JwtHeaderClaims.this.get(this.key);
            if (val instanceof Number)
                return ((Number) val).longValue();
            return 0L;
        }

        /**
         * Sets this timestamp value in seconds.
         * @param seconds the timestamp (seconds)
         */
        public void set(long seconds) {
            JwtHeaderClaims.this.put(this.key, seconds);
        }

        /**
         * Sets this timestamp value in milliseconds.
         * @param milliseconds the timestamp (milliseconds)
         */
        public void setInMillis(long milliseconds) {
            JwtHeaderClaims.this.put(this.key, (milliseconds / 1000L));
        }

        /**
         * Sets this timestamp to n seconds into the future.
         * @param seconds the seconds into the future
         */
        public void setFutureSecs(long seconds) {
            final long nowSecs = System.currentTimeMillis() / 1000L;
            JwtHeaderClaims.this.put(this.key, (nowSecs + seconds));
        }

        /**
         * Sets this timestamp to n hours into the future.
         * @param hours the hours into the future
         */
        public void setFutureHours(long hours) {
            final long futureSecs = (hours / 60 / 60);
            final long nowSecs = System.currentTimeMillis() / 1000L;
            JwtHeaderClaims.this.put(this.key, (nowSecs + futureSecs));
        }

        /**
         * Sets this timestamp to n seconds into the past.
         * @param seconds the seconds into the past
         */
        public void setPastSecs(long seconds) {
            final long nowSecs = System.currentTimeMillis() / 1000L;
            JwtHeaderClaims.this.put(this.key, (nowSecs - seconds));
        }

        /**
         * Sets this timestamp to n hours into the past.
         * @param hours the hours into the past
         */
        public void setPastHours(long hours) {
            final long futureSecs = (hours / 60 / 60);
            final long nowSecs = System.currentTimeMillis() / 1000L;
            JwtHeaderClaims.this.put(this.key, (nowSecs - futureSecs));
        }
    }
}

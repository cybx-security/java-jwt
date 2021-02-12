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
 * Represents a parsed jwt that has not been verified yet.
 * @author Tyler Suehr
 */
public class UnverifiedClaims {
    private JwtHeaderClaims mHeaderClaims;
    private JwtClaims mPayloadClaims;
    private byte[] mUnverified;
    private byte[] mSignature;

    @Override
    public String toString() {
        return "{" +
                "header: " + mHeaderClaims +
                ", payload: " + mPayloadClaims +
                '}';
    }

    /**
     * Gets the header claims of the token.
     * @return the header claims
     */
    public JwtHeaderClaims getHeaderClaims() {
        return mHeaderClaims;
    }

    /**
     * Sets the header claims of the token.
     * @param headerClaims the header claims
     */
    void setHeaderClaims(JwtHeaderClaims headerClaims) {
        mHeaderClaims = headerClaims;
    }

    /**
     * Gets the payload claims of the token.
     * @return the payload claims
     */
    public JwtClaims getPayloadClaims() {
        return mPayloadClaims;
    }

    /**
     * Sets the payload claims of the token.
     * @param payloadClaims the payload claims
     */
    void setPayloadClaims(JwtClaims payloadClaims) {
        mPayloadClaims = payloadClaims;
    }

    /**
     * Gets the unverified segment of the token.
     * @return the unverified segment
     */
    byte[] getUnverified() {
        return mUnverified;
    }

    /**
     * Sets the unverified segment of the token.
     * @param unverified the unverified segment
     */
    void setUnverified(byte[] unverified) {
        mUnverified = unverified;
    }

    /**
     * Gets the signature segment of the token.
     * @return the signature segment
     */
    byte[] getSignature() {
        return mSignature;
    }

    /**
     * Sets the signature segment of the token.
     * @param signature the signature segment
     */
    void setSignature(byte[] signature) {
        mSignature = signature;
    }
}

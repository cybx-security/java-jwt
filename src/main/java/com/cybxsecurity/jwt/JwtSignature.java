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
 * Contains all supported signature and MAC algorithms.
 * @author Tyler Suehr
 */
public enum JwtSignature {
    // Supported MAC algorithms
    HS256("HMAC-SHA256"),
    HS384("HMAC-SHA384"),
    HS512("HMAC-SHA512"),
    HS3_256("HMAC-SHA3-256"), // not in RFC
    HS3_384("HMAC-SHA3-384"), // not in RFC
    HS3_512("HMAC-SHA3-512"), // not in RFC
    // Supported signature algorithms
    EC256("SHA256withECDSA"),
    EC384("SHA384withECDSA"),
    EC512("SHA512withECDSA"),
    RS256("SHA256withRSA"),
    RS384("SHA384withRSA"),
    RS512("SHA512withRSA"),
    PS256("SHA256withRSAandMGF1"),
    PS384("SHA384withRSAandMGF1"),
    PS512("SHA512withRSAandMGF1");
    private final String algorithm;

    /**
     * Constructs with reference to algorithm.
     * @param algorithm the algorithm
     */
    JwtSignature(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return this.algorithm;
    }
}

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
 * Contains all supported encryption algorithms.
 * @author Tyler Suehr
 */
public enum JwtEncryption {
    AES_CBC("AES/CBC/PKCS7Padding"),
    AES_CTS("AES/CTS/PKCS7Padding"),
    AES_CTR("AES/CTR/NoPadding");
    private final String algorithm;

    /**
     * Constructs with reference to algorithm.
     * @param algorithm the algorithm
     */
    JwtEncryption(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return this.algorithm;
    }
}

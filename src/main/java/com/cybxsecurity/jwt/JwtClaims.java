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

import com.google.gson.Gson;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;

/**
 * Represents key-value claims of a jwt.
 * @author Tyler Suehr
 */
public class JwtClaims extends HashMap<String,Object> {
    private static Gson sConverter;

    /**
     * Converts these claims into a json string value.
     * @return the json string
     */
    public String toJsonString() {
        if (sConverter == null)
            sConverter = new Gson();
        return sConverter.toJson(this);
    }

    /**
     * Converts these claims into a json string UTF8 byte array.
     * @return the json string bytes
     */
    public byte[] toJsonStringBytes() {
        final String val = toJsonString();
        return val.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Converts a json string value into a new claims object.
     *
     * @param json the json to be converted
     * @return the claims
     *
     * @param <T> the type of claims object
     */
    public static <T extends JwtClaims> T fromJsonString(String json, Class<T> type) {
        if (sConverter == null)
            sConverter = new Gson();
        return sConverter.fromJson(json, type);
    }
}

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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Thrown when a not after timestamp has been exceeded on a jwt.
 * @author Tyler Suehr
 */
public class JwtExpirationException extends JwtException {
    static final DateFormat FORMAT = new SimpleDateFormat("MM/dd/yyyy'@'HH:mm:ss");

    JwtExpirationException(long expirationSecs) {
        super(String.format("JWT expired on '%s'!", formatExpiration(expirationSecs)));
    }

    static String formatExpiration(long notAfterSecs) {
        final long notAfterMillis = notAfterSecs * 1000L;
        return FORMAT.format(new Date(notAfterMillis));
    }
}

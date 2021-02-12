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
 * Default implementation of {@link JwtFactoryParams}.
 * Allows instantiating instance and manipulation with getters/setters.
 *
 * @author Tyler Suehr
 */
public class ConfigurableJwtFactoryParams implements JwtFactoryParams {
    private JwtSignature mSignature;
    private JwtEncryption mEncryption;
    private String mIssuer;
    private String mAudience;
    private String mSubject;
    private long mNotAfter;
    private long mNotBefore;
    private boolean mGenerateId;

    @Override
    public JwtSignature getSignature() {
        return mSignature;
    }

    public void setSignature(JwtSignature signature) {
        mSignature = signature;
    }

    @Override
    public JwtEncryption getEncryption() {
        return mEncryption;
    }

    public void setEncryption(JwtEncryption encryption) {
        mEncryption = encryption;
    }

    @Override
    public String getIssuer() {
        return mIssuer;
    }

    public void setIssuer(String issuer) {
        mIssuer = issuer;
    }

    @Override
    public String getAudience() {
        return mAudience;
    }

    public void setAudience(String audience) {
        mAudience = audience;
    }

    @Override
    public String getSubject() {
        return mSubject;
    }

    public void setSubject(String subject) {
        mSubject = subject;
    }

    @Override
    public long getNotAfter() {
        return mNotAfter;
    }

    public void setNotAfter(long notAfter) {
        mNotAfter = notAfter;
    }

    @Override
    public long getNotBefore() {
        return mNotBefore;
    }

    public void setNotBefore(long notBefore) {
        mNotBefore = notBefore;
    }

    @Override
    public boolean isGenerateId() {
        return mGenerateId;
    }

    public void setGenerateId(boolean generateId) {
        mGenerateId = generateId;
    }
}

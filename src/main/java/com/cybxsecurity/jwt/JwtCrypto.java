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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Encapsulated cryptography logic used by this library.
 * @author Tyler Suehr
 */
abstract class JwtCrypto {
    private JwtCrypto() {}

    /**
     * Cryptographically signs content with supported algorithm.
     *
     * @param alg the algorithm to sign content with
     * @param signKey the key to sign content with (symmetric/asymmetric)
     * @param content the content to be signed
     *
     * @return the signature
     * @throws IllegalStateException if signature could not be computed
     */
    static byte[] sign(JwtSignature alg, Key signKey, byte[] content) {
        try {
            if (signKey instanceof PrivateKey) {
                final PrivateKey privateKey = (PrivateKey) signKey;
                final Signature signer = Signature.getInstance(alg.toString(), BC);
                signer.initSign(privateKey);
                signer.update(content);
                return signer.sign();
            } else if (signKey instanceof SecretKey) {
                final Mac mac = Mac.getInstance(alg.toString(), BC);
                mac.init(signKey);
                mac.update(content);
                return mac.doFinal();
            } else {
                throw new IllegalArgumentException("Key must be a PrivateKey or SecretKey!");
            }
        } catch (NoSuchProviderException | NoSuchAlgorithmException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("No such provider or algorithm!");
        } catch (InvalidKeyException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("Invalid signing key!");
        } catch (SignatureException ex) {
            ex.printStackTrace(System.err);
            throw new IllegalStateException("Failed to create signature!");
        }
    }

    /**
     * Cryptographically verifies content with supported algorithm.
     *
     * @param alg the algorithm to verify content with
     * @param verifyKey the key to verify content with (symmetric/asymmetric)
     * @param unverified the unverified content
     * @param signature the signature of the content
     *
     * @return true if verified, otherwise false
     */
    static boolean verify(JwtSignature alg, Key verifyKey, byte[] unverified, byte[] signature) {
        try {
            if (verifyKey instanceof PublicKey) {
                final PublicKey publicKey = (PublicKey) verifyKey;
                final Signature signer = Signature.getInstance(alg.toString(), BC);
                signer.initVerify(publicKey);
                signer.update(unverified);
                return signer.verify(signature);
            } else if (verifyKey instanceof SecretKey) {
                final Mac mac = Mac.getInstance(alg.toString(), BC);
                mac.init(verifyKey);
                mac.update(unverified);
                return MessageDigest.isEqual(signature, mac.doFinal());
            } else {
                throw new IllegalArgumentException("Key must be a PublicKey or SecretKey!");
            }
        } catch (NoSuchProviderException| NoSuchAlgorithmException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("No such provider or algorithm!");
        } catch (InvalidKeyException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("Invalid signing key!");
        } catch (SignatureException ex) {
            ex.printStackTrace(System.err);
            return false;
        }
    }

    /**
     * Encrypts the content with supported algorithm.
     *
     * @param alg the encryption algorithm
     * @param encryptKey the key to encrypt content with
     * @param content the content to be encrypted
     *
     * @return the cipher text
     */
    static byte[] encrypt(JwtEncryption alg, Key encryptKey, byte[] content) {
        try {
            final byte[] iv = generateRandomIv();
            final byte[] cipherText;

            final Cipher cipher = Cipher.getInstance(alg.toString(), BC);
            cipher.init(Cipher.ENCRYPT_MODE, encryptKey, new IvParameterSpec(iv));
            cipherText = cipher.doFinal(content);

            return Arrays.concatenate(iv, cipherText);
        } catch (NoSuchProviderException| NoSuchAlgorithmException| NoSuchPaddingException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("No such provider, algorithm, or padding!");
        } catch (InvalidKeyException| InvalidAlgorithmParameterException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("Invalid signing key or algorithm param!");
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            ex.printStackTrace(System.err);
            throw new IllegalStateException("Failed to encrypt data!");
        }
    }

    /**
     * Decrypts the content with supported algorithm.
     *
     * @param alg the encryption algorithm
     * @param decryptKey the key to decrypt content with
     * @param content the content to be decrypted
     *
     * @return the plaintext
     */
    static byte[] decrypt(JwtEncryption alg, Key decryptKey, byte[] content) {
        if (content == null || content.length <= IV_LENGTH)
            throw new IllegalArgumentException("Malformed content!");
        try {
            final byte[] iv = Arrays.copyOfRange(content, 0, IV_LENGTH);
            final byte[] cipherText = Arrays.copyOfRange(content, IV_LENGTH, content.length);

            final Cipher cipher = Cipher.getInstance(alg.toString(), BC);
            cipher.init(Cipher.DECRYPT_MODE, decryptKey, new IvParameterSpec(iv));

            return cipher.doFinal(cipherText);
        } catch (NoSuchProviderException| NoSuchAlgorithmException| NoSuchPaddingException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("No such provider, algorithm, or padding!");
        } catch (InvalidKeyException| InvalidAlgorithmParameterException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("Invalid signing key or algorithm param!");
        } catch (BadPaddingException| IllegalBlockSizeException ex) {
            ex.printStackTrace(System.err);
            throw new IllegalStateException("Failed to decrypt data!");
        }
    }

    /**
     * Generates a random initialization vector.
     * Intended for use with a supported AES algorithm mode.
     *
     * @return the iv
     */
    static byte[] generateRandomIv() {
        try {
            final byte[] out = new byte[IV_LENGTH];
            SecureRandom.getInstance("DEFAULT", BC).nextBytes(out);
            return out;
        } catch (NoSuchProviderException | NoSuchAlgorithmException ex) {
            // programming error
            ex.printStackTrace(System.err);
            throw new Error("No such provider or algorithm!");
        }
    }

    static final int IV_LENGTH = 16; // block size of AES cipher
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    static {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}

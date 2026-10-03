/*
 * Copyright (C) 2018-2024 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ua.cn.al.easycrypt.impl;

import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.Digester;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Digesters
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class JCEDigestImpl implements Digester {
    private final CryptoParams params;

    public JCEDigestImpl(CryptoParams params) {
        this.params = params;
    }

    @Override
    public byte[] digest(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance(params.getDigester());
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No " + params.getDigester() + " defined", ex);
        }
    }

    @Override
    public MessageDigest digest() throws CryptoNotValidException {
        try {
            return MessageDigest.getInstance(params.getDigester());
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No " + params.getDigester() + " defined", ex);
        }
    }

    @Override
    public byte[] sha256(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No SHA-256 defined", ex);
        }
    }

    @Override
    public byte[] sha512(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No SHA-512 defined", ex);
        }
    }

    @Override
    public byte[] sha3_256(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA3-256");
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No SH3A-256 defined", ex);
        }
    }

    @Override
    public byte[] sha3_384(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA3-384");
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No SH3A-384 defined", ex);
        }
    }

    @Override
    public byte[] sha3_512(byte[] message) throws CryptoNotValidException {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA3-512");
            hash.update(message);
            return hash.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("No SH3A-512 defined", ex);
        }
    }

    @Override
    @Deprecated
    public byte[] PBKDF2(String passPhrase, byte[] salt) throws CryptoNotValidException {
        return derive(passPhrase, salt, CryptoParams.PBKDF2_LEGACY_ITERATIONS, CryptoParams.PBKDF2_KEYELEN,
                false, CryptoParams.PBKDF2_KEY_DERIVATION_FN);
    }

    @Override
    public byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt) throws CryptoNotValidException {
        return deriveKeyFromPassPhrase(passPhrase, salt, params.getPbkdf2Iterations());
    }

    @Override
    public byte[] deriveKeyFromPassPhrase(String passPhrase, byte[] salt, int iterations) throws CryptoNotValidException {
        return derive(passPhrase, salt, iterations, CryptoParams.PBKDF2_KEYELEN, true, params.getKeyDerivationFn());
    }

    private byte[] derive(String passPhrase, byte[] salt, int iterations, int keyLengthBits, boolean secureDefaults,
            String algorithm)
            throws CryptoNotValidException {
        if (passPhrase == null || passPhrase.isEmpty()) {
            throw new CryptoNotValidException("Passphrase must not be null or empty");
        }
        if (salt == null || (secureDefaults && salt.length < CryptoParams.PBKDF2_SALT_LEN_BYTES)) {
            throw new CryptoNotValidException("PBKDF2 salt must be at least "
                    + CryptoParams.PBKDF2_SALT_LEN_BYTES + " bytes");
        }
        if (iterations <= 0 || (secureDefaults && iterations < CryptoParams.PBKDF2_ITERATIONS)) {
            throw new CryptoNotValidException("PBKDF2 iteration count must be at least "
                    + CryptoParams.PBKDF2_ITERATIONS);
        }
        char[] password = passPhrase.toCharArray();
        PBEKeySpec spec = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            spec = new PBEKeySpec(password, salt, iterations, keyLengthBits);
            SecretKey key = skf.generateSecret(spec);
            return key.getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("PBKDF2 algorithm is unavailable: " + algorithm, ex);
        } catch (InvalidKeySpecException ex) {
            throw new CryptoNotValidException("Invalid parameters for PBKDF2", ex);
        } finally {
            if (spec != null) {
                spec.clearPassword();
            }
            java.util.Arrays.fill(password, '\0');
        }
    }
}

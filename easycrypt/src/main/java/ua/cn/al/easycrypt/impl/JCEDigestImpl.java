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
    public byte[] PBKDF2(String passPhrase, byte[] salt) throws CryptoNotValidException {
        if (salt == null) {
            throw new CryptoNotValidException("Salt can not be null, length is 12 bytes for PBKDF2");
        }
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(CryptoParams.PBKDF2_KEY_DERIVATION_FN);
            PBEKeySpec spec = new PBEKeySpec(passPhrase.toCharArray(), salt, CryptoParams.PBKDF2_ITERATIONS, CryptoParams.PBKDF2_KEYELEN);
            SecretKey key = skf.generateSecret(spec);

            byte[] res = key.getEncoded();
            return res;
        } catch (NoSuchAlgorithmException ex) {
            //ignore, we use constants
        } catch (InvalidKeySpecException ex) {
            throw new CryptoNotValidException("Possibly invalid salt length for PBKDF2");
        }
        return null;
    }
}

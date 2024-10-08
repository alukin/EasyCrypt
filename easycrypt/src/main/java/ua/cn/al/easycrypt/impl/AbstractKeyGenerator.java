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
import ua.cn.al.easycrypt.KeyGenerator;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common for ECC and RSA key generator methods
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public abstract class AbstractKeyGenerator implements KeyGenerator {

    private static final Logger log = LoggerFactory.getLogger(AbstractKeyGenerator.class);
    public static final int NOT_RANDOM_LEN = 4096;
    protected SecureRandom sr;
    protected final CryptoParams params;

    public AbstractKeyGenerator(CryptoParams params) {
        this.params = Objects.requireNonNull(params);
        sr = new SecureRandom();
        sr.nextBoolean();
    }

    /**
     * Simple deterministic key derivation function. It is one-way function. It
     * calculates hash (defined in params) of secretPhrase.getBytes() and salt.
     * If there is not enough bytes (keyLen) it uses hash result and the same
     * salt again and puts additional bytes to output.
     *
     * @param secretPhrase UTF-8 encoded string
     * @param salt random salt at least of 16 bytes
     * @param keyLenBits desired output length in bits (should be byte-aligned)
     * @return array of bytes that is determined by secretPhrase ans salt. It is
     * hard to calculate secretPhrase from it because it uses string
     * cryptographic hashing function SHA-512
     * @throws CryptoNotValidException
     */
    @Override
    public byte[] deriveFromSecretPhrase(String secretPhrase, byte[] salt, int keyLenBits) throws CryptoNotValidException {
        String digester = params.getDigester();
        // this is kind of "fuse" to avoid problems with shorter digesters
        if (keyLenBits > 256) {
            digester = "SHA-512"; //longes one
        }
        if (keyLenBits > 512) {
            throw new CryptoNotValidException("Can not generate key longer then 512 bits");
        }
        int keyLen = keyLenBits/8;
        int iterations = params.getPbkdf2Iterations(); //at the moment we do not have Pbkdf in JS
        ByteBuffer bb = ByteBuffer.allocate(keyLen);
        byte[] input;

        try {
            MessageDigest hash0 = MessageDigest.getInstance(digester);
            hash0.update(secretPhrase.getBytes());
            hash0.update(salt);
            input = hash0.digest();

            MessageDigest hash = MessageDigest.getInstance(digester);
            for (int i = 1; i < iterations; i++) {
                hash.update(input);
                input = hash.digest();
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("Digest algorythm is not available", ex);
        }

        bb.put(input, 0, keyLen);
        return bb.array();
    }

    @Override
    public byte[] generateSymKey() {
        byte[] key = new byte[params.getAesKeyLen()];
        sr.nextBytes(key);
        return key;
    }

    @Override
    public byte[] generateIV() {
        byte[] iv = new byte[params.getAesIvLen()];
        sr.nextBytes(iv);
        return iv;
    }

}

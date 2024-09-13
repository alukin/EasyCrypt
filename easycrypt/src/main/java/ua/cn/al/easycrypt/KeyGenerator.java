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

package ua.cn.al.easycrypt;

import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Key generator with defined key paramaters
 *
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com
 */
public interface KeyGenerator {

    /**
     * create PublicKey from encoded byte array
     *
     * @param bytes of key
     * @return Public key
     */
    PublicKey createPublicKeyFromBytes(byte[] bytes);

    /**
     * Simple deterministic key derivation function. It is one-way function. It
     * calculates hash (defined in params) of secretPhrase.getBytes() and salt.
     * It is      * hard to calculate secretPhrase from it because it uses strong
     * cryptographic hashing functions such as SHA-265 or SHA-512
     *
     * @param secretPhrase UTF-8 encoded string
     * @param salt         random salt at least of 16 bytes
     * @param keyLen       desired output length
     * @return array of bytes that is determined by secretPhrase ans salt. 
     * @throws CryptoNotValidException
     */
    byte[] deriveFromSecretPhrase(String secretPhrase, byte[] salt, int keyLen) throws CryptoNotValidException;

    /**
     * Generated true secure ECC or RSA key pair using secure random number generator
     *
     * @return Generated random key pair
     */
    KeyPair generateKeys();

    /**
     * Generate deterministic ECC key pair using defaultCurve and
     * passphrase.Well, obviously all the security depends on randomness of
     * passphrase!
     *
     * @param secretPhrase long enough and random enough pass phrase. You've
     *                     been warned!
     * @param salt         some random number, recomeneded size is 16 bytes
     * @return EEC key pair
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    KeyPair generateKeys(String secretPhrase, byte[] salt) throws CryptoNotValidException;
    /**
     * Generate symmetric key of required lenght usinh secure random 
     * @return symmetric key
     */
    public byte[] generateSymKey();
    
    /**
     * Genereate random Initialization Vector
     * @return Initialization vector or required length
     */
    public byte[] generateIV();
}

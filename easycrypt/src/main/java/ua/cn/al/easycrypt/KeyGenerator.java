/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * LICENSE
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

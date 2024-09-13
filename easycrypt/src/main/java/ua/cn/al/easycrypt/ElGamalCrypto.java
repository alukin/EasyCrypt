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

import ua.cn.al.easycrypt.dataformat.ElGamalEncryptedMessage;

import java.math.BigInteger;

//TODO: ASAP clarify this interface !!!

/**
 * ElGammal procedures
 *
 * @author Serhiy Lymar serhiy.lymar@gmail.com
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface ElGamalCrypto {

    /**
     * Decrypt ElGamalEncryptedMessage sent to us using our private key
     *
     * @param priKey our private key
     * @param cryptogram formated message parsed into ElGamalEncryptedMessage
     * @return decryption result, could be interpreted as byte array
     * @throws CryptoNotValidException
     */
    BigInteger decrypt(BigInteger priKey, ElGamalEncryptedMessage cryptogram) throws CryptoNotValidException;

    /**
     * ElGamal Encryption routine using 2 components of public key
     *
     * @param publicKeyX x coordinate of public key, presented as BigInteger
     * @param publicKeyY y coordinate of public key, presented as BigInteger
     * @param plainText  plain text in format of BigInteger
     * @return ElGamalEncryptedMessage crypto container, consisting
     * of M1 as ECPoint with X,Y coordinates and M2 as BigInteger
     * @throws CryptoNotValidException
     */
    ElGamalEncryptedMessage encrypt(BigInteger publicKeyX, BigInteger publicKeyY, BigInteger plainText) throws CryptoNotValidException;

    /**
     * ElGamal Keys generation routine
     *
     * @return ElGamalKeyPair crypto container, consisting
     * of as public key as ECPoint with X,Y coordinates and
     * private key as BigInteger
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */

    ElGamalKeyPair generateOwnKeys() throws CryptoNotValidException;

    /**
     * ElGamal getter for public key abscissa
     *
     * @return x coordinate of public as BigInteger
     */

    BigInteger getPublicKeyX();

    /**
     * ElGamal getter for public key ordinate
     *
     * @return y coordinate of public as BigInteger
     */

    BigInteger getPublicKeyY();

    /**
     * ElGamal getter for private key
     *
     * @return private key as BigInteger
     */

    BigInteger getPrivateKey();

}

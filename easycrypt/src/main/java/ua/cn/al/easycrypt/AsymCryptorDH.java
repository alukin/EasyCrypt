/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
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

/**
 * Crypto routines to "asymmetric" encryption using Diffie-Hellman key exchange.
 * In fact, symmetric AES encryption is used after common key is established.
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 
 */
public interface AsymCryptorDH extends AsymCryptor {
    
    /**
     * Performs ephemeral key EC Diffie-Hellman step1:
     * generates temporary key pair, signs temporary public key with
     * real private key.
     * @return signed temporal public key. Format: size of key: integer; byte[] key; byte[] signature 
     * @throws ua.cn.al.easycrypt.CryptoNotValidException 
     */

    byte[] ecdheStep1() throws CryptoNotValidException;
    
    /**
     * Performs step 2 of  ephemeral key EC Diffie-Hellman:
     * takes signed key form other side, verifies signature,
     * makes ECDH using temporary keys, hashes and returns
     * shared key.This key then should be used for symmetric encryption.
     * @param signedEphemeralPubKey signed shared key from other side
     * @return shared key
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    byte[] ecdheStep2(byte[] signedEphemeralPubKey)  throws CryptoNotValidException;
    
    
    /**
     * Calculate shared key usable by both ends of encryption by some Diffie-Hellman
     * procedure. In case of EC it is ECDH. If you have possibility to exchange temporal keys,
     * consider to use 2-step ECDHE procedure for more security.
     * @return encoded shared key
     */
    byte[] calculateSharedKey();
    
}

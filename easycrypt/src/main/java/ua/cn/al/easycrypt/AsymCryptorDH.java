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

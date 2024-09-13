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

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface to signature operations
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 
 */
public interface CryptoSignature {
    
    /**
     * Set just public key for signature verification
     * @param pk public key for signature verification
     */
    void setTheirPublicKey(PublicKey pk);
    
    /**
     * Set just our private key for signing
     * @param pk our private key
     */
    void setPrivateKey(PrivateKey pk);

    /**
     * Set all required keys
     * @param keys our public and private keys, their public key
     */
    void setKeys(AsymKeysHolder keys);

    /**
     * Sign message using private key.Please be careful while constructing FPCryptoParams, 
     * pay attention to signature algorithm inside of it
     * @param message input message. No matter encrypted or not.
     * @return signature bytes ( In ASN1 format, encoding - DER)
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    byte[] sign(byte[] message) throws CryptoNotValidException;

    /**
     * Verifies signature using theirPublicKey
     * Signature algorithm depends on CryptoParams settings. 
     * Please construct crypto routines
     * using CryptoMetaFactory from appropriate signature method ID string
     * @param message message bytes
     * @param signature signature bytes (In ASN1 format. Encoding - DER)
     * @return true if message is authentic false otherwise
     */
    boolean verify(byte[] message, byte[] signature);

    /**
     * Sign message using private key.Please be careful while constructing FPCryptoParams, 
     * pay attention to signature algorithm inside of it
     * @param message input message. No matter encrypted or not.
     * @return signature bytes as concatenation of R and S binary vectors
     * (2 * 66 = 132 bytes)
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    byte[] signPlain(byte[] message) throws CryptoNotValidException;

    /**
     * Verifies signature using theirPublicKey
     * Signature algorithm depends on CryptoParams settings. 
     * Please construct cryptographic routines
     * using CryptoMetaFactory from appropriate signature method ID string
     * @param message message bytes
     * @param signature signature bytes ( As concatenation of R and S, 132 bytes)
     * @return true if message is authentic false otherwise
     */
    boolean verifyPlain(byte[] message, byte[] signature);

}

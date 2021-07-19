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

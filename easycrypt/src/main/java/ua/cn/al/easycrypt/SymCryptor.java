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

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Interface to symmetric crypto routines
 *
 * @author Oleksiy Lukin alukin@gmail.com
 * REFERENCES: [1]
 * https://tools.ietf.org/rfc/rfc5288.txt AES Galois Counter Mode (GCM) Cipher
 * Suites for TLS [2] https://tools.ietf.org/html/draft-ietf-tls-tls13-28 TLS
 * 1.3 draft [3] https://tools.ietf.org/html/rfc5246 TLS 1.2 [4]
 * https://tools.ietf.org/html/rfc5116 An Interface and Algorithms for
 * Authenticated Encryption [5] https://tools.ietf.org/html/rfc4106 The Use of
 * Galois/Counter Mode (GCM) in IPsec Encapsulating Security Payload (ESP) [6]
 * https://tools.ietf.org/html/rfc7748 Elliptic Curves for Security
 */
public interface SymCryptor extends Cryptor {

    /**
     * Set key for AES/GCM which is used for symmetrical encryption.
     *
     * @param key then 128 or 256 bits of key   0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
     * @throws CryptoNotValidException, IllegalArgumentException
     */
    void setKey(byte[] key) throws CryptoNotValidException;

    /**
     *
     * @param IV Initialization vector variable part, 4+8=12 bytes, or salt and
     * explicit_nonce used to init GCM. So it could be 4 bytes of "fixed"
     * nonce or full 12 bytes. In case of 4 bytes random 8 bytes generated for
     * nonce_explicit From RFC 5288: AES-GCM security requires that the counter
     * is never reused. The IV construction in Section 3 is designed to prevent
     * counter reuse. Implementers should also understand the practical
     * considerations of IV handling outlined in Section 9 of [GCM]. In this
     * class IV is 12 bytes as defined in RFC 5116 struct { opaque salt[4];
     * opaque nonce_explicit[8]; } GCMNonce; Salt is "fixed" part of IV and
     * comes with key, nonce_explicit is "variable" part of IV and comes with
     * message. So IV in this method should be 12 bytes long
     */
    void setIV(byte[] IV);

    /**
     * 12 bytes of salt + nounce
     *
     * @return IV consisting of salt and nounce
     */
    byte[] getIV();

    /**
     * Set 4 bytes of salt, fixed part of GCM IV
     *
     * @param salt 4 bytes array
     */
    void setSalt(byte[] salt);

    /**
     * set 8 bits of variable part of GCM IV
     *
     * @param explicit_nonce 8 bit array of nounce if explicit_nounce is null
     * random value is generated
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    void setNonce(byte[] explicit_nonce) throws CryptoNotValidException;

    /**
     * get 8 bytes of variable part of GCM IV
     *
     * @return b 8 bytes array
     */
    byte[] getNonce();
    /**
     * get 4 bytes of salt (part of IV)
     * @return 4 bytes of salt
     */
    public byte[] getSalt();
    
    /**
     * Do we save salt in the encrypted message along with explicit nounce (entire IV)
     * of keep salt separatelly. Default is to put zero bytes instead of real salt.,
     * @param b saves salt in message prefix along with explicit nounce 
     */
    public void saltInMessage(boolean b);

    /**
     * Get cipher in encrypt or decrypt mode. Keys should be already set.
     * It is not intended to external use, but may be used if programmers know how 
     * to work with ciphers
     * @param mode is Chipher.ENCRIPT_MODE or Chipher.DECRYPT_MODE
     * @return ready to use cipher
     */
    public Cipher getCipher(int mode)throws NoSuchAlgorithmException, NoSuchPaddingException;
}

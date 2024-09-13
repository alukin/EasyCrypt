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

import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;

/**
 * Encrypt/decrypt operations interface
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface Cryptor {
        
    /**
     * Encrypt message
     * @param plain plain text
     * @return encrypted text. Format depends on implementation and crypto scheme.
     * @throws CryptoNotValidException
     */
    byte[] encrypt(byte[] plain) throws CryptoNotValidException;

    /**
     * Decrypt message
     * @param ciphered encrypted text prefixed with 12 bytes of IV
     * @return plain text
     * @throws CryptoNotValidException
     */
    byte[] decrypt(byte[] ciphered) throws CryptoNotValidException;
 
    /**
     * Encrypt plain text, using shared key
     * unencrypted authenticated associated data
     * AES-GCM is used
     * @param plain plain text to encrypt
     * @param aeadata data to add unencrypted but authenticated by HMAC
     * @return specially formated data that includes IV length in bytes
     * (4bytes), IV itself (variable part), unencryped data lenght (4 bytes),
     * unencrypted data and then encrypted data in the rest of message;
     * @throws CryptoNotValidException
     */
    AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) throws CryptoNotValidException;

    /**
     * Decrypt AEADPlain message ciphered with key derived from asymmetric keys
     * AES-GCM is used
     * @param message specially formated message, @see AEADCiphered
     * @return decrypted and verified data in AEADPlain structure
     * @throws CryptoNotValidException
     */
    AEADPlain decryptWithAEAData(byte[] message) throws CryptoNotValidException;
}

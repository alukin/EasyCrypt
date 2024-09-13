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

package ua.cn.al.easycrypt.impl.rsa;

import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.impl.AbstractAsymCryptor;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RSA based implementation of EasyCrypt interface
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AsymCryptorRSAImpl extends AbstractAsymCryptor {
    private static final Logger log = LoggerFactory.getLogger(AsymCryptorRSAImpl.class);
    
    public AsymCryptorRSAImpl(CryptoParams params) throws CryptoNotValidException {
        super(params);
    }

    /**
     * Default RSA encryption, weak, no IV or other data in output. Max message block
     * size is limited to 501 byte in Java implementations, so to encrypt larger message we
     * divide it into slices in 500 bytes, encrypt and concatenate 
     * @param plain plain text
     * @return encrypted text
     * @throws CryptoNotValidException
     */
    @Override
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        try {
            iesCipher.init(Cipher.ENCRYPT_MODE, theirPublicKey);
            byte[] encrypted = iesCipher.doFinal(plain);
            return encrypted;
        } catch (BadPaddingException|IllegalBlockSizeException|InvalidKeyException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Encryption filed", ex);
        }
    }

    /**
     * Default RSA decryption, weak no IV or other data in output
     * @param ciphered encrypted text prefixed with 12 bytes of IV
     * @return decrypted plain text
     * @throws CryptoNotValidException
     */
    @Override
    public byte[] decrypt(byte[] ciphered) throws CryptoNotValidException {
        try {
            iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = iesCipher.doFinal(ciphered);
            return decrypted;
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException  ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Decryption failed", ex);
        }
    }

    @Override
    public AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) {
        throw new UnsupportedOperationException("AEAD is not supported in RSA mode."); 
    }

    @Override
    public AEADPlain decryptWithAEAData(byte[] message) {
        throw new UnsupportedOperationException("AEAD is not supported in RSA mode."); 
    }

}

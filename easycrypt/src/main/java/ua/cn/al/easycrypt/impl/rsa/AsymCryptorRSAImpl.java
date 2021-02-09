/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
            iesCipher.update(plain);
            byte[] encrypted = iesCipher.doFinal();
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

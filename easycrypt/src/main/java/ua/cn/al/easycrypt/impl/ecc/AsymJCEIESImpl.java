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

package ua.cn.al.easycrypt.impl.ecc;

import ua.cn.al.easycrypt.impl.AbstractAsymCryptor;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.AsymCryptor;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AsymJCEIESImpl extends AbstractAsymCryptor implements AsymCryptor {
    
    private static final Logger log = LoggerFactory.getLogger(AsymJCEIESImpl.class);
    private final SecureRandom random = new SecureRandom();

    public AsymJCEIESImpl(CryptoParams params) throws CryptoNotValidException {
        super(params);
    }

    @Override
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        try {
            byte[] iv = new byte[params.getIesIvLen()];
            random.nextBytes(iv);
            IESParameterSpec parameterSpec = new IESParameterSpec(null, null, params.getAesKeyLen() * 8, params.getAesKeyLen() * 8, iv);

            iesCipher.init(Cipher.ENCRYPT_MODE, theirPublicKey, parameterSpec);

            byte[] encrypted = iesCipher.doFinal(plain);

            ByteBuffer bb = ByteBuffer.allocate(encrypted.length + params.getIesIvLen());
            bb.put(iv).put(encrypted);
            return bb.array();
        } catch (InvalidKeyException | InvalidAlgorithmParameterException| IllegalBlockSizeException | BadPaddingException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Ecnryption failed", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphered) throws CryptoNotValidException {
        try {
            byte[] iv = Arrays.copyOf(ciphered, params.getIesIvLen());
            IESParameterSpec parameterSpec = new IESParameterSpec(null, null, params.getAesKeyLen() * 8, params.getAesKeyLen() * 8, iv);

            iesCipher.init(Cipher.DECRYPT_MODE, privateKey, parameterSpec);
            byte[] decrypted = iesCipher.doFinal(ciphered, params.getIesIvLen(), ciphered.length - params.getIesIvLen());
            return decrypted;
        } catch (IllegalBlockSizeException | BadPaddingException| InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Decryption", ex);
        }
    }

    @Override
    public AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) throws CryptoNotValidException {
        throw new UnsupportedOperationException("AEAD operation are NON supported in IES mode");
    }

    @Override
    public AEADPlain decryptWithAEAData(byte[] message) throws CryptoNotValidException {
        throw new UnsupportedOperationException("AEAD operation are NON supported in IES mode");
    }
    
}

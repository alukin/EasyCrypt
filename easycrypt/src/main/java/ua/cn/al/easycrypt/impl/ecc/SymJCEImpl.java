/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
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

import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.CryptoNotValidException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import ua.cn.al.easycrypt.SymCryptor;
import ua.cn.al.easycrypt.dataformat.Ciphered;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
@Slf4j
public class SymJCEImpl implements SymCryptor {

    private static final SecureRandom random = new SecureRandom();
    private boolean saltInMessage = false;
    private SecretKeySpec symmetricKey;

    private final byte[] gcmIV;

    private final CryptoParams params;

    public SymJCEImpl(CryptoParams params) {
        this.params = params;
        gcmIV = new byte[params.getAesIvLen()];
    }

    /**
     * Set key for symmetric cipher
     *
     * @param key 128 or 256 bits key
     * @throws CryptoNotValidException
     */
    @Override
    public void setKey(byte[] key) throws CryptoNotValidException {
        if (!((key.length == 128 / 8) || (key.length == 256 / 8))) {
            throw new IllegalArgumentException("Key length must be exactly 16 or 32 or bytes long");
        }
        symmetricKey = new SecretKeySpec(key, "AES");
    }

    @Override
    public void setIV(byte[] iv) {
        ByteBuffer.wrap(gcmIV).put(iv, 0, gcmIV.length);
    }

    @Override
    public byte[] getIV() {
        return gcmIV;
    }

    @Override
    public void setSalt(byte[] salt) {
        ByteBuffer.wrap(gcmIV).put(salt, 0, params.getAesGcmSaltLen());
    }

    @Override
    public byte[] getSalt() {
        return Arrays.copyOfRange(gcmIV, 0, params.getAesGcmSaltLen());
    }

    @Override
    public void setNonce(byte[] explicitNonce) throws CryptoNotValidException {
        if (Arrays.equals(getNonce(), explicitNonce)) {
            throw new IllegalArgumentException("Nonce reuse detected!");
        }
        byte[] en;
        if (explicitNonce == null) {
            en = new byte[params.getAesGcmNonceLen()];
            random.nextBytes(en);
        } else {
            en = explicitNonce;
        }
        ByteBuffer.wrap(gcmIV).position(params.getAesGcmSaltLen()).put(en, 0, params.getAesGcmNonceLen());
    }

    @Override
    public byte[] getNonce() {
        return Arrays.copyOfRange(gcmIV, params.getAesGcmSaltLen(), gcmIV.length);
    }

    @Override
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        //TODO: avoid data copy, use ByteBuffer somehow
        try {
            Cipher blockCipherSym = getCipher(Cipher.ENCRYPT_MODE);
            byte[] encrypted = new byte[blockCipherSym.getOutputSize(plain.length)];
            int updateSize = blockCipherSym.update(plain, 0, plain.length, encrypted);
            blockCipherSym.doFinal(encrypted, updateSize);
            Ciphered cmsg = new Ciphered();
            cmsg.encrypted = encrypted;
            if (saltInMessage) {
                cmsg.setIV(gcmIV);
            } else {
                cmsg.setExplicitNonce(getNonce());
            }
            cmsg.encrypted = encrypted;
            return cmsg.toBytes();
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | NoSuchAlgorithmException| NoSuchPaddingException  ex) {
            log.warn("Symmatric encryption error", ex);
            throw new CryptoNotValidException(ex.getMessage(), ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphered) throws CryptoNotValidException {
        try {
            Ciphered cmsg = Ciphered.fromBytes(ciphered);

            if (saltInMessage) {
                setIV(cmsg.getIV());
            } else {
                setNonce(cmsg.getExplicitNonce());
            }

            Cipher blockCipherSym = getCipher(Cipher.DECRYPT_MODE);
            byte[] decrypted = new byte[blockCipherSym.getOutputSize(cmsg.encrypted.length)];
            int updateSize = blockCipherSym.update(cmsg.encrypted, 0, cmsg.encrypted.length, decrypted);
            blockCipherSym.doFinal(decrypted, updateSize);
            return decrypted;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
              |NoSuchPaddingException | NoSuchAlgorithmException ex) {
            log.warn("Symmetric decryption error",ex);
            throw new CryptoNotValidException(ex.getMessage(), ex);
        }
    }

    @Override
    public AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) throws CryptoNotValidException {
        try {
            AEADCiphered msg = new AEADCiphered(params);
            Cipher blockCipherSym = getCipher(Cipher.ENCRYPT_MODE);
            if (aeadata != null) {
                blockCipherSym.updateAAD(aeadata);
                msg.aatext = aeadata;
            }
            msg.encrypted = new byte[blockCipherSym.getOutputSize(plain.length)];
            int updateSize = blockCipherSym.update(plain, 0, plain.length, msg.encrypted);
            blockCipherSym.doFinal(msg.encrypted, updateSize);

            if (saltInMessage) {
                msg.setIV(gcmIV);
            } else {
                msg.setExplicitNonce(getNonce());
            }
            return msg;
        } catch (ShortBufferException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | NoSuchAlgorithmException ex) {
            log.warn("AEAD Encryption error", ex);
            throw new CryptoNotValidException(ex.getMessage(), ex);
        }
    }

    @Override
    public AEADPlain decryptWithAEAData(byte[] message) throws CryptoNotValidException {
        AEADPlain res = new AEADPlain();
        AEADCiphered msg = AEADCiphered.fromBytes(message, params);
        if (saltInMessage) {
            setIV(msg.getIV());
        } else {
            setNonce(msg.getExplicitNonce());
        }
        try {
            Cipher blockCipherSym = getCipher(Cipher.DECRYPT_MODE);
            blockCipherSym.updateAAD(msg.aatext);
            res.decrypted = new byte[blockCipherSym.getOutputSize(msg.encrypted.length)];
            int updateSize = blockCipherSym.update(msg.encrypted, 0, msg.encrypted.length, res.decrypted);
            blockCipherSym.doFinal(res.decrypted, updateSize);
            res.plain = msg.aatext;
            res.hmacOk = true;
            return res;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            log.warn("AEAD Decryption error", ex);
            throw new CryptoNotValidException(ex.getMessage(), ex);
        }
    }

    @Override
    public void saltInMessage(boolean b) {
        saltInMessage = b;
    }

    @Override
    public Cipher getCipher(int mode) throws NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher blockCipherSym = Cipher.getInstance(params.getSymCipher());
        GCMParameterSpec gcmParameterSpecSym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), gcmIV);
        try {
            blockCipherSym.init(mode, symmetricKey, gcmParameterSpecSym);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error("Can not create cipher", ex);
        }
        return blockCipherSym;
    }

}

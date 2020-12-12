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
package ua.cn.al.easycrypt.impl.ecc;

import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.CryptoNotValidException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import ua.cn.al.easycrypt.SymCryptor;

/**
 * 
 * @author Oleksiy Lukin alukin@gmail.com
 */

public class SymJCEImpl  implements SymCryptor {

    private static final Logger log = LoggerFactory.getLogger(SymJCEImpl.class);

    private static final SecureRandom random = new SecureRandom();

    private Cipher blockCipherSym;
    private SecretKeySpec symmetricKey;


    private final byte[] gcmIV;

    private final CryptoParams params;

    public SymJCEImpl(CryptoParams params) {
        this.params = params;
        gcmIV=new byte[params.getAesIvLen()];
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
        try {
            symmetricKey = new SecretKeySpec(key, "AES");
            blockCipherSym = Cipher.getInstance(params.getSymCipher());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException(ex.getMessage(), ex);
        }
    }

    @Override
    public void setIV(byte[] iv) {
        ByteBuffer.wrap(gcmIV).put(iv,0,gcmIV.length);
    }

    @Override
    public byte[] getIV() {
        return gcmIV;
    }

    @Override
    public void setSalt(byte[] salt) {
        ByteBuffer.wrap(gcmIV).put(salt,0,params.getAesGcmSaltLen());
    }

    @Override
    public byte[] getSalt() {
        return Arrays.copyOfRange(gcmIV, 0,params.getAesGcmSaltLen());
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
            en=explicitNonce;
        }
        ByteBuffer.wrap(gcmIV).position(params.getAesGcmSaltLen()).put(en,0,params.getAesGcmNonceLen());
    }

    @Override
    public byte[] getNonce() {
        return Arrays.copyOfRange(gcmIV, params.getAesGcmSaltLen(), gcmIV.length);
    }

    @Override
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        //TODO: avoid data copy, use ByteBuffer somehow
        try {
            GCMParameterSpec gcmParameterSpecSym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), gcmIV);
            blockCipherSym.init(Cipher.ENCRYPT_MODE, symmetricKey, gcmParameterSpecSym);
            byte[] encrypted = new byte[blockCipherSym.getOutputSize(plain.length)];
            int updateSize = blockCipherSym.update(plain, 0, plain.length, encrypted);
            blockCipherSym.doFinal(encrypted, updateSize);
            ByteBuffer bb = ByteBuffer.allocate(encrypted.length + params.getAesGcmNonceLen());
            bb.put(getNonce()).put(encrypted);
            return bb.array();
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.warn(ex.getMessage());
            throw new CryptoNotValidException("Invalid symmetric key", ex);
        }
    }

    
    
    @Override
    public byte[] decrypt(byte[] ciphered) throws CryptoNotValidException {
        try {
            setNonce(Arrays.copyOf(ciphered, params.getAesGcmNonceLen()));
            GCMParameterSpec gcmParameterSpecSym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), gcmIV);            
            blockCipherSym.init(Cipher.DECRYPT_MODE, symmetricKey, gcmParameterSpecSym);
            byte[] decrypted = new byte[blockCipherSym.getOutputSize(ciphered.length - params.getAesGcmNonceLen())];
            int updateSize = blockCipherSym.update(ciphered, params.getAesGcmNonceLen(), ciphered.length - params.getAesGcmNonceLen(), decrypted);
            blockCipherSym.doFinal(decrypted, updateSize);
            return decrypted;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.warn(ex.getMessage());
            throw new CryptoNotValidException("Invalid symmetric key", ex);
        }
    }

    @Override
    public AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) throws CryptoNotValidException {
        try {
            AEADCiphered msg = new AEADCiphered(params);
            GCMParameterSpec gcmParameterSpecSym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), gcmIV);            
            blockCipherSym.init(Cipher.ENCRYPT_MODE, symmetricKey, gcmParameterSpecSym);
            if(aeadata != null) {
                blockCipherSym.updateAAD(aeadata);
                msg.aatext = aeadata;
            }
            msg.encrypted = new byte[blockCipherSym.getOutputSize(plain.length)];
            int updateSize = blockCipherSym.update(plain, 0, plain.length, msg.encrypted);
            blockCipherSym.doFinal(msg.encrypted, updateSize);
            msg.setExplicitNonce(getNonce());
            return msg;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.warn(ex.getMessage());
            throw new CryptoNotValidException("Invalid symmetric key", ex);
        }
    }

    @Override
    public AEADPlain decryptWithAEAData(byte[] message) throws CryptoNotValidException {
        AEADPlain res = new AEADPlain();
        AEADCiphered msg = AEADCiphered.fromBytes(message, params);
        setNonce(msg.getExplicitNonce());
        try {
            GCMParameterSpec gcmParameterSpecSym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), gcmIV);
            blockCipherSym.init(Cipher.DECRYPT_MODE, symmetricKey, gcmParameterSpecSym);
            blockCipherSym.updateAAD(msg.aatext);
            res.decrypted = new byte[blockCipherSym.getOutputSize(msg.encrypted.length)];
            int updateSize = blockCipherSym.update(msg.encrypted, 0, msg.encrypted.length, res.decrypted);
            blockCipherSym.doFinal(res.decrypted, updateSize);
            res.plain = msg.aatext;
            res.hmacOk = true;
            return res;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.warn(ex.getMessage());
            throw new CryptoNotValidException("Invalid symmetric key", ex);
        }
    }

}

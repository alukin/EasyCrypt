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

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.impl.AbstractAsymDH;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.cn.al.easycrypt.AsymCryptorDH;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AsymJCEECDHImpl extends AbstractAsymDH implements AsymCryptorDH {
    private static final Logger log = LoggerFactory.getLogger(AsymJCEECDHImpl.class);
    private final SecureRandom random = new SecureRandom();

    public AsymJCEECDHImpl(CryptoParams params) {
        super(params);
    }

    @Override
    public byte[] ecdheStep1() throws CryptoNotValidException{
        KeyGeneratorEC kg = new KeyGeneratorEC(params);       
        ephemeralKeys = kg.generateKeys();
        byte[] key = ephemeralKeys.getPublic().getEncoded();
        byte[] signature = signer.sign(key);
        int capacity = Integer.BYTES+key.length+signature.length;
        ByteBuffer bb = ByteBuffer.allocate(capacity);
        bb.putInt(key.length);
        bb.put(key);
        bb.put(signature);
        return bb.array();
    }

    @Override
    public byte[] ecdheStep2(byte[] signedEphemeralPubKey)  throws CryptoNotValidException{
        ByteBuffer bb = ByteBuffer.wrap(signedEphemeralPubKey);
        int keySize = bb.getInt();
        byte[] key = new byte[keySize];        
        byte[] signature = new byte[signedEphemeralPubKey.length-keySize-Integer.BYTES];
        bb.get(key);
        bb.get(signature);
        boolean ok = signer.verify(key, signature);
        if(!ok){
             throw new CryptoNotValidException("ECDHE public key signature is not valid!");
        }
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("ECDSA", "BC");
            PublicKey theirPub = kf.generatePublic(new X509EncodedKeySpec(key));   
            byte[] skh = doCalculateShared(ephemeralKeys.getPublic(), ephemeralKeys.getPrivate(), theirPub);
            SecretKeySpec sk = new SecretKeySpec(skh, "AES");
            ephemeralKeys=null; //allow GC to clean tmp keys
            return sk.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException ex ) {
            String msg = "Something wrong with public key from other side";
            log.error(msg, ex);
            throw new CryptoNotValidException(msg, ex);
        }
    }
    
    @Override
    protected byte[] doCalculateShared(PublicKey ourPub, PrivateKey ourPriv, PublicKey theirPub) throws NoSuchAlgorithmException, InvalidKeyException{
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", CryptoConfig.getProvider());
            keyAgreement.init(ourPriv);
            keyAgreement.doPhase(theirPub, true);
            byte[] sk = keyAgreement.generateSecret();
            MessageDigest hash = MessageDigest.getInstance(params.getKeyAgreementDigester());
            hash.update(sk);
            // Simple deterministic ordering of keys to get same result on both ends
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPublicKey.getEncoded()), ByteBuffer.wrap(theirPublicKey.getEncoded()));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));
            byte[] skh = hash.digest();  
            return skh;
    }
    
    @Override
    public byte[] calculateSharedKey() {
        try {
            byte[] skh= doCalculateShared(ourPublicKey, privateKey, theirPublicKey);
            sharedKey = new SecretKeySpec(skh, "AES");
            return sharedKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            log.error(ex.getMessage());
        }
        return null;
    }
    
    @Override
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        try {
            byte[] iv = new byte[params.getAesIvLen()];
            random.nextBytes(iv);

            gcmParameterSpecAsym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), iv);
            blockCipherAsym.init(Cipher.ENCRYPT_MODE, sharedKey, gcmParameterSpecAsym);
            byte[] encrypted = new byte[blockCipherAsym.getOutputSize(plain.length)];
            int updateSize = blockCipherAsym.update(plain, 0, plain.length, encrypted);
            blockCipherAsym.doFinal(encrypted, updateSize);
            ByteBuffer bb = ByteBuffer.allocate(encrypted.length + params.getAesIvLen());
            bb.put(iv).put(encrypted);
            return bb.array();
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Encryption filed", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphered) throws CryptoNotValidException {
        try {
            byte[] iv = Arrays.copyOf(ciphered, params.getAesIvLen());
            gcmParameterSpecAsym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), iv);

            blockCipherAsym.init(Cipher.DECRYPT_MODE, sharedKey, gcmParameterSpecAsym);
            byte[] decrypted = new byte[blockCipherAsym.getOutputSize(ciphered.length - params.getAesIvLen())];
            int updateSize = blockCipherAsym.update(ciphered, params.getAesIvLen(), ciphered.length - params.getAesIvLen(), decrypted);
            blockCipherAsym.doFinal(decrypted, updateSize);
            return decrypted;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Decryption failed", ex);
        }
    }

    @Override
    public AEADCiphered encryptWithAEAData(byte[] plain, byte[] aeadata) throws CryptoNotValidException {
        try {
            byte[] iv = new byte[params.getAesIvLen()];
            random.nextBytes(iv);

            gcmParameterSpecAsym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), iv);

            AEADCiphered msg = new AEADCiphered(params);
            blockCipherAsym.init(Cipher.ENCRYPT_MODE, sharedKey, gcmParameterSpecAsym);
            if(aeadata != null) {
                blockCipherAsym.updateAAD(aeadata);
                msg.aatext = aeadata;
            }
            msg.encrypted = new byte[blockCipherAsym.getOutputSize(plain.length)];
            int updateSize = blockCipherAsym.update(plain, 0, plain.length, msg.encrypted);
            blockCipherAsym.doFinal(msg.encrypted, updateSize);
            msg.setIV(iv);
            return msg;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Encryption failed", ex);
        }
    }

    @Override
    public AEADPlain decryptWithAEAData(byte[] message) throws CryptoNotValidException {
        AEADPlain res = new AEADPlain();
        AEADCiphered msg = AEADCiphered.fromBytes(message, params);
        gcmParameterSpecAsym = new GCMParameterSpec(params.getGcmAuthTagLenBits(), msg.getIV());
        try {
            blockCipherAsym.init(Cipher.DECRYPT_MODE, sharedKey, gcmParameterSpecAsym);
            blockCipherAsym.updateAAD(msg.aatext);
            res.decrypted = new byte[blockCipherAsym.getOutputSize(msg.encrypted.length)];
            int updateSize = blockCipherAsym.update(msg.encrypted, 0, msg.encrypted.length, res.decrypted);
            blockCipherAsym.doFinal(res.decrypted, updateSize);
            res.plain = msg.aatext;
            res.hmacOk = true;
            return res;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Encryption failed", ex);
        }
    }
    
}

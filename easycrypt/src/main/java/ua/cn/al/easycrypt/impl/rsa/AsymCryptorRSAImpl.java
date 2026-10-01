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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
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
    private static final byte[] HYBRID_MAGIC = "ECRH".getBytes(StandardCharsets.US_ASCII);
    private static final byte HYBRID_VERSION = 1;
    private static final int HYBRID_HEADER_SIZE = 12;
    private static final int GCM_IV_SIZE = 12;
    private static final int GCM_TAG_SIZE = 16;
    private static final int MAX_HYBRID_PLAINTEXT_SIZE = 64 * 1024 * 1024;
    private static final String RSA_OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final SecureRandom RANDOM = new SecureRandom();
    
    public AsymCryptorRSAImpl(CryptoParams params) throws CryptoNotValidException {
        super(params);
    }

    /**
     * Legacy single-block RSAES-PKCS1-v1_5 encryption. Plaintext is limited to
     * modulusBytes - 11 and this format provides no integrity protection.
     * Prefer {@link #encryptHybrid(byte[])} for new data.
     * @param plain plain text
     * @return encrypted text
     * @throws CryptoNotValidException
     */
    @Override
    @Deprecated
    public byte[] encrypt(byte[] plain) throws CryptoNotValidException {
        requirePublicKey();
        if (plain == null || plain.length > rsaModulusBytes() - 11) {
            throw new CryptoNotValidException("Legacy RSA plaintext exceeds the modulusBytes - 11 limit");
        }
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
        requirePrivateKey();
        try {
            iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = iesCipher.doFinal(ciphered);
            return decrypted;
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException  ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("Decryption failed", ex);
        }
    }

    /** Encrypts arbitrary payloads with AES-256-GCM and wraps the random AES key with RSA-OAEP-SHA256. */
    public byte[] encryptHybrid(byte[] plain) throws CryptoNotValidException {
        requirePublicKey();
        if (plain == null || plain.length > MAX_HYBRID_PLAINTEXT_SIZE) {
            throw new CryptoNotValidException("Hybrid RSA plaintext is null or exceeds " + MAX_HYBRID_PLAINTEXT_SIZE + " bytes");
        }
        byte[] aesKey = new byte[32];
        byte[] iv = new byte[GCM_IV_SIZE];
        RANDOM.nextBytes(aesKey);
        RANDOM.nextBytes(iv);
        try {
            Cipher rsa = Cipher.getInstance(RSA_OAEP);
            rsa.init(Cipher.ENCRYPT_MODE, theirPublicKey, oaepParameters(), RANDOM);
            byte[] wrappedKey = rsa.doFinal(aesKey);
            if (wrappedKey.length > 0xffff) {
                throw new CryptoNotValidException("RSA wrapped key is too large for the hybrid envelope");
            }
            int encryptedLength = Math.addExact(plain.length, GCM_TAG_SIZE);
            ByteBuffer header = ByteBuffer.allocate(HYBRID_HEADER_SIZE);
            header.put(HYBRID_MAGIC).put(HYBRID_VERSION).putShort((short) wrappedKey.length)
                    .put((byte) iv.length).putInt(encryptedLength);
            byte[] headerBytes = header.array();

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv), RANDOM);
            aes.updateAAD(headerBytes);
            byte[] encrypted = aes.doFinal(plain);

            ByteBuffer envelope = ByteBuffer.allocate(HYBRID_HEADER_SIZE + wrappedKey.length + iv.length + encrypted.length);
            envelope.put(headerBytes).put(wrappedKey).put(iv).put(encrypted);
            return envelope.array();
        } catch (GeneralSecurityException | ArithmeticException ex) {
            throw new CryptoNotValidException("Hybrid RSA encryption failed", ex);
        } finally {
            java.util.Arrays.fill(aesKey, (byte) 0);
        }
    }

    /** Decrypts a version 1 hybrid envelope produced by {@link #encryptHybrid(byte[])}. */
    public byte[] decryptHybrid(byte[] envelope) throws CryptoNotValidException {
        requirePrivateKey();
        if (envelope == null || envelope.length < HYBRID_HEADER_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE) {
            throw new CryptoNotValidException("Truncated hybrid RSA envelope");
        }
        ByteBuffer input = ByteBuffer.wrap(envelope);
        byte[] magic = new byte[HYBRID_MAGIC.length];
        input.get(magic);
        byte version = input.get();
        int wrappedKeyLength = Short.toUnsignedInt(input.getShort());
        int ivLength = Byte.toUnsignedInt(input.get());
        int encryptedLength = input.getInt();
        long expectedLength = (long) HYBRID_HEADER_SIZE + wrappedKeyLength + ivLength + encryptedLength;
        if (!java.util.Arrays.equals(magic, HYBRID_MAGIC) || version != HYBRID_VERSION
                || wrappedKeyLength == 0 || ivLength != GCM_IV_SIZE || encryptedLength < GCM_TAG_SIZE
                || encryptedLength > MAX_HYBRID_PLAINTEXT_SIZE + GCM_TAG_SIZE || expectedLength != envelope.length) {
            throw new CryptoNotValidException("Invalid hybrid RSA envelope header or lengths");
        }
        byte[] header = java.util.Arrays.copyOf(envelope, HYBRID_HEADER_SIZE);
        byte[] wrappedKey = new byte[wrappedKeyLength];
        byte[] iv = new byte[ivLength];
        byte[] encrypted = new byte[encryptedLength];
        input.get(wrappedKey).get(iv).get(encrypted);
        byte[] aesKey = null;
        try {
            Cipher rsa = Cipher.getInstance(RSA_OAEP);
            rsa.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters());
            aesKey = rsa.doFinal(wrappedKey);
            if (aesKey.length != 32) {
                throw new CryptoNotValidException("Hybrid envelope did not contain a valid AES-256 key");
            }
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
            aes.updateAAD(header);
            return aes.doFinal(encrypted);
        } catch (GeneralSecurityException ex) {
            throw new CryptoNotValidException("Hybrid RSA decryption or authentication failed", ex);
        } finally {
            if (aesKey != null) {
                java.util.Arrays.fill(aesKey, (byte) 0);
            }
        }
    }

    private static OAEPParameterSpec oaepParameters() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    private int rsaModulusBytes() throws CryptoNotValidException {
        if (!(theirPublicKey instanceof RSAKey rsaKey)) {
            throw new CryptoNotValidException("RSA public key has not been configured");
        }
        return (rsaKey.getModulus().bitLength() + 7) / 8;
    }

    private void requirePublicKey() throws CryptoNotValidException {
        if (theirPublicKey == null) {
            throw new CryptoNotValidException("Recipient RSA public key has not been configured");
        }
    }

    private void requirePrivateKey() throws CryptoNotValidException {
        if (privateKey == null) {
            throw new CryptoNotValidException("RSA private key has not been configured");
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

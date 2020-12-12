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

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.impl.AbstractKeyGenerator;
import ua.cn.al.easycrypt.impl.NotRandom;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generators for crypto keys and nonce
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class KeyGeneratorRSA extends AbstractKeyGenerator {
    private static final Logger log = LoggerFactory.getLogger(KeyGeneratorRSA.class);
    
    public KeyGeneratorRSA(CryptoParams params) {
        super(params);
    }
    
    
    private KeyFactory getKeyFactory() throws NoSuchAlgorithmException, NoSuchProviderException{
        KeyFactory factory = KeyFactory.getInstance("RSA", CryptoConfig.getProvider());
        return factory;
    }

    private KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException{
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", CryptoConfig.getProvider());
        return g;
    }
    
    /**
     * Generated true secure ECC or RSA key pair using secure random number generator
     *
     * @return key pair
     */
    @Override
    public KeyPair generateKeys() {
        KeyPair pair = null;
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(params.getDefaultCurve());
        try {
            KeyPairGenerator g = getKeyPairGenerator();
            g.initialize(ecSpec, new SecureRandom());
            pair = g.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            log.error(ex.getMessage());
        }
        return pair;
    }

    /**
     * Generate deterministic ECC key pair using defaultCurve and
     * passphrase.Well, obviously all the security depends on randomness of
     * passphrase!
     *
     * @param secretPhrase long enough and random enough pass phrase. You've
     * been warned!
     * @param salt some random number, recommended size is 16 bytes
     * @return EEC key pair
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    @Override
    public KeyPair generateKeys(String secretPhrase, byte[] salt) throws CryptoNotValidException {
        KeyPair pair = null;
        byte[] hash = deriveFromSecretPhrase(secretPhrase, salt, NOT_RANDOM_LEN);

        KeyPairGenerator g;
        try {
            g = getKeyPairGenerator();
            NotRandom srand = new NotRandom();
            srand.setSeed(hash);
            g.initialize(params.getBaseKeyLen(), srand);
            pair = g.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException  ex) {
            String msg = "Invalid key generation parameters.";
            log.error(msg, ex);
            throw new CryptoNotValidException(msg, ex);
        }
        return pair;
    }

    /**
     * Generate ECDSA PublicKey X509 encoded
     *
     * @param bytes
     * @return
     */
    @Override
    public PublicKey createPublicKeyFromBytes(byte[] bytes) {
        PublicKey result = null;
        try {
            KeyFactory factory = KeyFactory.getInstance("ECDSA", "BC");
            result = factory.generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchProviderException | NoSuchAlgorithmException ex) {
            log.error(ex.getMessage());
        }
        return result;
    }

    /**
     * Simple deterministic key derivation function. It is one-way function. It
     * calculates hash (defined in params) of secretPhrase.getBytes() and salt.
     * If there is not enough bytes (keyLen) it uses hash result and the same
     * salt again and puts additional bytes to output.
     *
     * @param secretPhrase UTF-8 encoded string
     * @param salt random salt at least of 16 bytes
     * @param keyLen desired output lenght
     * @return array of bytes that is determined by secretPhrase ans salt. It is
     * hard to calculate secretPhrase from it because it uses string
     * cryptographic hashing function SHA-512
     * @throws CryptoNotValidException
     */
    @Override
    public byte[] deriveFromSecretPhrase(String secretPhrase, byte[] salt, int keyLen) throws CryptoNotValidException {
        ByteBuffer bb = ByteBuffer.allocate(keyLen);
        int haveBytes = 0;
        byte[] input = secretPhrase.getBytes();
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            while (haveBytes < keyLen) {
                hash.update(input);
                hash.update(salt);
                byte[] digest = hash.digest();
                haveBytes += digest.length;
                try {
                    bb.put(digest);
                    input = digest;
                } catch (BufferOverflowException e) {
                    break;
                }
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoNotValidException("Digest is not available", ex);
        }
        return bb.array();
    }

}

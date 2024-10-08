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

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.impl.AbstractKeyGenerator;
import ua.cn.al.easycrypt.impl.NotRandom;
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
}

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

package ua.cn.al.easycrypt.identity.cert;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.Signature;
import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoParams;

/**
 * Base class for certificate and CSR
 * Also holds private key of certificate
 *
 * @author alukin@gmail.com
 */
public class CertBase {
    public static final int ACTOR_ID_LENGTH = 256/8; //32 bytes or 256 bit of Actor ID
    
    protected PublicKey pubKey = null;
    protected CryptoParams params = CryptoConfig.createDefaultParams();
    protected CryptoFactory factory = CryptoFactory.newInstance(params);
    
    /**
     * Checks that the supplied private key corresponds to this object's public
     * key by signing and verifying a fresh challenge. Returns false for null,
     * incompatible, or unsupported keys.
     */
    public boolean checkKeys(PrivateKey pvtk) {
        if (pvtk == null || pubKey == null || !keyFamily(pvtk.getAlgorithm()).equals(keyFamily(pubKey.getAlgorithm()))) {
            return false;
        }
        try {
            String keyAlgorithm = pubKey.getAlgorithm();
            String signatureAlgorithm = switch (keyAlgorithm.toUpperCase(java.util.Locale.ROOT)) {
                case "RSA" -> "SHA256withRSA";
                case "EC", "ECDSA" -> "SHA256withECDSA";
                case "ED25519" -> "Ed25519";
                default -> null;
            };
            if (signatureAlgorithm == null) {
                return false;
            }
            byte[] challenge = new byte[32];
            new java.security.SecureRandom().nextBytes(challenge);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(pvtk);
            signature.update(challenge);
            byte[] signedChallenge = signature.sign();
            signature.initVerify(pubKey);
            signature.update(challenge);
            return signature.verify(signedChallenge);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    public PublicKey getPublicKey() {
        return pubKey;
    }

    private static String keyFamily(String algorithm) {
        String normalized = algorithm.toUpperCase(java.util.Locale.ROOT);
        return "ECDSA".equals(normalized) ? "EC" : normalized;
    }

}

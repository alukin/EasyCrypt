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
package ua.cn.al.easycrypt;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * Purpose of this helper is creating the crypto factory instance
 * given a set of parameters consistent for the certain cryptosystem.
 * All we need  is to guess parameters is X.509 certificate or public key.
 * ECC with curves secp521r1, secp256k1, prime256v1 is supported
 * RSA with key length 2048,4096, 8192, 16384 is also supported
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptoFactoryHelper {
    private CryptoFactoryHelper() {
    }

    /**
     * Create cryptographic system using public key
     *
     * @param pubKey public key that defines cryptoprimitives to be used
     * @return CryptoFactory with all parameters set consistently
     */
    public static CryptoFactory createFactory(PublicKey pubKey) {
        CryptoParams params;
        String algo = pubKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algo)) {
            RSAPublicKey rpk = (RSAPublicKey) pubKey;
            int bitLength = rpk.getModulus().bitLength();
            params = CryptoConfig.createRSAn(bitLength);
        } else if ("EC".equalsIgnoreCase(algo)) {
            //TODO: implement different params
            params = CryptoConfig.createDefaultParams();
        } else {
            params = CryptoConfig.createDefaultParams();
        }
        return CryptoFactory.newInstance(params);
    }

    public static CryptoFactory createFactory(X509Certificate cert) {
        PublicKey pk = cert.getPublicKey();
        return createFactory(pk);
    }

    /**
     * Create cryptographic system on best guess using just signature algorithm name and length
     * Useful sometimes for similar signature creation. Please use with care
     *
     * @param sigAlgName Supported names: SHA256withRSA, SHA384withRSA, SHA512withRSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA
     * @return CryptoFactory with all parameters set consistently
     */
    public static CryptoFactory createFactory(String sigAlgName) {
        CryptoParams params;
        if ("SHA256withRSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createRSAn(2048);
        } else if ("SHA384withRSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createRSAn(4096);
        } else if ("SHA512withRSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createRSAn(8192);
        } else if ("SHA256withECDSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createSecp256k1();
        } else if ("SHA384withECDSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createSecp256k1();
        } else if ("SHA512withECDSA".equalsIgnoreCase(sigAlgName)) {
            params = CryptoConfig.createSecp521r1(); //it is default
        } else {
            params = CryptoConfig.createDefaultParams();
        }

        return CryptoFactory.newInstance(params);
    }

    public static CryptoFactory createFactory(CryptoParams p) {
        return CryptoFactory.newInstance(p);
    }

    //TODO: fluent style parameter setting
    public static CryptoFactory createFactory(CryptoConfig.CryptoSystem cs) {
        CryptoFactory newFactory;
        switch (cs) {
            case ECC_SECP521R1:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createSecp521r1());
                break;
            case ECC_SECP256K1:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createSecp256k1());
                break;
            case ECC_PRIME256256V1:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createPrime256v1());
                break;
            case RSA_2048:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createRSAn(2048));
                break;
            case RSA_4096:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createRSAn(4096));
                break;
            case RSA_8192:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createRSAn(8192));
                break;
            case RSA_16384:
                newFactory = CryptoFactory.newInstance(CryptoConfig.createRSAn(16384));
                break;
            default: {
                newFactory = CryptoFactory.newInstance();
            }
        }
        return newFactory;
    }
}

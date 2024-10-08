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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Configuration parameters for all EasyCrypt library
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptoConfig {
    private static final Logger log = LoggerFactory.getLogger(CryptoConfig.class);

    private static Provider provider;

    //register bouncy castle provider
    static {
        if (!setBCProvider())
            throw new IllegalStateException();
    }

    public static Provider getProvider() {
        return provider;
    }

    public static boolean setBCProvider() {
        //this will work with JDK 1.8 update 162 and later.
        //Otherwise you should download unlimited policy from oracle
        Security.setProperty("crypto.policy", "unlimited");
        
        provider = new BouncyCastleProvider();
            //(Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance();
    

        if (provider != null) {
            Security.addProvider(provider);
            //we can not add BC as first provider because of bug in OkHttpClient
            //int pos = Security.insertProviderAt(provider, 1);
            return true;
        } else {
            log.error("Can't instantiate the security provider.");
            return false;
        }
    }

    private CryptoConfig() {
    }

    /**
     * Supported crypto systems.
     * Crypto system means cositent set of algorithms and parameters
     * for signatures, hashes, symmetric and asymmetric encryption
     *
     * @author alukin@gmail.com
     */
    public enum CryptoSystem {
        ECC_SECP521R1,
        ECC_SECP256K1,
        ECC_PRIME256256V1,
        RSA_2048,
        RSA_4096,
        RSA_8192,
        RSA_16384
    }

    public static CryptoParams createDefaultParams() {
        return createSecp521r1();
    }

    public static CryptoParams createSecp521r1() {
        CryptoParams.CryptoParamsBuilder builder = new CryptoParams.CryptoParamsBuilder()
                .signatureSchema("EC") //EC only for Oracle provider
                .baseKeyLen(521)
                .defaultCurve("secp521r1")
                .symCipher("AES/GCM/NoPadding")
                .asymCipher("AES/GCM/NoPadding")
                .asymIesCipher("ECIESwithAES-CBC")
                .digester("SHA-512")
                .signatureAlgorythm("SHA512withECDSA")
                .keyDerivationFn("PBKDF2WithHmacSHA256") //produces 256 bit key
                .pbkdf2Iterations(16)
                .gcmAuthTagLenBits(128)
                .aesIvLen(12) //12 bytes
                .iesIvLen(16) //16 bytes
                .aesKeyLen(256 / 8) //32 bytes
                .aesGcmSaltLen(4) //4 of 12 bytes
                .aesGcmNonceLen(8) //8 of 12 bytes
                .keyAgreementDigester("SHA-256");
        return builder.build();
    }

    public static CryptoParams createRSAn(int keylen) {
        if (keylen < 2048 || keylen > 16384) {
            log.error("Unsupported key length: {}", keylen);
            return null;
        }
        CryptoParams.CryptoParamsBuilder builder = new CryptoParams.CryptoParamsBuilder()
                .signatureSchema("RSA") //EC only for Oracle provider
                .defaultCurve("")
                .symCipher("AES/GCM/NoPadding")
                .asymCipher("AES/GCM/NoPadding")
                .asymIesCipher("RSA/ECB/PKCS1Padding")
                .keyDerivationFn("PBKDF2WithHmacSHA256") //produces 256 bit key
                .pbkdf2Iterations(16)
                .gcmAuthTagLenBits(128)
                .aesIvLen(12) //12 bytes
                .iesIvLen(16) //16 bytes
                .aesKeyLen(256 / 8) //32 bytes
                .aesGcmSaltLen(4) //4 of 12 bytes
                .aesGcmNonceLen(8) //8 of 12 bytes
                .keyAgreementDigester("SHA-256");
        if (keylen == 2048) {
            builder.baseKeyLen(2048).digester("SHA-256").signatureAlgorythm("SHA256withRSA");
        } else if (keylen <= 4096) {
            builder.baseKeyLen(4096).digester("SHA-384").signatureAlgorythm("SHA384withRSA");
        } else if (keylen <= 8192) { // > 4K means 8K
            builder.baseKeyLen(8192).digester("SHA-512").signatureAlgorythm("SHA512withRSA");
        } else if (keylen <= 16384) { // > 8K means 16K
            builder.baseKeyLen(16384).digester("SHA-512").signatureAlgorythm("SHA512withRSA");
        }
        return builder.build();
    }

    public static CryptoParams createSecp256k1() {
        CryptoParams.CryptoParamsBuilder builder = new CryptoParams.CryptoParamsBuilder()
                .signatureSchema("EC") //EC only for Oracle provider
                .baseKeyLen(256)
                .defaultCurve("secp256k1")
                .symCipher("AES/GCM/NoPadding")
                .asymCipher("AES/GCM/NoPadding")
                .asymIesCipher("ECIESwithAES-CBC")
                .digester("SHA-256")
                .signatureAlgorythm("SHA256withECDSA")
                .keyDerivationFn("PBKDF2WithHmacSHA256") //produces 256 bit key
                .pbkdf2Iterations(16)
                .gcmAuthTagLenBits(128)
                .aesIvLen(12) //12 bytes
                .iesIvLen(16) //16 bytes
                .aesKeyLen(128 / 8) //16 bytes
                .aesGcmSaltLen(4) //4 of 12 bytes
                .aesGcmNonceLen(8) //8 of 12 bytes
                .keyAgreementDigester("SHA-256");
        return builder.build();
    }

    public static CryptoParams createPrime256v1() {
        CryptoParams.CryptoParamsBuilder builder = new CryptoParams.CryptoParamsBuilder()
                .signatureSchema("EC") //EC only for Oracle provider
                .baseKeyLen(256)
                .defaultCurve("prime256v1")
                .symCipher("AES/GCM/NoPadding")
                .asymCipher("AES/GCM/NoPadding")
                .asymIesCipher("ECIESwithAES-CBC")
                .digester("SHA-256")
                .signatureAlgorythm("SHA256withECDSA")
                .keyDerivationFn("PBKDF2WithHmacSHA256") //produces 256 bit key
                .pbkdf2Iterations(16)
                .gcmAuthTagLenBits(128)
                .aesIvLen(12) //12 bytes
                .iesIvLen(16) //16 bytes
                .aesKeyLen(128 / 8) //16 bytes
                .aesGcmSaltLen(4) //4 of 12 bytes
                .aesGcmNonceLen(8) //8 of 12 bytes
                .keyAgreementDigester("SHA-256");
        return builder.build();
    }
}

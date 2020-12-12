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
package ua.cn.al.easycrypt;

/**
 * Configuration parameters for all FBCrypto library
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptoParams {
    public static final String PBKDF2_KEY_DERIVATION_FN = "PBKDF2WithHmacSHA256"; //produces 256 bit key
    public static final int PBKDF2_ITERATIONS = 16;
    public static final int PBKDF2_KEYELEN = 256; //256 bits for AES

    public static final int GCM_AUTH_TAG_LEN_BITS = 128; //128 bits
    public static final int AES_IV_LEN = 12; //12 bytes

    protected int baseKeyLen;
    protected String signatureSchema;
    protected String defaultCurve;
    protected String symCipher;
    protected String asymCipher;
    // for RSA it is just RSA, for EC is depends
    protected String asymIesCipher;
    protected String digester;
    protected String signatureAlgorythm;
    protected String keyDerivationFn;
    protected int pbkdf2Iterations;
    protected int gcmAuthTagLenBits;
    protected int symIvLen;
    protected int iesIvLen;
    protected int symKeyLen;
    protected int symGcmSaltLen;
    protected int symGcmNonceLen;
    protected String keyAgreementDigester;

    protected CryptoParams() {
    }

    public CryptoParams(int baseKeyLen, String signatureSchema, String defaultCurve, String symCipher, String asymCipher, String asymIesCipher, String digester, String signatureAlgorythm, String keyDerivationFn, int pbkdf2Iterations, int gcmAuthTagLenBits, int aesIvLen, int iesIvLen, int aesKeyLen, int aesGcmSaltLen, int aesGcmNonceLen, String keyAgreementDigester) {
        this.baseKeyLen = baseKeyLen;
        this.signatureSchema = signatureSchema;
        this.defaultCurve = defaultCurve;
        this.symCipher = symCipher;
        this.asymCipher = asymCipher;
        this.asymIesCipher = asymIesCipher;
        this.digester = digester;
        this.signatureAlgorythm = signatureAlgorythm;
        this.keyDerivationFn = keyDerivationFn;
        this.pbkdf2Iterations = pbkdf2Iterations;
        this.gcmAuthTagLenBits = gcmAuthTagLenBits;
        this.symIvLen = aesIvLen;
        this.iesIvLen = iesIvLen;
        this.symKeyLen = aesKeyLen;
        this.symGcmSaltLen = aesGcmSaltLen;
        this.symGcmNonceLen = aesGcmNonceLen;
        this.keyAgreementDigester = keyAgreementDigester;
    }

    public String getSignatureSchema() {
        return signatureSchema;
    }

    public String getDefaultCurve() {
        return defaultCurve;
    }

    public String getSymCipher() {
        return symCipher;
    }

    public String getAsymCipher() {
        return asymCipher;
    }

    public String getAsymIesCipher() {
        return asymIesCipher;
    }

    public String getDigester() {
        return digester;
    }

    public String getSignatureAlgorythm() {
        return signatureAlgorythm;
    }

    public String getKeyDerivationFn() {
        return keyDerivationFn;
    }

    public int getPbkdf2Iterations() {
        return pbkdf2Iterations;
    }

    public int getGcmAuthTagLenBits() {
        return gcmAuthTagLenBits;
    }

    public int getAesIvLen() {
        return symIvLen;
    }

    public int getIesIvLen() {
        return iesIvLen;
    }

    public int getAesKeyLen() {
        return symKeyLen;
    }

    public int getAesGcmSaltLen() {
        return symGcmSaltLen;
    }

    public int getAesGcmNonceLen() {
        return symGcmNonceLen;
    }

    public String getKeyAgreementDigester() {
        return keyAgreementDigester;
    }
    
    public int getBaseKeyLen(){
        return baseKeyLen;
    }
    
    @Override
    public String toString() {
        String res = 
                "baseKeyLen: " + baseKeyLen+"\n"+
                "signatureSchema: "+signatureSchema+"\n"+
                "defaultCurve: "+ defaultCurve+"\n"+
                "symCipher: "+symCipher+"\n"+
                "asymCipher: "+asymCipher+"\n"+
                "asymIesCipher: "+asymCipher+"\n"+
                "digester: "+digester+"\n"+
                "signatureAlgorythm: "+signatureAlgorythm+"\n"+
                "keyDerivationFn: "+keyDerivationFn+"\n"+
                "pbkdf2Iterations: "+pbkdf2Iterations+"\n"+
                "gcmAuthTagLenBits: "+gcmAuthTagLenBits+"\n"+
                "symIvLen: "+symIvLen+"\n"+
                "iesIvLen: "+iesIvLen+"\n"+
                "symKeyLen: "+symKeyLen+"\n"+
                "symGcmSaltLen: "+symGcmSaltLen+"\n"+
                "symGcmNonceLen: "+symGcmNonceLen+"\n"+
                "keyAgreementDigester: "+keyAgreementDigester;
        return res;
    }
    
    public static class CryptoParamsBuilder {
        private int baseKeyLen;
        private String signatureSchema;
        private String defaultCurve;
        private String symCipher;
        private String asymCipher;
        private String asymIesCipher;
        private String digester;
        private String signatureAlgorythm;
        private String keyDerivationFn;
        private int pbkdf2Iterations;
        private int gcmAuthTagLenBits;
        private int aesIvLen;
        private int iesIvLen;
        private int aesKeyLen;
        private int aesGcmSaltLen;
        private int aesGcmNonceLen;
        private String keyAgreementDigester;

        public CryptoParamsBuilder baseKeyLen(int baseKeyLen) {
            this.baseKeyLen = baseKeyLen;
            return this;
        }

        public CryptoParamsBuilder signatureSchema(String signatureSchema) {
            this.signatureSchema = signatureSchema;
            return this;
        }

        public CryptoParamsBuilder defaultCurve(String defaultCurve) {
            this.defaultCurve = defaultCurve;
            return this;
        }

        public CryptoParamsBuilder symCipher(String symCipher) {
            this.symCipher = symCipher;
            return this;
        }

        public CryptoParamsBuilder asymCipher(String asymCipher) {
            this.asymCipher = asymCipher;
            return this;
        }

        public CryptoParamsBuilder asymIesCipher(String asymIesCipher) {
            this.asymIesCipher = asymIesCipher;
            return this;
        }

        public CryptoParamsBuilder digester(String digester) {
            this.digester = digester;
            return this;
        }

        public CryptoParamsBuilder signatureAlgorythm(String signatureAlgorythm) {
            this.signatureAlgorythm = signatureAlgorythm;
            return this;
        }

        public CryptoParamsBuilder keyDerivationFn(String keyDerivationFn) {
            this.keyDerivationFn = keyDerivationFn;
            return this;
        }

        public CryptoParamsBuilder pbkdf2Iterations(int pbkdf2Iterations) {
            this.pbkdf2Iterations = pbkdf2Iterations;
            return this;
        }

        public CryptoParamsBuilder gcmAuthTagLenBits(int gcmAuthTagLenBits) {
            this.gcmAuthTagLenBits = gcmAuthTagLenBits;
            return this;
        }

        public CryptoParamsBuilder aesIvLen(int aesIvLen) {
            this.aesIvLen = aesIvLen;
            return this;
        }

        public CryptoParamsBuilder iesIvLen(int iesIvLen) {
            this.iesIvLen = iesIvLen;
            return this;
        }

        public CryptoParamsBuilder aesKeyLen(int aesKeyLen) {
            this.aesKeyLen = aesKeyLen;
            return this;
        }

        public CryptoParamsBuilder aesGcmSaltLen(int aesGcmSaltLen) {
            this.aesGcmSaltLen = aesGcmSaltLen;
            return this;
        }

        public CryptoParamsBuilder aesGcmNonceLen(int aesGcmNonceLen) {
            this.aesGcmNonceLen = aesGcmNonceLen;
            return this;
        }

        public CryptoParamsBuilder keyAgreementDigester(String keyAgreementDigester) {
            this.keyAgreementDigester = keyAgreementDigester;
            return this;
        }

        public CryptoParams build() {
            return new CryptoParams(baseKeyLen, signatureSchema, defaultCurve, symCipher, asymCipher, asymIesCipher,
                    digester, signatureAlgorythm, keyDerivationFn, pbkdf2Iterations, gcmAuthTagLenBits,
                    aesIvLen, iesIvLen, aesKeyLen, aesGcmSaltLen, aesGcmNonceLen, keyAgreementDigester);
        }
    }

}

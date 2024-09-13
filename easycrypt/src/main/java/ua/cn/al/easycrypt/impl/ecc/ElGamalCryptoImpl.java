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

package ua.cn.al.easycrypt.impl.ecc;

import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.ElGamalCrypto;
import ua.cn.al.easycrypt.ElGamalKeyPair;
import ua.cn.al.easycrypt.dataformat.ElGamalEncryptedMessage;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;

/**
 * @author Serhiy Lymar serhiy.lymar@gmail.com
 * @author Oleksiy Lukin alukin@gmail.com
 */

public class ElGamalCryptoImpl implements ElGamalCrypto {
    private static final Logger log = LoggerFactory.getLogger(ElGamalCryptoImpl.class);

    private PrivateKey privateKey;
    private PublicKey ourPublicKey;
    private PublicKey theirPublicKey;

    private KeyPair ourKeyPair;

    private final CryptoParams params;

    private ECDomainParameters eCDomainParameters;
    private ECCurve curve;

    private ECPublicKeyParameters _theirPublicKey;
    private ECPublicKeyParameters _ourPublicKey;
    private ECPrivateKeyParameters _privateKey;

    public ECCurve getCurve() {
        return curve;
    }

    public ECPoint extrapolateECPoint(BigInteger x, BigInteger y) {
        ECPoint pkz = curve.createPoint(x, y);
        return pkz;
    }

    public ECDomainParameters getECDomainParameters() {
        return eCDomainParameters;
    }

    public ElGamalCryptoImpl(CryptoParams params) {
        this.params = params;
        setCurveParameters();
    }

    private void setCurveParameters() {
        String curveID = params.getDefaultCurve();

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveID);
        ECCurve curveEntry = spec.getCurve();

        BigInteger fieldSize = curveEntry.getField().getCharacteristic();
        BigInteger coefA = curveEntry.getA().toBigInteger();
        BigInteger coefB = curveEntry.getB().toBigInteger();
        BigInteger curveOrder = curveEntry.getOrder();
        BigInteger cofactor = curveEntry.getCofactor();

        this.curve = new ECCurve.Fp(
                fieldSize, // q
                coefA,
                coefB,
                curveOrder,
                cofactor
        );

        ECPoint Gx = spec.getG();

        ECDomainParameters dparams = new ECDomainParameters(
                curve,
                Gx,
                curveOrder);
        this.eCDomainParameters = dparams;
    }


    public void setAsymmetricKeysBC(ECPublicKeyParameters ourPubkey, ECPrivateKeyParameters privKey, ECPublicKeyParameters theirPubKey) throws InvalidKeyException {
        setCurveParameters();
        setPrivateKeyBC(privKey);
        setMyPublicKeyBC(ourPubkey);
        setHisPublicKeyBC(theirPubKey);
    }

    public void doInternalTesting() {
        setCurveParameters();

        BigInteger rx = new BigInteger(eCDomainParameters.getN().bitLength() - 1, new SecureRandom());
        // doTest(priKey, pRandom, rand);
        log.debug("rx: {}", rx.toString());
        ElGamalEncryptedMessage cryptogram = asymEncryptInternal(_ourPublicKey, rx);

        log.debug("M1.X: {}" + cryptogram.getM1().getRawXCoord().toBigInteger().toString(16));
        log.debug("M1.Y: {}" + cryptogram.getM1().getRawYCoord().toBigInteger().toString(16));
        log.debug("M2.   {}: " + cryptogram.getM2().toString(16));

        BigInteger restored = asymDecryptInternal(_privateKey, cryptogram);

        System.out.println("restored : " + restored.toString());

        if (restored.equals(rx)) {
            log.debug("Test passed successfully");
        } else {
            log.debug("Error: ElGamal Encryption scheme is not valid!");
        }

    }

    private BigInteger asymDecryptCoreRoutine(BigInteger priKey, ElGamalEncryptedMessage cryptogram) {
        ECPoint M1 = cryptogram.getM1();
        BigInteger M2 = cryptogram.getM2();
        BigInteger n = eCDomainParameters.getN(); // priKey.getParameters().getN();
        ECPoint CT = M1.multiply(priKey).normalize();
        BigInteger c = CT.getRawXCoord().toBigInteger();
        BigInteger cInv = c.modInverse(n);
        BigInteger restoredText = M2.multiply(cInv).mod(n);
        return restoredText;
    }


    private BigInteger asymDecryptInternal(ECPrivateKeyParameters priKey, ElGamalEncryptedMessage cryptogram) {
        return asymDecryptCoreRoutine(priKey.getD(), cryptogram);
    }

    private BigInteger asymDecryptInternal(BigInteger priKey, ElGamalEncryptedMessage cryptogram) {
        return asymDecryptCoreRoutine(priKey, cryptogram);
    }

    void setPrivateKeyBC(ECPrivateKeyParameters privKey) {
        this._privateKey = privKey;
    }

    void setPrivateKey(PrivateKey privKey) {
        this.privateKey = privKey;
        BCECPrivateKey prikey = (BCECPrivateKey) this.privateKey;

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                prikey.getD(),
                this.eCDomainParameters);
        this._privateKey = priKey;

    }

    void setMyPublicKeyBC(ECPublicKeyParameters myPublicKey) {
        this._ourPublicKey = myPublicKey;
    }

    void setMyPublicKey(PublicKey myPublicKey) {
        this.ourPublicKey = myPublicKey;

        ECPublicKey pkx = (ECPublicKey) this.ourPublicKey;

        java.security.spec.ECPoint ppub = pkx.getW();

        BigInteger X = ppub.getAffineX();
        BigInteger Y = ppub.getAffineY();

        ECPoint pkz = curve.createPoint(X, Y);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                pkz,
                this.eCDomainParameters);

        this._ourPublicKey = pubKey;
    }

    void setHisPublicKeyBC(ECPublicKeyParameters hisPublicKey) {
        this._theirPublicKey = hisPublicKey;
    }

    void setHisPublicKey(PublicKey hisPublicKey) {
        this.theirPublicKey = hisPublicKey;

        ECPublicKey pkx = (ECPublicKey) this.theirPublicKey;

        java.security.spec.ECPoint ppub = pkx.getW();

        BigInteger X = ppub.getAffineX();
        BigInteger Y = ppub.getAffineY();

        ECPoint pkz = curve.createPoint(X, Y);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                pkz,
                this.eCDomainParameters);

        this._theirPublicKey = pubKey;
    }


    private ElGamalEncryptedMessage asymEncryptInternalCore(ECPublicKeyParameters pubKey, BigInteger value) {
        BigInteger k;

        SecureRandom rx = new SecureRandom();
        ECPoint base = pubKey.getParameters().getG();
        BigInteger n = pubKey.getParameters().getN();
        do {
            BigInteger modulus = n;
            k = new BigInteger(521, rx);
            k = k.mod(modulus);
        } while ((k.compareTo(BigInteger.ZERO) == 0) || (k.compareTo(BigInteger.ONE) == 0));

        // System.out.println("K: " + k.toString(16) );

        ECPoint CB = base.multiply(k).normalize();

        ECPoint publicKey = pubKey.getQ().normalize();
        ECPoint CS = publicKey.multiply(k).normalize();
        BigInteger cx = CS.getRawXCoord().toBigInteger();// x();
        ECPoint M1 = CB;
        BigInteger M2 = value.multiply(cx).mod(n);

        ElGamalEncryptedMessage encryptedMessage = new ElGamalEncryptedMessage();

        encryptedMessage.setM1(M1);
        encryptedMessage.setM2(M2);

        return encryptedMessage;
    }

    private ElGamalEncryptedMessage asymEncryptInternal(ECPublicKeyParameters pubKey, BigInteger value) {
        return asymEncryptInternalCore(pubKey, value);
    }

    private ElGamalEncryptedMessage asymEncryptInternal(BigInteger pubKeyX, BigInteger pubKeyY, BigInteger value) {

        ECPoint pkz = curve.createPoint(pubKeyX, pubKeyY);

        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                pkz,
                this.eCDomainParameters);

        return asymEncryptInternalCore(pubKey, value);
    }

//
//    @Override
//    public void setOurKeyPair(KeyPair keyPair) {
//        this.ourKeyPair = keyPair;
//        setMyPublicKey(keyPair.getPublic());
//        setMyPublicKey(keyPair.getPublic());
//    }

//    @Override
//    public void setTheirPublicKey(PublicKey theirPublicKey) {
//        setHisPublicKey(theirPublicKey);
//    }


    @Override
    public BigInteger decrypt(BigInteger priKey, ElGamalEncryptedMessage cryptogram) throws CryptoNotValidException {
        return asymDecryptInternal(priKey, cryptogram);
    }

    @Override
    public ElGamalEncryptedMessage encrypt(BigInteger publicKeyX, BigInteger publicKeyY, BigInteger plainText) throws CryptoNotValidException {
        return asymEncryptInternal(publicKeyX, publicKeyY, plainText);
    }

    @Override
    public ElGamalKeyPair generateOwnKeys() throws CryptoNotValidException {

        X9ECParameters xparams = SECNamedCurves.getByName("secp521r1");
        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

        kpGen.init(new ECKeyGenerationParameters(eCDomainParameters, new SecureRandom()));

        AsymmetricCipherKeyPair myKeyPair;

        myKeyPair = kpGen.generateKeyPair();

        _privateKey = (ECPrivateKeyParameters) myKeyPair.getPrivate();
        _ourPublicKey = (ECPublicKeyParameters) myKeyPair.getPublic();

        ElGamalKeyPair rx = new ElGamalKeyPair();
        rx.setPrivateKey(_privateKey.getD());
        rx.setPublicKey(_ourPublicKey.getQ());

        return rx;
    }

    @Override
    public BigInteger getPublicKeyX() {
        return this._ourPublicKey.getQ().getAffineXCoord().toBigInteger();
    }

    @Override
    public BigInteger getPublicKeyY() {
        return this._ourPublicKey.getQ().getAffineYCoord().toBigInteger();
    }

    @Override
    public BigInteger getPrivateKey() {
        return this._privateKey.getD();
    }

}

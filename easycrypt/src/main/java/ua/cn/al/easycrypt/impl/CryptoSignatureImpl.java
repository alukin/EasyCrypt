/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
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

package ua.cn.al.easycrypt.impl;

import ua.cn.al.easycrypt.AsymKeysHolder;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.CryptoSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Common implementation of signature for all crypto systems supported by the library
 *
 * @author alukin@gmail.com
 */
public class CryptoSignatureImpl implements CryptoSignature {
    private static final Logger log = LoggerFactory.getLogger(CryptoSignatureImpl.class);

    protected PrivateKey privateKey;
    protected PublicKey ourPublicKey;
    protected PublicKey theirPublicKey;
    protected final CryptoParams params;
    protected Signature signature;

    public CryptoSignatureImpl(CryptoParams params) {
        this.params = Objects.requireNonNull(params);
    }

    @Override
    public void setTheirPublicKey(PublicKey pk) {
        theirPublicKey = pk;
    }

    @Override
    public void setPrivateKey(PrivateKey pk) {
        privateKey = pk;
    }

    @Override
    public void setKeys(AsymKeysHolder keys) {
        this.ourPublicKey = keys.getOurPublicKey();
        this.privateKey = keys.getPrivateKey();
        this.theirPublicKey = keys.getTheirPublicKey();
        try {
            this.signature = Signature.getInstance(params.getSignatureAlgorythm());
        } catch (NoSuchAlgorithmException ex) {
            log.error("Signature spec " + params.getSignatureAlgorythm() + " is not supported.");
        }
    }

    @Override
    public byte[] sign(byte[] message) throws CryptoNotValidException {
        try {
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (InvalidKeyException | SignatureException ex) {
            log.error("Signing error", ex);
            throw new CryptoNotValidException("Signing error", ex);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(params.getSignatureAlgorythm());
            sig.initVerify(theirPublicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            log.warn("Signature check exception", ex);
        }
        return false;
    }


    public byte[] add2BeginningOfArray(byte[] elements, byte element) {
        byte[] newArray = Arrays.copyOf(elements, elements.length + 1);
        newArray[0] = element;
        System.arraycopy(elements, 0, newArray, 1, elements.length);
        return newArray;
    }

    private static ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(data);
             ASN1InputStream asnInputStream = new ASN1InputStream(inStream);) {
            return asnInputStream.readObject();
        }
    }

    @Override
    public byte[] signPlain(byte[] message) throws CryptoNotValidException {
        byte[] asn1result = sign(message);
        byte[] plainResult;

        List<BigInteger> dsInts = new ArrayList<>();
        ASN1Primitive asn1;
        try {
            asn1 = toAsn1Primitive(asn1result);

            if (asn1 instanceof ASN1Sequence) {
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
                ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
                for (ASN1Encodable asn1Encodable : asn1Encodables) {
                    ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
                    if (asn1Primitive instanceof ASN1Integer) {
                        ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
                        BigInteger integer = asn1Integer.getValue();
                        dsInts.add(integer);
                    }
                }
            }
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new CryptoNotValidException("ASN1 signature creation error", ex);
        }

        byte[] r = dsInts.get(0).toByteArray();
        byte[] s = dsInts.get(1).toByteArray();

        if (r.length < 66) {
            while (r.length != 66) {
                r = add2BeginningOfArray(r, (byte) 0);
            }
        }

        if (s.length < 66) {
            while (s.length != 66) {
                s = add2BeginningOfArray(s, (byte) 0);
            }
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(r);
            outputStream.write(s);
        } catch (IOException ex) {
            log.error(ex.getMessage());
        }

        plainResult = outputStream.toByteArray();

        return plainResult;
    }

    @Override
    public boolean verifyPlain(byte[] message, byte[] signature) {

        if (signature.length != 132) {
            return false;
        }

        byte[] r = Arrays.copyOfRange(signature, 0, 66);
        byte[] s = Arrays.copyOfRange(signature, 66, 132);

        BigInteger _r = new BigInteger(r);
        BigInteger _s = new BigInteger(s);

        byte[] asnSignature = null;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DERSequenceGenerator seq;
        try {
            seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(_r.toByteArray()));
            seq.addObject(new ASN1Integer(_s.toByteArray()));
            seq.close();
            asnSignature = baos.toByteArray();
        } catch (IOException ex) {
            log.warn("Signature check, DER generation exception", ex);
            return false;
        }

        try {
            Signature sig = Signature.getInstance(params.getSignatureAlgorythm());
            sig.initVerify(theirPublicKey);
            sig.update(message);
            return sig.verify(asnSignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            log.warn("Signature check exception", ex);
        }

        return false;
    }

}

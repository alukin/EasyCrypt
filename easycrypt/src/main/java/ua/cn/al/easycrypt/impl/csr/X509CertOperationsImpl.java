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

package ua.cn.al.easycrypt.impl.csr;

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.csr.CertSubject;
import ua.cn.al.easycrypt.csr.CertificateRequestData;
import ua.cn.al.easycrypt.csr.X509CertOperations;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author alukin@gmail.com
 */
public class X509CertOperationsImpl implements X509CertOperations {

    private final CryptoParams params;
    private static final Logger log = LoggerFactory.getLogger(X509CertOperationsImpl.class);

    public X509CertOperationsImpl(CryptoParams params) {
        this.params = params;
    }

    @Override
    public PKCS10CertificationRequest createX509CertificateRequest(KeyPair kp, CertificateRequestData certData, boolean allowCertSign, String challengePassword) throws IOException {
        PKCS10CertificationRequest certRequest = null;
        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(certData.getSubject(), kp.getPublic());
        requestBuilder.setLeaveOffEmptyAttributes(true);
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, certData.getExtensions());
        if (challengePassword != null && !challengePassword.isEmpty()) {
            DERPrintableString password = new DERPrintableString(challengePassword);
            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
        }
        try {
            ContentSigner cs = new JcaContentSignerBuilder(params.getSignatureAlgorythm()).setProvider("BC").build(kp.getPrivate());
            certRequest = requestBuilder.build(cs);
        } catch (OperatorCreationException ex) {
            log.error("Can not create content signer", ex);
        }
        return certRequest;
    }

    @Override
    public X509Certificate createSelfSignedX509v3(KeyPair kp, CertificateRequestData certData, Date validityBegin, Date validityEnd) throws IOException {
        X509Certificate cert = null;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(certData.getSubject(),
                serial,
                validityBegin,
                validityEnd,
                certData.getSubject(),
                subPubKeyInfo);
        Extensions exts = certData.getExtensions();
        for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
            certBuilder.addExtension(exts.getExtension(oid));
        }
        try {
            ContentSigner cs = new JcaContentSignerBuilder(params.getSignatureAlgorythm()).setProvider("BC").build(kp.getPrivate());
            X509CertificateHolder holder = certBuilder.build(cs);
            // convert to JRE certificate
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(new BouncyCastleProvider());
            cert = converter.getCertificate(holder);
        } catch (OperatorCreationException | CertificateException ex) {
            log.error("Can not create content signer", ex);
        }
        return cert;
    }

    @Override
    public X509Certificate createSelfSignedX509v3(KeyPair kp, CertificateRequestData certData) throws IOException {
        // hour ago
        GregorianCalendar validityBeginDate = new GregorianCalendar();
        validityBeginDate.add(GregorianCalendar.HOUR, -1);
        // in 2 years
        GregorianCalendar validityEndDate = new GregorianCalendar();
        validityEndDate.add(GregorianCalendar.YEAR, 2);
        return createSelfSignedX509v3(kp, certData, validityBeginDate.getTime(), validityEndDate.getTime());
    }
    
/**
 *  This is quick and dirty implementation by no means full
 *  TODO: finish implementation
 * @param req
 * @param caCert
 * @param caKey
 * @param validityBegin
 * @param validityEnd
 * @return 
 */
    @Override
    public X509Certificate signCert(PKCS10CertificationRequest req, X509Certificate caCert, PrivateKey caKey, Date validityBegin, Date validityEnd) {

        X509Certificate cert = null;
        SubjectPublicKeyInfo subjPubKeyInfo = req.getSubjectPublicKeyInfo();
//TODO parse CSR and get certData
        Map<String,String> csrAttr = CertSubject.byNames(req.getSubject());
        CertificateRequestData certData = CertificateRequestData.fromMap(csrAttr, CertificateRequestData.CSRType.HOST);
//TODO: handle serials
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(certData.getSubject(),
                serial,
                validityBegin,
                validityEnd,
                certData.getSubject(),
                subjPubKeyInfo);

        try {
            Extensions exts = certData.getExtensions();
            for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
                certBuilder.addExtension(exts.getExtension(oid));
            }
            //TODO: Issuer subj            
            ContentSigner cs = new JcaContentSignerBuilder(params.getSignatureAlgorythm())
                    .setProvider(CryptoConfig.getProvider())
                    .build(caKey);
            X509CertificateHolder holder = certBuilder.build(cs);
            // convert to JRE certificate
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            converter.setProvider(CryptoConfig.getProvider());
            cert = converter.getCertificate(holder);
        } catch (OperatorCreationException | CertificateException | CertIOException ex) {
            log.error("Can not create content signer", ex);
        }
        return cert;
    }

}

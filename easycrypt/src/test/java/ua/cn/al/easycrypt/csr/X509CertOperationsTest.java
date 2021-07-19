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

package ua.cn.al.easycrypt.csr;

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.KeyGenerator;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import ua.cn.al.easycrypt.impl.csr.X509CertOperationsImpl;
import ua.cn.al.easycrypt.impl.ecc.KeyGeneratorEC;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeAll;
import ua.cn.al.easycrypt.TestBase;

/**
 *
 * @author alukin@gmail.com
 */
public class X509CertOperationsTest extends TestBase {
 
    private static CryptoParams params = CryptoConfig.createDefaultParams();   
    
    private static final String CERT_FILE="testdata/out/certops_test_cert.pem";
    private static final String CSR_FILE="testdata/out/certops_test_csr.pem";
  
    @BeforeAll
    private static void prepare(){
        mkdirs("testdata/out");
    }
    
    private static Properties fillProperties() {
        Properties p = new Properties();
        p.put("subject.CN", "al@cn.ua");
        p.put("subject.O", "OleksiyLukin");
        p.put("subject.OU", "OleskisyLukin-oss");
        p.put("subject.L", "Chernigiv");
        p.put("subject.C", "UA");
        p.put("subject.emailAddress", "a.lukin@gmail.com");
        p.put("subject.SERIALNUMBER", "1234567890");
        p.put("subject.UID", "1234567890");
        return p;
    }
  

    /**
     * Test of createSelfSignedX509v3 method, of class X509CertOperations.
     */
    @Test
    public void testCreateSelfSignedX509v3() throws Exception {
        System.out.println("createSelf SignedX509v3");
        Properties p = fillProperties();
        CertificateRequestData certData = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.PERSON);
        certData.processCertData(true);
        KeyGenerator kg = new KeyGeneratorEC(params);
        KeyPair kp = kg.generateKeys();
        
        X509CertOperations instance = new X509CertOperationsImpl(params);
        X509Certificate result = instance.createSelfSignedX509v3(kp, certData);
        System.out.println(result.getIssuerDN().toString());
        Map<String,String> subjAtrributes = CertSubject.byNamesFromPrincipal(result.getIssuerDN());
        assertEquals("OleksiyLukin", subjAtrributes.get("O"));
        assertEquals("a.lukin@gmail.com", subjAtrributes.get("E"));
        KeyWriter kw = new KeyWriterImpl();
        kw.writeX509CertificatePEM(CERT_FILE, result);
    }

    /**
     * Test of createX509CertificateRequest method, of class X509CertOperations.
     */
    @Test
    public void testCreateX509CertificateRequest() throws Exception {
        System.out.println("createX509CertificateRequest");
        Properties p = fillProperties();
        CertificateRequestData certData = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.PERSON);
        certData.processCertData(true);
        KeyGenerator kg = new KeyGeneratorEC(params);
        KeyPair kp = kg.generateKeys();
        
        boolean allowCertSign = false;
        String challengePassword = "1234567890";
        
        X509CertOperations instance = new X509CertOperationsImpl(params);
        PKCS10CertificationRequest result = instance.createX509CertificateRequest(kp, certData, allowCertSign, challengePassword);
        System.out.println(result.getSubject().toString());
        Map<String,String> subjAtrributes = CertSubject.byNames(result.getSubject());
        assertEquals("OleksiyLukin", subjAtrributes.get("O"));
        assertEquals("a.lukin@gmail.com", subjAtrributes.get("E"));
        KeyWriter kw = new KeyWriterImpl();
        kw.writeCertificateRequestPEM(CSR_FILE, result);
    }


}

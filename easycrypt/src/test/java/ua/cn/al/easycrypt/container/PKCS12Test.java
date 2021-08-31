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

package ua.cn.al.easycrypt.container;

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.csr.CertificateRequestData;
import ua.cn.al.easycrypt.csr.X509CertOperations;
import ua.cn.al.easycrypt.impl.ecc.KeyGeneratorEC;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;
import ua.cn.al.easycrypt.impl.csr.X509CertOperationsImpl;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class PKCS12Test {
    private static final String pathToKeyStore="tesKeyStore.p12";
    private static final String ksAlias="test";
    private static final String ksPassword="test";
    private static final String pvtKeyPassword="keypass";
    private static byte[] pvtKey;
    public PKCS12Test() {
    }
    
    @BeforeAll
    public static void setUpClass() {

            Properties p = new Properties();
            p.put("subject.CN","test.cn.ua");
            p.put("subject.O","OleksiyLukin");
            p.put("subject.OU","FB-cn");
            p.put("subject.L","Chernigiv");
            p.put("subject.C","UA");
            p.put("subject.emailAddress","test@al.cn.ua");
            p.put("subject.SERIALNUMBER","0001f1fcf82d132f9bb018ca6738a19f");
            p.put("subject.UID","0002da0e32e07b61c9f0251fe627a9c");
            p.put("subject.BusinessCategory","00032da0e32e07b61c9f0251fe627a9c");
            p.put("subject.DN","00042da0e32e07b61c9f0251fe627a9c");
            p.put("attribute.subjaltnames.registeredid","1.3.6.78.91.235");
            p.put("attribute.subjaltnames.dnsname","test.al.cn.ua");
            p.put("attribute.subjaltnames.ipaddress","192.168.15.5");
            CertificateRequestData cd = CertificateRequestData.fromProperty(p, CertificateRequestData.CSRType.HOST);
        try {            
            cd.processCertData(true);
            CryptoParams params = CryptoConfig.createDefaultParams();
            KeyGeneratorEC kg = new KeyGeneratorEC(params);
            KeyPair kp = kg.generateKeys();
            pvtKey=kp.getPrivate().getEncoded();
            X509CertOperations certOps = new X509CertOperationsImpl(params);
            X509Certificate cert = certOps.createSelfSignedX509v3(kp, cd);
            KeyWriter kw = new KeyWriterImpl();
            PKCS12KeyStore ks = new PKCS12KeyStore();
            ks.createOrOpenKeyStore(pathToKeyStore, ksPassword);
            ks.addPrivateKey(kp.getPrivate(), ksAlias, pvtKeyPassword, cert, cert);
            ks.save(pathToKeyStore,ksPassword);
        } catch (CryptoNotValidException | IOException ex) {
            fail(ex.toString());
        }
    }
    
    @AfterAll
    public static void tearDownClass() {
        File f = new File(pathToKeyStore);
        f.delete();        
    }
    /**
     * Test of openKeyStore method, of class PKCS12.
     */
    @Test
    public void testOpenKeyStore() {
        System.out.println("openKeyStore");
        PKCS12KeyStore instance = new PKCS12KeyStore();
        boolean expResult = true;
        boolean result = instance.openKeyStore(pathToKeyStore, ksPassword);
        assertEquals(expResult, result);
    }


    /**
     * Test of getAliases method, of class PKCS12.
     */
    @Test
    public void testGetAliases() {
        System.out.println("getAliases");
        PKCS12KeyStore instance = new PKCS12KeyStore();
        boolean res = instance.openKeyStore(pathToKeyStore, ksPassword);
        assertEquals(res, true);
        List<String> expResult = new ArrayList<>();
        expResult.add("test");
        List<String> result = instance.getAliases();
        assertEquals(expResult.get(0), result.get(0));
    }

    /**
     * Test of getCertificates method, of class PKCS12.
     */
    @Test
    public void testGetCertificates() {
        System.out.println("getCertificates");
        PKCS12KeyStore instance = new PKCS12KeyStore();
        boolean res = instance.openKeyStore(pathToKeyStore, ksPassword);
        assertEquals(res, true);
        String expResult ="DN=00042da0e32e07b61c9f0251fe627a9c,CN=test.cn.ua,L=Chernigiv,O=OleksiyLukin,OU=FB-cn,E=test@al.cn.ua,C=UA,BusinessCategory=00032da0e32e07b61c9f0251fe627a9c,UID=0002da0e32e07b61c9f0251fe627a9c,SERIALNUMBER=0001f1fcf82d132f9bb018ca6738a19f";
        List<Certificate> cl = instance.getCertificates();
        X509Certificate c = (X509Certificate) cl.get(0);
        String cn =c.getSubjectDN().getName();
        assertEquals(expResult, cn);
    }


    /**
     * Test of getPrivateKey method, of class PKCS12.
     */
    @Test
    public void testGetPrivateKey() {
        System.out.println("getPrivateKey");
        PKCS12KeyStore instance = new PKCS12KeyStore();
        boolean res = instance.openKeyStore(pathToKeyStore, ksPassword);
        assertEquals(res, true);
        PrivateKey result = instance.getPrivateKey(ksAlias, pvtKeyPassword);
        assertArrayEquals(pvtKey, result.getEncoded());
    }
    
}

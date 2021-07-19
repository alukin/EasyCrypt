/*
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

package ua.cn.al.easycrypt.identity.cert;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author alukin@gmail.com
 */
public class ExtCertTest {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ExtCertTest.class);
    static ExtCert acert;
    static PrivateKey pvtKey;
    
    public ExtCertTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        System.out.println("Reading test certificates and keys");
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test_cert.pem")) {
            acert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test_pvtkey.pem")) {
            pvtKey = CertKeyPersistence.loadPvtKey(is,"");
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }        
    }

    /**
     * Test of getAuthorityId method, of class ApolloCertificate.
     */
    @Test
    public void testGetAuthorityId() {
        AuthorityID result = acert.getAuthorityId();
        assertEquals(0x0100, result.getActorTypeAsInt());
        ActorType at = result.getActorType();
        assertEquals(0x01, at.getType());
        assertEquals(0x00, at.getSubType());
        assertEquals(0x0302, result.getRegionCode());
        assertEquals(0x0504, result.getBusinessCode());
        assertEquals(0x0706, result.getAuthorityCode());
        assertEquals(0x11100908, result.getOperationCode());
        assertEquals(0x15141312, result.getSuplementalCode());
    }
    
    @Test
    public void testAuthorityIdGetterAndSetters(){
       AuthorityID aid = new AuthorityID(acert.getAuthorityId().get());
       aid.setActorType(0x1234);
       assertEquals(0x1234,aid.getActorTypeAsInt());
       aid.setAuthorityCode(0x1234);
       assertEquals(0x1234,aid.getAuthorityCode());
       aid.setBusinessCode(0x1234);
       assertEquals(0x1234,aid.getBusinessCode());
       aid.setOperationCode(0x12345678L);
       assertEquals(0x12345678L,aid.getOperationCode());
       aid.setSuplementalCode(0x12345678L);
       assertEquals(0x12345678L,aid.getSuplementalCode());
       
       String exp = "01020304050607080000000000000000";      
       aid.setNetId(Hex.decode(exp));
       String res = Hex.toHexString(aid.getNetId());
       assertEquals(exp,res);
       exp="0abcde1234";
       aid.setNetId(Hex.decode(exp));
       res = Hex.toHexString(aid.getNetId());
       String exp2="00000000000000000000000abcde1234";
       assertEquals(exp2,res);               
    }
    /**
     * Test of getCN method, of class ApolloCertificate.
     */
    @Test
    public void testGetCN() {
        String result = acert.getCN();
        assertEquals("al@cn.ua", result);
    }

    /**
     * Test of getOrganization method, of class ApolloCertificate.
     */
    @Test
    public void testGetOrganization() {
        String expResult = "FirstBridge";
        String result = acert.getOrganization();
        assertEquals(expResult, result);
    }

    /**
     * Test of getOrganizationUnit method, of class ApolloCertificate.
     */
    @Test
    public void testGetOrganizationUnit() {
        String expResult = "FB-cn";
        String result = acert.getOrganizationUnit();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCountry method, of class ApolloCertificate.
     */
    @Test
    public void testGetCountry() {
        String expResult = "UA";
        String result = acert.getCountry();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCity method, of class ApolloCertificate.
     */
    @Test
    public void testGetCity() {
        String expResult = "Chernigiv";
        String result = acert.getCity();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCertificatePurpose method, of class ApolloCertificate.
     */
    @Test
    public void testGetCertificatePurpose() {
        String expResult = "Node";
        String result = acert.getCertificatePurpose();
        assertEquals(expResult, result);
    }

    /**
     * Test of getIPAddresses method, of class ApolloCertificate.
     */
    @Test
    public void testGetIPAddresses() {
        List<String> expResult = null;
        List<String> result = acert.getIPAddresses();
        assertEquals(expResult, result);
    }

    /**
     * Test of getDNSNames method, of class ApolloCertificate.
     */
    @Test
    public void testGetDNSNames() {
        List<String> expResult = null;
        List<String> result = acert.getDNSNames();
        assertEquals(expResult, result);
    }

    /**
     * Test of getStateOrProvince method, of class ApolloCertificate.
     */
    @Test
    public void testGetStateOrProvince() {
        String expResult = null;
        String result = acert.getStateOrProvince();
        assertEquals(expResult, result);
    }

    /**
     * Test of getEmail method, of class ApolloCertificate.
     */
    @Test
    public void testGetEmail() {
        String expResult = "alukin@gmail.com";
        String result = acert.getEmail();
        assertEquals(expResult, result);
    }

    /**
     * Test of getCertPEM method, of class ApolloCertificate.
     */
    @Test
    public void testGetPEM() {
        String result = acert.getCertPEM();
        assertEquals(true, result.startsWith("-----BEGIN CERTIFICATE----"));
    }

    /**
     * Test of isValid method, of class ApolloCertificate.
     */
    @Test
    public void testIsValid() {
        Date date = null;
        boolean expResult = false;
        boolean result = acert.isValid(date);
        assertEquals(expResult, result);
    }

    /**
     * Test of getSerial method, of class ApolloCertificate.
     */
    @Test
    public void testGetSerial() {
        BigInteger result = acert.getSerial();
        BigInteger expResult = BigInteger.valueOf(1605086367578L);
        assertEquals(expResult, result);
    }

    @Test
    public void testGetIssuerAttributes() {
        CertAttributes cert_attr = acert.getIssuerAttrinutes();
        assertEquals("al@cn.ua", cert_attr.getCn());
        assertEquals("FirstBridge", cert_attr.getO());
    }

}

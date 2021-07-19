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
import java.security.PrivateKey;
import org.junit.jupiter.api.Assertions;


/**
 * @author alukin@gmail.com
 */
public class CertSignTest {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(CertSignTest.class);
    static ExtCert acert;
    static ExtCert sscert;
    static PrivateKey pvtKey;
    static ExtCert caCert;
    
    public CertSignTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        System.out.println("Reading test certificates and keys");
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test_cert.pem")) {
            sscert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }        
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test2_cert.pem")) {
            acert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("test2_pvtkey.pem")) {
            pvtKey = CertKeyPersistence.loadPvtKey(is,"");
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }  
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("CA_cert.pem")) {
            caCert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (IOException ex) {
            log.error("Can not load test certificate ", ex);
        } catch (CertException ex) {
            log.error("can not parse test certificate", ex);
        }        
    }
    
    @Test
    public void testCASign() {
        CertAttributes signer_attr = acert.getIssuerAttrinutes();
        CertAttributes cert_attr_ca = caCert.getSubjectAttrinutes();
        //is signed by CA? verify, for instance, e-mail
        Assertions.assertEquals(signer_attr.geteMail(), cert_attr_ca.geteMail(), "CA is not the signer of cert according to e-mail");
        //verify signature
        Assertions.assertTrue(acert.isSignedBy(caCert.getCertificate()),"Cert is not signed by this CA");   
    }

    
    @Test
    public void testSelfSigned(){
        CertAttributes cert_attr = sscert.getSubjectAttrinutes();
        CertAttributes signer_attr = sscert.getIssuerAttrinutes();
        Assertions.assertEquals(signer_attr.geteMail(), cert_attr.geteMail(), "Cert is not self-signed");
        Assertions.assertTrue(sscert.isSignedBy(sscert.getCertificate()),"Cert is not self-signed");         
    }
}

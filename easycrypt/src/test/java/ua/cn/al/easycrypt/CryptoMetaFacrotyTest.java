
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

import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptoMetaFacrotyTest {

    private static final String RSA_CERT_FILE_1 = "testdata/cert-rsa/cert_1.pem";

    private static final String EC_CERT_FILE_1 = "testdata/cert-ecc/test1_cert.pem";

    public CryptoMetaFacrotyTest() {
    }

    @BeforeAll
    public static void setUpClass() {
        // we have to test crypto providers
        Provider p = CryptoConfig.getProvider();
        System.out.println("EasyCrypt security provider: " + p.getName() + " version: " + p.getVersionStr());
        // Bouncy castle provider must be here
        Assertions.assertEquals("BC", p.getName());
        boolean bcFound = false;
        for (Provider provider : Security.getProviders()) {
    
            if ("BC".equals(provider.getName())){
               bcFound=true;
            }
            System.out.println(provider.getName());
//uncoment this is you want to list all providers with properties
//            for (String key : provider.stringPropertyNames()) {
//                System.out.println("\t" + key + "\t" + provider.getProperty(key));
//            }
        }
        Assertions.assertEquals(true,bcFound);
    }

    /**
     * Test of createFacrory method, of class CryptoMetaFacroty.
     *
     * @throws java.io.FileNotFoundException
     */
    @Test
    public void testCreateFacrory_PublicKey_RSA() throws FileNotFoundException {
        InputStream is = new FileInputStream(RSA_CERT_FILE_1);
        KeyReader kr = new KeyReaderImpl();
        X509Certificate cert = kr.readX509CertPEMorDER(is);
        CryptoFactory res_pk = CryptoFactoryHelper.createFactory(cert.getPublicKey());
        CryptoParams params_pk = res_pk.getCryptoParams();
        String signAlgo = cert.getSigAlgName();
        CryptoFactory res_ca = CryptoFactoryHelper.createFactory(signAlgo);
        CryptoParams params_ca = res_ca.getCryptoParams();

        Assertions.assertEquals("RSA", params_pk.signatureSchema);
        Assertions.assertEquals("RSA", params_ca.signatureSchema);
    }

    /**
     * Test of createFacrory method, of class CryptoMetaFacroty.
     *
     * @throws java.io.FileNotFoundException
     */
    @Test
    public void testCreateFacrory_PublicKey_EC() throws FileNotFoundException {
        InputStream is = new FileInputStream(EC_CERT_FILE_1);
        KeyReader kr = new KeyReaderImpl();
        X509Certificate cert = kr.readX509CertPEMorDER(is);
        CryptoFactory res_pk = CryptoFactoryHelper.createFactory(cert.getPublicKey());
        CryptoParams params_pk = res_pk.getCryptoParams();
        String signAlgo = cert.getSigAlgName();
        CryptoFactory res_ca = CryptoFactoryHelper.createFactory(signAlgo);
        CryptoParams params_ca = res_ca.getCryptoParams();

        Assertions.assertEquals("EC", params_pk.signatureSchema);
        //need new cert with EC CA signature
        Assertions.assertEquals("RSA", params_ca.signatureSchema);
    }

    /**
     * Test of createFacrory method, of class CryptoMetaFacroty.
     *
     * @throws java.io.FileNotFoundException
     */
    @Test
    public void testCreateFacrory_X509Certificate() throws FileNotFoundException {
        InputStream is = new FileInputStream(EC_CERT_FILE_1);
        KeyReader kr = new KeyReaderImpl();
        X509Certificate cert = kr.readX509CertPEMorDER(is);
        CryptoFactory result = CryptoFactoryHelper.createFactory(cert);
        CryptoParams params_pk = result.getCryptoParams();
        Assertions.assertEquals("EC", params_pk.signatureSchema);
    }

}

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

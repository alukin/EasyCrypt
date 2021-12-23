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

package ua.cn.al.easycrypt;

import ua.cn.al.easycrypt.impl.ecc.KeyGeneratorEC;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class KeyReadWriteTest extends TestBase {
    private static KeyPair kp;
    private static final CryptoParams params = CryptoConfig.createDefaultParams();
    private static final String CERT_FILE = "testdata/cert-ecc/cacert.pem";
    private static final String EC_KEY_FILE = "testdata/cert-ecc/secp521r1_key.pem";
    private static final String EC_KEY_FILE_NP = "testdata/cert-ecc/secp521r1_key_np.pem";
    private static final String PVT_KEY_PKCS8_OUT_FILE ="testdata/out/test_pvt_key_pw.pem";            
    private static final String KEY_PASSWOD = "12345678";
    public KeyReadWriteTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
        mkdirs(PVT_KEY_PKCS8_OUT_FILE);
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator kg = new KeyGeneratorEC(params);
        kp=kg.generateKeys();
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

     @Test
     public void testPublicKeySerialization() throws CryptoNotValidException {
         KeyWriter kw = new KeyWriterImpl();
         KeyReader kr = new KeyReaderImpl();
         byte[] s = kw.serializePublicKey(kp.getPublic());
         PublicKey pubk = kr.deserializePublicKey(s);
         assertArrayEquals(kp.getPublic().getEncoded(), pubk.getEncoded());
     }
     
     @Test
     public void testPrivateKeySerialization() throws CryptoNotValidException {
         KeyWriter kw = new KeyWriterImpl();
         KeyReader kr = new KeyReaderImpl();         
         byte[] s = kw.serializePrivateKey(kp.getPrivate());
         PrivateKey pk = kr.deserializePrivateKey(s);
         assertArrayEquals(kp.getPrivate().getEncoded(), pk.getEncoded());
         
     }
     @Test
     public void testReadPEM() throws FileNotFoundException{
          KeyReader kr = new KeyReaderImpl();
          InputStream is = new FileInputStream(CERT_FILE);
          Assertions.assertNotNull(is);
          X509Certificate cert = kr.readX509CertPEMorDER(is);
          Assertions.assertNotNull(cert);
     }
     
     @Test
     public void readEncryptedKey() throws FileNotFoundException, IOException{
         KeyReader kr = new KeyReaderImpl();
         InputStream is = new FileInputStream(EC_KEY_FILE);
         Assertions.assertNotNull(is);
         PrivateKey privk = kr.readPrivateKeyPEM(is, KEY_PASSWOD);
         Assertions.assertNotNull(privk);
         is = new FileInputStream(EC_KEY_FILE_NP);
         PrivateKey privk_np = kr.readPrivateKeyPEM(is, KEY_PASSWOD);
         assertArrayEquals(privk.getEncoded(), privk_np.getEncoded());
     }
     
     @Test
     public void writeEncryptedKey() throws FileNotFoundException, IOException{
         KeyWriter kw = new KeyWriterImpl();
         boolean res = kw.writePvtKeyPKSC8(PVT_KEY_PKCS8_OUT_FILE, kp.getPrivate(), KEY_PASSWOD);
         Assertions.assertEquals(true,res);
         KeyReader kr = new KeyReaderImpl();
         InputStream is = new FileInputStream(PVT_KEY_PKCS8_OUT_FILE);
         Assertions.assertNotNull(is);
         PrivateKey pk = kr.readPrivateKeyPKCS8(is, KEY_PASSWOD);
         Assertions.assertNotNull(pk);
         assertArrayEquals(kp.getPrivate().getEncoded(), pk.getEncoded());
     }     
}

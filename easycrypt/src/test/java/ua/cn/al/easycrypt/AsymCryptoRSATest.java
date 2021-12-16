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


import ua.cn.al.easycrypt.impl.CryptoSignatureImpl;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import ua.cn.al.easycrypt.impl.rsa.AsymCryptorRSAImpl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 
*/
public class AsymCryptoRSATest extends TestBase {

    private static KeyPair kpAlice;
    private static KeyPair kpBob;
    private static final String PLAIN_FILE = "testdata/input/lorem_ipsum.txt";
    private static final String SIGNATURE_ALICE_FILE = "testdata/out/rsa_encrypt_asym_test_signature_alice.bin";
    private static final String OUT_FILE_ENCRYPT_ASYM_ALICE = "testdata/out/rsa_encrypt_asym_test.bin";
    
    private static final String CERT_1="testdata/cert-rsa/cert_1.pem";
    private static final String KEY_1_NP="testdata/cert-rsa/key_1_nopass.pem";
    private static final String CERT_2="testdata/cert-rsa/cert_2.pem";
    private static final String KEY_2_NP="testdata/cert-rsa/key_2_nopass.pem";
    
    private static final int RSA_KEY_LEN = 4096;
    
    private static AsymKeysHolder khA;
    private static AsymKeysHolder khB;
    
    private static final CryptoParams params = CryptoConfig.createRSAn(RSA_KEY_LEN);
    
    public AsymCryptoRSATest() {
    }

    private static ByteBuffer readFromFile(String fileName, int size) throws IOException {
        FileChannel fChan;
        Long fSize;
        ByteBuffer mBuf;
        fChan = new FileInputStream(fileName).getChannel();
        fSize = fChan.size();
        if(size>fSize.intValue()){
            size=fSize.intValue();
        }
        mBuf = ByteBuffer.allocate(size);
        fChan.read(mBuf);
        fChan.close();
        mBuf.rewind();
        return mBuf;
    }

    @BeforeAll
    public static void setUpClass() {
        try {
            mkdirs(OUT_FILE_ENCRYPT_ASYM_ALICE);
            System.out.println("Reading certificates and keys for asymmetric crypto tests");
            KeyReaderImpl kr = new KeyReaderImpl();
            X509Certificate test1_cert = kr.readX509CertPEMorDER(new FileInputStream(CERT_1));
            PrivateKey test1_priv = kr.readPrivateKeyPEM(new FileInputStream(KEY_1_NP));
            kpAlice = new KeyPair(kr.extractPublicKeyFromX509(test1_cert), test1_priv);

            X509Certificate test2_cert = kr.readX509CertPEMorDER(new FileInputStream(CERT_2));
            PrivateKey test2_priv = kr.readPrivateKeyPEM(new FileInputStream(KEY_2_NP));
            kpBob = new KeyPair(kr.extractPublicKeyFromX509(test2_cert), test2_priv);
            
            khA = new AsymKeysHolder(kpAlice.getPublic(), kpAlice.getPrivate(), kpBob.getPublic());
            khB = new AsymKeysHolder(kpBob.getPublic(), kpBob.getPrivate(), kpAlice.getPublic());
            
        } catch (IOException | CertificateException | CryptoNotValidException ex) {
            fail("Can not read public or private key files",ex);
        }

    }

    @Test
    public void testSign() throws Exception {
        System.out.println("tesing signing");

        CryptoSignature instance1 = new CryptoSignatureImpl(params);
        instance1.setKeys(khA);

        CryptoSignature instance2 = new CryptoSignatureImpl(params);
        instance2.setKeys(khB);
        ByteBuffer plain = readFromFile(PLAIN_FILE,Integer.MAX_VALUE);
        byte[] signature = instance1.sign(plain.array());
        boolean res = instance2.verify(plain.array(), signature);
        ByteBuffer sb = ByteBuffer.wrap(signature);
        
        writeToFile(sb, SIGNATURE_ALICE_FILE);
        
        assertTrue(res);
    }
    
    /**
     * Test of encryptAsymmetricIES method with RSA
     */
    
    
    @Test
    public void testEncryptAsymmetricIES() throws Exception {
        System.out.println("encryptAsymmetric");
        //size of message to encrypt is limited by key lenght with RSA 
        int keyLenBytes = khA.getOurPublicKey().getEncoded().length-38; // 38 bytes is ASN.1 encoded types
        int maxMessageSize = keyLenBytes-11; // RSA limitations 
        ByteBuffer plain = readFromFile(PLAIN_FILE, maxMessageSize); 

        AsymCryptor instance1 = new AsymCryptorRSAImpl(params);
        instance1.setKeys(khA);
        byte[] encrypted = instance1.encrypt(plain.array());
        ByteBuffer eb = ByteBuffer.wrap(encrypted);
        
        writeToFile(eb,OUT_FILE_ENCRYPT_ASYM_ALICE );
        
        AsymCryptor instance2 = new AsymCryptorRSAImpl(params);
        instance2.setKeys(khB);
        byte[] decrypted = instance2.decrypt(encrypted);

        
        assertArrayEquals(plain.array(), decrypted);
    }

    

}

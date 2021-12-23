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

import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.dataformat.ElGamalEncryptedMessage;
import ua.cn.al.easycrypt.impl.CryptoSignatureImpl;
import ua.cn.al.easycrypt.impl.ecc.AsymJCEECDHImpl;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import ua.cn.al.easycrypt.impl.ecc.ElGamalCryptoImpl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class AsymCryptoECCTest extends TestBase{

    private static KeyPair kpAlice;
    private static KeyPair kpBob;
    private static final String PLAIN_FILE_TEXT = "testdata/input/lorem_ipsum.txt";
    private static final String SHARED_KEY_ECDHE_FILE = "testdata/out/ecc_encrypt_asym_test_key_echdhe.bin";
    private static final String SHARED_KEY_ECDH_FILE = "testdata/out/ecc_encrypt_asym_test_key_ecdh.bin";
    private static final String SIGNATURE_ALICE_FILE = "testdata/out/ecc_encrypt_asym_test_signature_alice.bin";
    private static final String SIGNATURE_ALICE_PLAIN_FILE = "testdata/out/ecc_encrypt_asym_test_signature_alice_plain.bin";
    private static final String OUT_FILE_ENCRYPT_ASYM_ALICE = "testdata/out/ecc_encrypt_asym_test.bin";
    private static final String OUT_FILE_ENCRYPT_ASYM_AEAD_ALICE = "testdata/out/ecc_encrypt_asym_aead_test.bin";
    private static final String OPEN_TEXT = ">>>This is test open text. Should be visisble as is<<<";
    
    private static final String CERT_1="testdata/cert-ecc/test1_cert.pem";
    private static final String KEY_1="testdata/cert-ecc/test1_pvtkey.pem";
    private static final String CERT_2="testdata/cert-ecc/test2_cert.pem";
    private static final String KEY_2="testdata/cert-ecc/test2_pvtkey.pem";
    private static final SecureRandom srand = new SecureRandom();
    private static final int RANDOM_BYTES_NUMBER = 4096;
    
    private static AsymKeysHolder khA;
    private static AsymKeysHolder khB;
    
    private static final CryptoParams params = CryptoConfig.createDefaultParams();
    
    
    public AsymCryptoECCTest() {
    }
    


    @BeforeAll
    public static void setUpClass() {
        try {
            mkdirs(OUT_FILE_ENCRYPT_ASYM_ALICE);
            System.out.println("Reading certificates and keys for asymmetric crypto tests");
            KeyReaderImpl kr = new KeyReaderImpl();
            X509Certificate test1_cert = kr.readX509CertPEMorDER(new FileInputStream(CERT_1));
            PrivateKey test1_priv = kr.readPrivateKeyPEM(new FileInputStream(KEY_1));
            kpAlice = new KeyPair(kr.extractPublicKeyFromX509(test1_cert), test1_priv);

            X509Certificate test2_cert = kr.readX509CertPEMorDER(new FileInputStream(CERT_2));
            PrivateKey test2_priv = kr.readPrivateKeyPEM(new FileInputStream(KEY_2));
            kpBob = new KeyPair(kr.extractPublicKeyFromX509(test2_cert), test2_priv);

            System.out.println("Preparing random plain file for asymmetric crypto tests");
            
            khA = new AsymKeysHolder(kpAlice.getPublic(), kpAlice.getPrivate(), kpBob.getPublic());
            khB = new AsymKeysHolder(kpBob.getPublic(), kpBob.getPrivate(), kpAlice.getPublic());

        } catch (IOException | CertificateException | CryptoNotValidException ex) {
            fail("Can not read public or private key files");
        }

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
    public void testECDHE() throws Exception {
        System.out.println("ECDHE keys writing to file: " + SHARED_KEY_ECDHE_FILE);
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        AsymKeysHolder khA = new AsymKeysHolder(kpAlice.getPublic(), kpAlice.getPrivate(), kpBob.getPublic());
        instance1.setKeys(khA);

        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        AsymKeysHolder khB = new AsymKeysHolder(kpBob.getPublic(), kpBob.getPrivate(), kpAlice.getPublic());
        instance2.setKeys(khB);

        byte[] aliceSignedKey = instance1.ecdheStep1();
        byte[] bobSignedKey = instance2.ecdheStep1();

        byte[] sharedKeyAlice = instance1.ecdheStep2(bobSignedKey);
        byte[] sharedKeyBob = instance2.ecdheStep2(aliceSignedKey);
        assertArrayEquals(sharedKeyAlice, sharedKeyBob);
        writeToFile(ByteBuffer.wrap(sharedKeyBob), SHARED_KEY_ECDHE_FILE);
    }
       

    @Test
    public void testECDH() throws Exception {
        System.out.println("ECDH keys writing to file: " + SHARED_KEY_ECDH_FILE);
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);

        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);

        byte[] sharedKeyAlice = instance1.calculateSharedKey();
        byte[] sharedKeyBob = instance2.calculateSharedKey();
        assertArrayEquals(sharedKeyAlice, sharedKeyBob);
        writeToFile(ByteBuffer.wrap(sharedKeyBob), SHARED_KEY_ECDH_FILE);
    }
        
    
    
    @Test
    public void testSign() throws Exception {
        System.out.println("tesing signing specific");

        CryptoSignature instance1 = new CryptoSignatureImpl(params);
        instance1.setKeys(khA);

        CryptoSignature instance2 = new CryptoSignatureImpl(params);
        instance2.setKeys(khB);

        ByteBuffer plain = readFromFile(PLAIN_FILE_TEXT);
        byte[] signature = instance1.sign(plain.array());
        boolean res = instance2.verify(plain.array(), signature);
        ByteBuffer sb = ByteBuffer.wrap(signature);        
        writeToFile(sb, SIGNATURE_ALICE_FILE);        
        assertTrue(res);
                
        byte[] plainSig = instance1.signPlain( plain.array() );
        ByteBuffer spb = ByteBuffer.wrap(plainSig);
        boolean resPlain = instance2.verifyPlain(plain.array(), spb.array());                     
        writeToFile(spb, SIGNATURE_ALICE_PLAIN_FILE);               
        assertTrue(resPlain);
    }
    
    

    /**
     * Test of encrypt method of common implementation.
     */

    
    @Test
    public void testEncryptDH() throws Exception {
        System.out.println("encryptAsymmetric");
        ByteBuffer plain = readFromFile(PLAIN_FILE_TEXT); 

        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);       
        instance1.setKeys(khA);
        instance1.calculateSharedKey();
        byte[] encrypted = instance1.encrypt(plain.array());
        ByteBuffer eb = ByteBuffer.wrap(encrypted);
        
        writeToFile(eb,OUT_FILE_ENCRYPT_ASYM_ALICE );
        
        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);
        instance2.calculateSharedKey();
        byte[] decrypted = instance2.decrypt(encrypted);
        
        assertArrayEquals(plain.array(), decrypted);
    }  
    
    
    /**
     * Test of encryptAsymmetricWithAEAData method, of class EasyCrypt.
     */
    @Test
    public void testEncryptAsymmetricWithAEAData() throws Exception {
        System.out.println("encryptAsymmetricWithAEAData");
        ByteBuffer plain = readFromFile(PLAIN_FILE_TEXT); 
        String open = OPEN_TEXT;

        AsymCryptorDH instance1 =  new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);
        AEADCiphered encrypted = instance1.encryptWithAEAData(plain.array(), open.getBytes());
        ByteBuffer eb = ByteBuffer.wrap(encrypted.toBytes());
        
        writeToFile(eb, OUT_FILE_ENCRYPT_ASYM_AEAD_ALICE);
        
        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);

        AEADPlain decrypted = instance2.decryptWithAEAData(encrypted.toBytes());

        String open_r = new String(decrypted.plain);
        String open_e = new String(encrypted.aatext);
        assertArrayEquals(plain.array(), decrypted.decrypted);
        assertEquals(open, open_r);
        assertEquals(open, open_e);
    }
    
    
    @Test
    public void testEncryptAsymmetricElGamalSeparateKeys() throws Exception {
        System.out.println("testEncryptAsymmetricElGamal");
        
    ElGamalCryptoImpl instanceOfAlice = new ElGamalCryptoImpl(params);
    
    ElGamalKeyPair aliceKeys = instanceOfAlice.generateOwnKeys();
   
    BigInteger alicePrivateKey = aliceKeys.getPrivateKey();
    
    // distributed stuff
    BigInteger alicePublicKeyX = aliceKeys.getPrivateKeyX();
    BigInteger alicePublicKeyY = aliceKeys.getPrivateKeyY();
    
    System.out.println("Alice, privateKey : " + alicePrivateKey.toString() );
    System.out.println("Alice, public.X   : " + alicePublicKeyX.toString() );
    System.out.println("Alice, public.Y   : " + alicePublicKeyY.toString() );
   
    // transferring Alice's public key to the side of BOB
    // Alice's private key should be left on her side 
    // and under no circumstances should it be exposed
    
    ElGamalCryptoImpl instanceOfBob = new ElGamalCryptoImpl(params);
    
    // generating random plaintext
    
    BigInteger plainText = new BigInteger( instanceOfBob.getECDomainParameters().getN().bitLength() - 1, new SecureRandom());
    System.out.println("plainText: " + plainText.toString(16) );
    
    
    ElGamalEncryptedMessage cryptogram = instanceOfBob.encrypt(alicePublicKeyX, alicePublicKeyY, plainText);

    
    String m2str = cryptogram.getM2().toString(16);

    String m1xstr = cryptogram.getM1().getRawXCoord().toBigInteger().toString(16);
    String m1ystr = cryptogram.getM1().getRawYCoord().toBigInteger().toString(16);

    
    System.out.println("M1.X: " + m1xstr);
    System.out.println("M1.Y: " + m1ystr);
    System.out.println("M2. : " + m2str );
    
    // decrypting this information. 
    
    BigInteger restored = instanceOfAlice.decrypt( alicePrivateKey, cryptogram);    
    System.out.println("restored : " + restored.toString(16));
    

    // Input: m1xstr = x coordinate of m1 as string
    // m1xstr = y coordinate of m1 as string
    // m2str = m2 as tring

    // creating cryptogram data class instance: 
    ElGamalEncryptedMessage cryptogram1 = new ElGamalEncryptedMessage();    
    cryptogram1.setM2( new BigInteger(m2str,16)); 

    org.bouncycastle.math.ec.ECPoint _M1 = 
            instanceOfBob.extrapolateECPoint(
                    new BigInteger(m1xstr,16),
                    new BigInteger(m1ystr,16));
    // setting M1 to the instance of cryptogram
    cryptogram1.setM1(_M1);
    // decrypting
    BigInteger restored1 = instanceOfAlice.decrypt( alicePrivateKey, cryptogram1);    
    System.out.println("restored1 : " + restored1.toString(16));    
    
    }
    
}

/*
 *
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

import ua.cn.al.easycrypt.dataformat.AEADCiphered;
import ua.cn.al.easycrypt.dataformat.AEADPlain;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import ua.cn.al.easycrypt.impl.ecc.AsymJCEECDHImpl;
import ua.cn.al.easycrypt.impl.AbstractAsymCryptor;
import ua.cn.al.easycrypt.impl.CryptoSignatureImpl;
import ua.cn.al.easycrypt.impl.ecc.AsymJCEIESImpl;
import ua.cn.al.easycrypt.impl.JCEDigestImpl;
import ua.cn.al.easycrypt.impl.ecc.SymJCEImpl;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class NoFilesCryptoTest {
    
    private static KeyPair kpAlice;
    private static KeyPair kpBob;
    private static final SecureRandom srand = new SecureRandom();
    private static final CryptoParams params = CryptoConfig.createDefaultParams();

    private static AsymKeysHolder khA;
    private static AsymKeysHolder khB;
    
    public NoFilesCryptoTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
        try {
            CryptoConfig.setBCProvider();
            KeyReaderImpl kr = new KeyReaderImpl();
            X509Certificate test1_cert = kr.readX509CertPEMorDER( new FileInputStream("testdata/cert-ecc/test1_cert.pem"));
            PrivateKey test1_priv = kr.readPrivateKeyPEM(new FileInputStream("testdata/cert-ecc/test1_pvtkey.pem"));
            kpAlice = new KeyPair(kr.extractPublicKeyFromX509(test1_cert), test1_priv);
 
            X509Certificate test2_cert = kr.readX509CertPEMorDER( new FileInputStream("testdata/cert-ecc/test2_cert.pem"));
            PrivateKey test2_priv = kr.readPrivateKeyPEM(new FileInputStream("testdata/cert-ecc/test2_pvtkey.pem"));
            kpBob = new KeyPair(kr.extractPublicKeyFromX509(test2_cert), test2_priv);
            khA = new AsymKeysHolder(kpAlice.getPublic(), kpAlice.getPrivate(), kpBob.getPublic());
            khB = new AsymKeysHolder(kpBob.getPublic(), kpBob.getPrivate(), kpAlice.getPublic());           
        } catch (IOException | CertificateException | CryptoNotValidException ex) {
            fail("Can not read public or private key files", ex);
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

    /**
     * Test of setSymmetricKey method, of class EasyCrypt.
     */
    @Test
    public void testSetSymmetricKey() throws Exception {
        System.out.println("setSymmetricKey");
        byte[] key = new byte[256/8];
        srand.nextBytes(key);
        SymCryptor instance = new SymJCEImpl(params);
        try{
          instance.setKey(key);
        }catch(Exception e){
            fail("Can not set symmetric key!");
        }
    }

    /**
     * Test of setSymmetricIV method, of class EasyCrypt.
     */
    @Test
    public void testSetSymmetricIV() {
        System.out.println("setSymmetricIV");
        byte[] IV = new byte[12];
        srand.nextBytes(IV);
        SymCryptor instance = new SymJCEImpl(params);
        try{
          instance.setIV(IV);
        }catch(Exception e){
            fail("Can not set symmertic IV");
        }

      //  fail("The test case is a prototype.");
    }

    /**
     * Test of setSymmetricSalt method, of class EasyCrypt.
     */
    @Test
    public void testSetSymmetricSaltAndNounce() {
        System.out.println("setSymmetricSalt");
        byte[] iv = new byte[12];
        byte[] salt; 
        byte[] nounce; 
        srand.nextBytes(iv);
        salt = Arrays.copyOfRange(iv, 0,4);
        nounce = Arrays.copyOfRange(iv, 4, 12);
        SymCryptor instance = new SymJCEImpl(params);
        try{
          instance.setSalt(salt);
          instance.setNonce(nounce);
        }catch(Exception e){
            fail("Can not set salt");
        }
        try{
            instance.setNonce(nounce);
            fail("Nouce reuse not detected");
        }catch(Exception e){      
        }
       byte[] k = instance.getIV();
       assertArrayEquals(iv, k);
    }


    /**
     * Test of encryptSymmetric method, of class EasyCrypt.
     */
    @Test
    public void testEncryptSymmetric() throws Exception {
        System.out.println("encryptSymmetric");
        String plain_text = "Red fox jumps over lazy dog";
        byte[] key = new byte[256/8];
        byte[] salt = new byte[4]; //iv=salt+nounce 12 bytes
        byte[] explicitNounce = new byte[8];
        srand.nextBytes(key);
        srand.nextBytes(salt);
        srand.nextBytes(explicitNounce);
        SymCryptor instance1 = new SymJCEImpl(params);
        instance1.setSalt(salt);
        instance1.setNonce(explicitNounce);
        instance1.setKey(key);        
        byte[] encrypted = instance1.encrypt(plain_text.getBytes());
        
        //in real life we must set salt and iv; nounce is prefix of encrypted message
        SymCryptor instance2 = new SymJCEImpl(params);
        instance2.setKey(key);
        instance2.setSalt(salt);
        //ready to decrypt
        byte[] plain = instance2.decrypt(encrypted);
        String text = new String(plain);
        assertEquals(plain_text, text);
    }

    /**
     * Test of encryptSymmetricWithAEAData method, of class EasyCrypt.
     */
    @Test
    public void testEncryptSymmetricWithAEAData() throws Exception {

        System.out.println("encryptSymmetricWithAEAData");
        String plain_text = "Red fox jumps over lazy dog";

        byte[] key = new byte[256/8];
        byte[] salt = new byte[4];
        byte[] nonce = new byte[8];
        srand.nextBytes(key);
        srand.nextBytes(salt);
        srand.nextBytes(nonce);

        SymCryptor instance1 = new SymJCEImpl(params);
        instance1.setKey(key);
        instance1.setSalt(salt);
        instance1.setNonce(nonce);
        String adata = "<<<TEXT TO STAY OPEN>>>";
        AEADCiphered msg = instance1.encryptWithAEAData(plain_text.getBytes(), adata.getBytes());

        /* use instance2 with IV set from msg.getIV() */
        SymCryptor instance2 = new SymJCEImpl(params);
        instance2.setKey(key);
        instance2.setSalt(salt);

        AEADPlain plain = instance2.decryptWithAEAData(msg.toBytes());
        String text = new String(plain.decrypted);       
        assertEquals(plain_text, text);        

    }

    /**
     * Test of encryptAsymmetric method, of class EasyCrypt.
     */
    @Test
    public void testEncryptAsymmetricIES() throws Exception  {
        System.out.println("encryptAsymmetricIES");
        String plain ="Red fox Jumps over Lazy Dog";
        
        AsymCryptor instance1 = new AsymJCEIESImpl(params);
        instance1.setKeys(khA);
        byte[] encrypted = instance1.encrypt(plain.getBytes());

        AbstractAsymCryptor instance2 = new AsymJCEIESImpl(params);
        instance2.setKeys(khB);        
        byte[] decrypted = instance2.decrypt(encrypted);
        
        String text = new String(decrypted);
        assertEquals(plain, text);
    }
    
/**
 * Test shared iv generation
 * @throws Exception 
 */
    @Test
    public void testCalculateSharedKey() throws Exception{
        
        System.out.println("calculateSharedKey");
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);

        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);        
        
        byte[] sharedKey1 = instance1.calculateSharedKey();
        byte[] sharedKey2 = instance2.calculateSharedKey();
        System.out.println(Hex.toHexString(sharedKey1));
        System.out.println(Hex.toHexString(sharedKey2));
        assertArrayEquals(sharedKey1, sharedKey2);
    }
    /**
     * Test of encryptAsymmetric method, of class EasyCrypt.
     */
    @Test
    public void testEncryptAsymmetric() throws Exception  {
        System.out.println("encryptAsymmetric");    
        String plain ="Red fox Jumps over Lazy Dog";
        
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);
        byte[] encrypted = instance1.encrypt(plain.getBytes());
        
        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);
        byte[] decrypted = instance2.decrypt(encrypted);
        
        String text = new String(decrypted);
        assertEquals(plain, text);
    }
    
    /**
     * Test of encryptAsymmetricWithAEAData method, of class EasyCrypt.
     */
    @Test
    public void testEncryptAsymmetricWithAEAData() throws Exception {
        System.out.println("encryptAsymmetricWithAEAData");
        String plain ="Red fox Jumps over Lazy Dog";
        String open ="<<<OPEN TEXT>>>";
        
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);
        AEADCiphered encrypted = instance1.encryptWithAEAData(plain.getBytes(),open.getBytes());
        
        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);
        
        AEADPlain decrypted = instance2.decryptWithAEAData(encrypted.toBytes());
        
        String text = new String(decrypted.decrypted);
        String open_r = new String(decrypted.plain);
        String open_e = new String(encrypted.aatext);
        assertEquals(plain, text);
        assertEquals(open, open_r);
        assertEquals(open, open_e);
    }


    /**
     * Test of digest method, of class EasyCrypt.
     * @throws java.lang.Exception
     */
    @Test
    public void testDigest() throws Exception {
        System.out.println("digest");
        String msg="Test message";
        Digester instance = new JCEDigestImpl(params);
        byte[] expResult = Hex.decode("48418241a4d779508a6b98e623328a68f7f0bf27fd101bb2c89384827bfc07403fefd5855576f1824fcd7acd233541514240c2bcf0fa9732ebb8f166a7c38bdf");
        byte[] result = instance.digest(msg.getBytes());
        System.out.println(Hex.toHexString(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EasyCrypt.
     */
    @Test
    public void testSign() throws Exception {
        System.out.println("sign");

        CryptoSignature instance1 = new CryptoSignatureImpl(params);
        instance1.setKeys(khA);

        CryptoSignature instance2 = new CryptoSignatureImpl(params);
        instance2.setKeys(khB);
        
        String plain ="Red fox Jumps over Lazy Dog";
        byte[] signature = instance1.sign(plain.getBytes());
        boolean res = instance2.verify(plain.getBytes(), signature);
        assertTrue(res);
    }
    
    /**
     * Test ephemeral iv ECDH iv agreement 
     */
    @Test
    public void testECDHE() throws Exception{
        System.out.println("ECDHE keys");
        AsymCryptorDH instance1 = new AsymJCEECDHImpl(params);
        instance1.setKeys(khA);

        AsymCryptorDH instance2 = new AsymJCEECDHImpl(params);
        instance2.setKeys(khB);
        
        byte[] aliceSignedKJey = instance1.ecdheStep1();
        byte[] bobSignedKJey = instance2.ecdheStep1();
        
        byte[] sharedKeyAlice = instance1.ecdheStep2(bobSignedKJey);
        byte[] sharedKeyBob = instance2.ecdheStep2(aliceSignedKJey);
        assertArrayEquals(sharedKeyAlice, sharedKeyBob);
    }

    
}

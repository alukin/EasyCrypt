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
import ua.cn.al.easycrypt.impl.ecc.SymJCEImpl;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class SymCryptoTest extends TestBase {

    private static final String PLAIN_FILE = "testdata/out/encrypt_sym_test_plain.bin";
    private static final String KEY_FILE = "testdata/out/encrypt_sym_test_key.bin";
    private static final String OUT_FILE_ENCRYPT_SYM = "testdata/out/encrypt_sym_test.bin";
    private static final String OUT_FILE_ENCRYPT_SYM_AEAD = "testdata/out/encrypt_sym_aead_test.bin";
    private static final String OPEN_TEXT = "This is test open text. Should be visisble as is";
    private static final SecureRandom srand = new SecureRandom();
    private static final int RANDOM_BYTES_NUMBER = 4096;

    private static final CryptoParams params = CryptoConfig.createDefaultParams();
        

    @BeforeAll
    public static void setUpClass() {
        mkdirs(KEY_FILE);
        System.out.println("Preparing random plain file and random salt+key");
        //write random file of plain text
        byte[] rt = new byte[RANDOM_BYTES_NUMBER];
        srand.nextBytes(rt);
        try {
            writeToFile(ByteBuffer.wrap(rt), PLAIN_FILE);

            byte[] key = new byte[256 / 8];
            byte[] salt = new byte[4];
            srand.nextBytes(key);
            srand.nextBytes(salt);
            //write salt+key to file
            ByteBuffer skb = ByteBuffer.allocate(salt.length + key.length);
            skb.put(salt);
            skb.put(key);
            writeToFile(skb, KEY_FILE);

        } catch (IOException ex) {
            fail("Can not write: " + PLAIN_FILE);
        }
    }

    @AfterAll
    public static void tearDownClass() {
    }


    @Test
    public void testEncryptToFile() {
        System.out.println("Testing symmetric encryptio-decryption fith files");
        try {
            //read plain text file
            byte[] plain = readFromFile(PLAIN_FILE).array();

            byte[] key = new byte[256 / 8];
            byte[] salt = new byte[4];
            //read key file: salt+key
            ByteBuffer skb = readFromFile(KEY_FILE);
            skb.get(salt);
            skb.get(key);
            
            SymCryptor instance_e = new SymJCEImpl(params);
            instance_e.setSalt(salt);
            instance_e.setNonce(null); //generate random nonce
            instance_e.setKey(key);
            byte[] encrypted = instance_e.encrypt(plain);

            //write encrypted to file prefixed with explicitNounce
            writeToFile(ByteBuffer.wrap(encrypted), OUT_FILE_ENCRYPT_SYM);

            //read encrypted data file into "encrypted" byte array
            encrypted = readFromFile(OUT_FILE_ENCRYPT_SYM).array();
            
            //prepare instance for decription.            
            SymCryptor instance_d = new SymJCEImpl(params);
            instance_d.setSalt(salt);
            instance_d.setKey(key);
            //There is no need to call setSymmetricNounce() because nounce
            // is part of encrypted data (prefix of 8 bytes legnth)
            byte[] plain_decrypted = instance_d.decrypt(encrypted);
            //check that decrypted and plain arrays match
            assertArrayEquals(plain, plain_decrypted);
        } catch (IOException ex) {
            fail("Can not read: " + PLAIN_FILE);
        } catch (CryptoNotValidException ex) {
            fail("Can not encrypt:" + ex.getMessage());
        }

    }

    @Test
    public void testEncryptAEADToFile() {
        System.out.println("Testing symmetric AEAD encryption-decryption fith files");
        try {
            //read plain text file
            byte[] plain = readFromFile(PLAIN_FILE).array();

            byte[] key = new byte[256 / 8];
            byte[] salt = new byte[4];
            //read key file
            //read key file: salt+key
            ByteBuffer skb = readFromFile(KEY_FILE);
            skb.get(salt);
            skb.get(key);
            //encrypt       
            SymCryptor instance_e = new SymJCEImpl(params);
            instance_e.setSalt(salt);
            instance_e.setNonce(null); //generate random nonce
            
            instance_e.setKey(key);
            AEADCiphered encrypted = instance_e.encryptWithAEAData(plain, OPEN_TEXT.getBytes());

            //write encrypted to file prefixed with explicitNounce
            ByteBuffer wrb = ByteBuffer.wrap(encrypted.toBytes());
            writeToFile(wrb, OUT_FILE_ENCRYPT_SYM_AEAD);

            //read encrypted
            byte[] encrypted_buf = readFromFile(OUT_FILE_ENCRYPT_SYM_AEAD).array();

            SymCryptor instance_d = new SymJCEImpl(params);
            instance_d.setSalt(salt);
            instance_d.setKey(key);
            AEADPlain decrypted = instance_d.decryptWithAEAData(encrypted_buf);
            //check
            assertTrue(decrypted.hmacOk);
            assertArrayEquals(decrypted.decrypted, plain);
            assertArrayEquals(decrypted.plain, OPEN_TEXT.getBytes())
                    ;
        } catch (IOException ex) {
            fail("Can not read: " + PLAIN_FILE);
        } catch (CryptoNotValidException ex) {
            fail("Can not encrypt:" + ex.getMessage());
        }
    }

}

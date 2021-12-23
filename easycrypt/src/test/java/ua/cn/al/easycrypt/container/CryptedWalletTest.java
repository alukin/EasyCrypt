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

import ua.cn.al.easycrypt.impl.NotRandom;
import java.io.FileInputStream;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import ua.cn.al.easycrypt.TestBase;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptedWalletTest extends TestBase {
    private static String OUT_WALLET_FILE = "testdata/out/WalletTest.bin";
    private static NotRandom nr = new NotRandom();
    private static byte[] NR_SEED={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,33,24,25,26,27,28,29,30,31};
    private byte[] salt = {1,2,3,4,5,6,7,8,9,10,11,12};
    byte[] openData = "1234567890".getBytes();
            
    public CryptedWalletTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
        TestBase.mkdirs(OUT_WALLET_FILE);
        nr.setSeed(NR_SEED);
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
    
    private void addTestData(CryptedWallet w){
       int N_REC=8;
       for(Integer i = 0; i<N_REC; i++){
          DataRecord dr = new DataRecord();
          dr.alias="rec"+i.toString();
          dr.data=Integer.toString(i,16);
          dr.encoding="HEX";
          KeyRecord kr = new KeyRecord();
          kr.alias=dr.alias;
          kr.keyType=KeyTypes.OTHER;
          kr.publicKey=Long.toHexString(i);
          w.addData(dr);
          w.addKey(kr);
       }      
    }

    /**
     * Test of saveFile method, of class CryptedWallet.
     */
    @Test
    public void testSaveThenOpenFile() throws Exception {
        System.out.println("saveFThenOpenile");
        String path = OUT_WALLET_FILE;
        CryptedWallet instance = new CryptedWallet();
        instance.setOpenData(openData);
        addTestData(instance);
        byte[] key = instance.keyFromPassPhrase("123", NR_SEED);
        instance.saveFile(path, key, salt);
        CryptedWallet instance2 = new CryptedWallet();
        instance2.openFile(path, key);
        String alias = "rec1";
        String d1 = instance.getData(alias).data;
        String d2 = instance2.getData(alias).data;
        assertEquals(d1, d2);
        byte[] od1 = instance.getOpenData();
        byte[] od2 = instance2.getOpenData();
        assertArrayEquals(od1, od2);
        CryptedContainer c = new CryptedContainer();
        byte[] od3 = c.readOpenDataOnly(new FileInputStream(path));
        assertArrayEquals(od1, od3);
    }


    /**
     * Test of keyFromPassPhrase method, of class CryptedWallet.
     */
    @Test
    public void testKeyFromPassPhrase() throws Exception {
        System.out.println("keyFromPassPhrase");
        String passPhrase = "123";
        CryptedWallet instance = new CryptedWallet();
        byte[] expResult = Hex.decode("e6afb6334d9eea8ed2e4985a6ed217984cb030df73be279ee8714a69c520611a");
        byte[] result = instance.keyFromPassPhrase(passPhrase, salt);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of addData method, of class CryptedWallet.
     */
    @Test
    public void testAddThernGetData() {
        System.out.println("addData");
        DataRecord dr = null;
        CryptedWallet instance = new CryptedWallet();
        instance.addData(dr);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

    /**
     * Test of addKey method, of class CryptedWallet.
     */
    @Test
    public void testAddThenGetKey() {
        System.out.println("addKey");
        KeyRecord kr = null;
        CryptedWallet instance = new CryptedWallet();
        instance.addKey(kr);
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }

}

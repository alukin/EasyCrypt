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
import java.security.KeyPair;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
*/
public class KeyGeneratorTest {
    private static byte[] salt = {1,2,3,4,5,6,7,8,9,0};
    private static CryptoParams params = CryptoConfig.createDefaultParams();
        
    public KeyGeneratorTest() {
    }
    

    /**
     * Test of generateKeys method, of class KeyGeneratorEC.
     */
    @Test
    public void testGenerateKeys_String() throws Exception {
        //TODO: Fix test
        System.out.println("generateKeys-string");
        String secretPhrase = "1234567890";
        KeyGeneratorEC keyGenerator = new KeyGeneratorEC(params);
        KeyPair result1 = keyGenerator.generateKeys(secretPhrase,salt);
        String pubKeyString = Hex.toHexString(result1.getPublic().getEncoded());
        String pvtKeyString = Hex.toHexString(result1.getPrivate().getEncoded());
        Assertions.assertTrue(pubKeyString.startsWith("30819b301006072a8648ce3d020106052b810400230381860004"));
        Assertions.assertTrue(pvtKeyString.startsWith("3081f7020100301006072a8648ce3d020106052b810400230481"));
//        System.out.println(pubKeyString);
//        System.out.println(pvtKeyString);
    }

    /**
     * Test of deriveFromPasssPhrase method, of class KeyGeneratorEC.
     */
    @Test
    public void testDeriveFromPasssPhrase() throws Exception {
        //TODO: Fix test
        System.out.println("deriveFromSecretPhrase");
        KeyGeneratorEC keyGenerator = new KeyGeneratorEC(params);
        String secretPhrase = "1234567890 and or 0987654321";
        byte[] result = keyGenerator.deriveFromSecretPhrase(secretPhrase, salt, 256);
        String keyString = Hex.toHexString(result);
        System.out.println(keyString);
        Assertions.assertEquals("c5cfb4e7442d4cf37041cca98006cff24b804b4bfff81f73b9d6d359fce1b11b",keyString);
    }


}

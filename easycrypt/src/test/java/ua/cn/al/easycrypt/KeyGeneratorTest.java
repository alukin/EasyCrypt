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

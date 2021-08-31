/*
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
package ua.cn.al.easycrypt.identity.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author alukin@gmail.com
 */
public class HexTest {
    
    public HexTest() {
    }
    

    /**
     * Test of decode method, of class Hex.
     */
    @Test
    public void testDecode() {
        System.out.println("decode");
        String s = "abcdef01234567890";
        String expResult = "0abcdef01234567890";
        byte[] result = Hex.decode(s);
        String res = Hex.encode(result);
        assertEquals(expResult, res);
        String badChars = "0g0h0j";
        NumberFormatException assertThrows = assertThrows( NumberFormatException.class, 
                () -> {
                    Hex.decodeWithNFE(badChars);
                }
        );
    }

    /**
     * Test of encode method, of class Hex.
     */
    @Test
    public void testEncode() {
        System.out.println("encode");
        byte[] byteArray = {1,2,3,4,5,6,7,8,9,0,0xa,0xb,0xc,0xd,0xe,0xf};
        String expResult = "010203040506070809000a0b0c0d0e0f";
        String result = Hex.encode(byteArray);
        assertEquals(expResult, result);
    }

    
}

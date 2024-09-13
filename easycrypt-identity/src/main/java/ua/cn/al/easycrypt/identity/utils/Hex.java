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

package ua.cn.al.easycrypt.identity.utils;

/**
 * Hex strings and byte arrays
 * @author alukin@gmail.com
 */
public class Hex {
   
    /**
     * Decode hex string to byte array. If string contains  odd number of symbols, 
     * "0" is added at the beginning. If string contains non-HEX symbols, no exception
     * being thrown but result is obviously wrong.
     * 
     * @param s String to decode
     * @return byte array of decoded values
     */
    public static byte[] decode(String s) {
        //we have to add unsignificant zero to hanle odd number of chars
        if(s.length() % 2 != 0){
            s="0"+s;
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    /**
     *  Decodes HEX string into byte array
     * @param s HEX string to decode
     * @return array of bytes
     * @throws NumberFormatException if invalid character is present in input
     */
    public static byte[] decodeWithNFE(String s) throws NumberFormatException{
        for( char c: s.toCharArray()){
            if(Character.digit(c,16)<0 || Character.digit(c, 16)>15){
               throw new NumberFormatException("Invalid char: "+c+" in Hex string: "+ s);
            }
        }
        return decode(s);
    }
/**
 * Encode byte array as HEX string
 * @param byteArray byte array
 * @return String in HEX format
 */
    public static String encode(byte[] byteArray) {
        StringBuilder hexStringBuffer = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }
/**
 * Represent byte as hex string
 * @param num byte to encode
 * @return 2 chars of HEX representation of byte
 */
    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }
}

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

package ua.cn.al.easycrypt.dataformat;


import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Defines message format for chiphered data with IV
 * specially formated data that includes: 
 *    IV  (12 bytes), (salt+explicit nounce)
 *    unencrypted data (variable len)
 *    IV contains Salt (4 bytes) and Explicit nonce (8 bits).
 *    Salt is 0s if Explicit nonce is set. To set Salt and nounce, use setIV method
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class Ciphered {
    /**
     * Maximal size of plain and encrypted parts in sum to prevent DoS attacks
     */
    public static final int MAX_MSG_SIZE = 65536;

    public byte[] encrypted;

    private final byte[] iv; //12 bytes = 4 of salt + 8 of nonce

    public Ciphered() {
        this.iv = new byte[12]; //12 bytes, RFC 5288;  salt and explicit nounce
    }

    /**
     * Sets 8 bytes of implicit part on nounce that goes with message
     * @param en 8 bytes of explicit part of IV
     */
    public void setExplicitNonce(byte[] en){
        if(en.length!=8){
            throw new IllegalArgumentException("Nounce size must be exactly 8 bytes");
        }
        Arrays.fill(iv, (byte)0);
        System.arraycopy(en, 0, iv, 4, 8);       
    }

    
    public byte[] getExplicitNonce(){
        return Arrays.copyOfRange(iv, 4, 12);
    }

    public byte[] getIV(){
        return iv;
    }
    
    public void setIV(byte[] ivv){
       if(ivv.length != 12){
            throw new IllegalArgumentException("Nonce size must be exactly 8 bytes");
        }
       System.arraycopy(ivv, 0, iv, 0, 12);
    }

    public static Ciphered fromBytes(byte[] message){
        Ciphered res = new Ciphered();
        ByteBuffer bb = ByteBuffer.wrap(message);
        bb.get(res.iv);
        res.encrypted = new byte[message.length-res.iv.length];
        bb.get(res.encrypted);
        return res;
    }
    
    public byte[] toBytes(){
        int capacity = iv.length+encrypted.length;
        ByteBuffer bb = ByteBuffer.allocate(capacity);
        bb.put(iv);
        bb.put(encrypted); 
        return bb.array();
    }


}

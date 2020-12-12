/*
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

package ua.cn.al.easycrypt.impl;

import java.security.SecureRandom;

/**
 * Ring-like buffer for deterministic key generation
 * @author Oleksiy Lukin alukin@gmil.com
 */

public class NotRandom extends SecureRandom{
    private byte[] seed;
    int idx = 0;
    
    @Override
    public void nextBytes(byte[] bytes) {
        for(int i=0; i<bytes.length; i++){
            bytes[i]=seed[idx];
            idx++;
            if(idx>=seed.length){
                idx=0;
            }
        }
    }

    @Override
    public synchronized void setSeed(byte[] seed) {
       this.seed=seed;
    }
    
}

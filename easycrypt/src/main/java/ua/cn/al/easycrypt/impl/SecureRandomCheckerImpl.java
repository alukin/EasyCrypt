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

import ua.cn.al.easycrypt.SecureRandomChecker;
import java.security.SecureRandom;

/**
 * Check if SecureRandom is fast enough
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class SecureRandomCheckerImpl implements SecureRandomChecker {
    public static final int GET_SIZE=512;
    public static final int GET_ITERATIONS=32;

    SecureRandom srand;
    private final Long initDuration;
    private Long duration = 0L;

    public SecureRandomCheckerImpl() {
        Long begin = System.currentTimeMillis();
        srand=new SecureRandom();
        Long end = System.currentTimeMillis();
        initDuration = end-begin;
    }
    
    @Override
    public boolean check(){
       byte[] rnd = new byte[GET_SIZE];
       Long begin = System.currentTimeMillis();
       for(int i=0; i<GET_ITERATIONS;i++){
           srand.nextBytes(rnd);
       }
       Long end = System.currentTimeMillis();
       duration = end-begin;
       boolean res = (duration <SECURE_RANDOM_ACCEPTABLE_TIME_MS);
       return res;
    }

    public Long getDuration() {
        return duration;
    }
}

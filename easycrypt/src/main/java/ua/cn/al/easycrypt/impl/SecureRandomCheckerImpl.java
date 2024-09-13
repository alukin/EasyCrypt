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

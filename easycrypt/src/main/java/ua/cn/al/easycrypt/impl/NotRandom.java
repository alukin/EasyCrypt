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

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

import ua.cn.al.easycrypt.impl.SecureRandomCheckerImpl;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;


/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class SecureRandomTest {
    
    public SecureRandomTest() {
    }
    
    @Test
    public void secureRandomSpeed() {
        System.out.println("SecureRandom speed");
        SecureRandomCheckerImpl srck = new SecureRandomCheckerImpl();
        boolean res = srck.check();
        if(!res){
          System.out.println("SecureRandom speed is not enough. Please install \"haveged\" package");  
        }else{
            System.out.println("SecureRandom speed is OK."+SecureRandomCheckerImpl.GET_ITERATIONS+ " iteration took " +srck.getDuration()+" ms");
        }
        assertTrue(res);
    }
}

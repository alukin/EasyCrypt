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

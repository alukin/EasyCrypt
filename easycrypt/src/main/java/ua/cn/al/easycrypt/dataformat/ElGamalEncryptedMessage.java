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
    
package ua.cn.al.easycrypt.dataformat;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 
 */

public class ElGamalEncryptedMessage {
    private ECPoint M1;
    private BigInteger M2; 
     
    public ECPoint getM1() {
        return M1; 
    }
     
    public void setM1(ECPoint M1) {
        this.M1 = M1; 
    }
     
    public BigInteger getM2() {
        return M2; 
    }
     
    public void setM2(BigInteger M2) {
        this.M2 = M2; 
    }
    
}

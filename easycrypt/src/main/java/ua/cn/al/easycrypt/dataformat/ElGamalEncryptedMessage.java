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

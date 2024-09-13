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

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * El Gamal encryption keys holder
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 
 */

public class ElGamalKeyPair {
    
    private ECPoint publicKey;
    private BigInteger privateKey; 
     
    public ECPoint getPublicKey() {
        return publicKey; 
    }
     
    public void setPublicKey(ECPoint pubk) {
        this.publicKey = pubk; 
    }
     
    public BigInteger getPrivateKey() {
        return privateKey; 
    }

    public void setPrivateKey( BigInteger prik ) {
        privateKey = prik; 
    }
    
    public BigInteger getPrivateKeyX() {
        return publicKey.getAffineXCoord().toBigInteger();
    }

    public BigInteger getPrivateKeyY() {
        return publicKey.getAffineYCoord().toBigInteger();
    }
    
}

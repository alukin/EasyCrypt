/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
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

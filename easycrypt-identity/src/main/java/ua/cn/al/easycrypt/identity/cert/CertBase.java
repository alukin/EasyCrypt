/*
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

package ua.cn.al.easycrypt.identity.cert;

import java.security.PrivateKey;
import java.security.PublicKey;
import ua.cn.al.easycrypt.AsymCryptor;
import ua.cn.al.easycrypt.AsymKeysHolder;
import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;

/**
 * Base class for certificate and CSR
 * Also holds private key of certificate
 *
 * @author alukin@gmail.com
 */
public class CertBase {
    public static final int ACTOR_ID_LENGTH = 256/8; //32 bytes or 256 bit of Actor ID
    
    protected PublicKey pubKey = null;
    protected CryptoParams params = CryptoConfig.createDefaultParams();
    protected CryptoFactory factory = CryptoFactory.newInstance(params);
    
    public boolean checkKeys(PrivateKey pvtk) {
        boolean res = false;
        try {
            String test = "Lazy Fox jumps ofver snoopy dog";
            AsymCryptor ac = factory.getAsymCryptor();
            AsymKeysHolder kn = new AsymKeysHolder(pubKey, pvtk, pubKey);
            ac.setKeys(kn);
            byte[] enc = ac.encrypt(test.getBytes());
            byte[] dec = ac.decrypt(enc);
            String test_res = new String(dec);
            res = test.compareTo(test_res) == 0;
        } catch (CryptoNotValidException ex) {
        }
        return res;
    }

    public PublicKey getPublicKey() {
        return pubKey;
    }

}

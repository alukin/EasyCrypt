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

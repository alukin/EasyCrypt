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

import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.cn.al.easycrypt.AsymCryptor;
import ua.cn.al.easycrypt.AsymKeysHolder;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import javax.crypto.NoSuchPaddingException;

/**
 * Common part of asymmetric encryptor with integrated encryption schemaimiplementations 
 * @author Oleksiy Lukin alukin@gmail.com
 */
public abstract class AbstractAsymCryptor implements AsymCryptor {
    private static final Logger log = LoggerFactory.getLogger(AbstractAsymCryptor.class);

    protected PrivateKey privateKey;
    protected PublicKey ourPublicKey;
    protected PublicKey theirPublicKey;
    protected Cipher iesCipher;
          
    protected final CryptoParams params;

    public AbstractAsymCryptor(CryptoParams params) throws CryptoNotValidException {
        this.params = Objects.requireNonNull(params);
        String cipherSpec=params.getAsymIesCipher();
        try {
           iesCipher =  Cipher.getInstance(cipherSpec);
        }catch(NoSuchAlgorithmException ex){
            log.error("Cipher spec {} is not supported.", cipherSpec);
            throw new CryptoNotValidException("Wrong params", ex);
        }catch(NoSuchPaddingException ex){
            log.error("Padding spec {} is not supported.", cipherSpec);
            throw new CryptoNotValidException("Wrong params", ex);
        }        
    }

    public CryptoParams getParams() {
        return params;
    }
    
    /**
     * Set all required keys
     * @param keys our public and private keys, their public key
     */
    @Override
    public void setKeys(AsymKeysHolder keys){
        this.ourPublicKey = keys.getOurPublicKey();
        this.privateKey = keys.getPrivateKey();
        this.theirPublicKey = keys.getTheirPublicKey();
    }

}

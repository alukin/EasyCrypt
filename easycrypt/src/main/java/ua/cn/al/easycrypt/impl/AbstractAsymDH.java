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

import ua.cn.al.easycrypt.CryptoParams;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.cn.al.easycrypt.AsymCryptorDH;
import ua.cn.al.easycrypt.AsymKeysHolder;
import ua.cn.al.easycrypt.CryptoSignature;

/**
  *
  * @author Oleksiy Lukin alukin@gmail.com
  */
public abstract class AbstractAsymDH implements AsymCryptorDH {
    private static final Logger log = LoggerFactory.getLogger(AbstractAsymDH.class);

    protected Cipher blockCipherAsym;
    protected GCMParameterSpec gcmParameterSpecAsym;
    protected PrivateKey privateKey;
    protected PublicKey ourPublicKey;
    protected PublicKey theirPublicKey;
    protected SecretKeySpec sharedKey;
    protected KeyPair ephemeralKeys;            
    protected final CryptoParams params;
    protected final CryptoSignature signer;
    
     public AbstractAsymDH(CryptoParams params) {
        this.params = Objects.requireNonNull(params);
        signer = new CryptoSignatureImpl(params);
    } 
    
    public CryptoParams getParams(){
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
        this.signer.setKeys(keys);
        try {
            blockCipherAsym = Cipher.getInstance(params.getAsymCipher());
            calculateSharedKey();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            log.error("Can not create cipher for {} :", params.getAsymCipher(), ex);
        }        
    }    
    
    protected abstract byte[] doCalculateShared(PublicKey ourPub, PrivateKey ourPriv, PublicKey theirPub) throws NoSuchAlgorithmException, InvalidKeyException;
    
}

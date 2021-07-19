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

package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.ExtCSR;
import ua.cn.al.easycrypt.identity.cert.ExtCert;
import ua.cn.al.easycrypt.identity.cert.CertAndKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import lombok.extern.slf4j.Slf4j;
import ua.cn.al.easycrypt.AsymKeysHolder;
import ua.cn.al.easycrypt.CryptoFactory;
import ua.cn.al.easycrypt.CryptoFactoryHelper;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoSignature;

/**
 *
 * @author alukin@gmail.com
 */
@Slf4j
public class ThisActorIdHandlerImpl implements ThisActorIdHandler {
    ExtCert myCert;
    private PrivateKey pvtKey;
    CryptoFactory cryptoFactory;
    
    public ThisActorIdHandlerImpl() {
        this(null, null);
    }

    public ThisActorIdHandlerImpl(ExtCert myCert, PrivateKey pvtKey) {
        this.myCert = myCert;
        this.pvtKey = pvtKey;
        if(myCert==null){
            cryptoFactory = CryptoFactory.newInstance();
        }else{
            cryptoFactory = CryptoFactoryHelper.createFactory(myCert.getCertificate());
        }
    }
    
        
    @Override
    public byte[] getActorId() {
       return myCert.getActorId();
    }

    @Override
    public ExtCert getExtCert() {
        return myCert;
    }
    
    @Override
    public byte[] sign(byte[] message) {
        byte[] res = null;
        CryptoSignature signer = cryptoFactory.getCryptoSiganture();
        PublicKey pubKey = myCert.getPublicKey();        
        AsymKeysHolder kh = new AsymKeysHolder(pubKey, pvtKey, null);
        signer.setKeys(kh);
        try {
            res = signer.sign(message);
        } catch (CryptoNotValidException ex) {
            log.error("Can not sign message with my node private key", ex);
        }
        return res;
    }

    @Override
    public  CertAndKey generateSelfSignedCert(ExtCSR csr) {
        CertAndKey certAndKey = csr.getSelfSignedX509PEM();
        pvtKey = certAndKey.getPvtKey();
        myCert = new ExtCert(certAndKey.getCert());
        return certAndKey;
    }
    
}

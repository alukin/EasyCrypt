/*
 * Copyright (C) 2021 Oleksiy Lukin 
 *
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
package ua.cn.al.easycrypt.identity.cert;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.security.auth.DestroyFailedException;

/**
 * X509XCertificate and private key Holder/loader/writer
 * @author alukin@gmail.com
 */
public class CertAndKey {
    private X509Certificate cert;
    private PrivateKey pvtKey;

    public CertAndKey() {
    }

    public CertAndKey(X509Certificate cert, PrivateKey pvtKey) {
        this.cert = cert;
        this.pvtKey = pvtKey;
    }
    
    public void destroy(){
        try {
            pvtKey.destroy();
        } catch (DestroyFailedException ex) {            
        }
    }

    public X509Certificate getCert() {
        return cert;
    }

    public PrivateKey getPvtKey() {
        return pvtKey;
    }
    
    public boolean loadCert(Path p){
        return false;
    }
    
    public boolean loadKey(Path p, String password){
        return false;
    }
    
    public boolean saveCert(Path p){
        return false;
    }
    
    public boolean saveKey(Path p, String password){
        return false;
    }
    
    public String getCertPEM(){
        return null;
    }
    
    public String getKeyPEM(){
        return null;
    }
}

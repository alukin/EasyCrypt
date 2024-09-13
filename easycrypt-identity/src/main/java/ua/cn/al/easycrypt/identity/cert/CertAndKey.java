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

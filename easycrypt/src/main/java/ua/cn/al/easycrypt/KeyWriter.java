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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface KeyWriter {

    boolean addX509CertToPKCS12(X509Certificate certificate, String pathToJKS, String alias, String jksPassword);

    byte[] serializePrivateKey(PrivateKey privateKey);

    byte[] serializePublicKey(PublicKey publicKey);

    boolean writeCertificateRequestPEM(String path, PKCS10CertificationRequest cr) throws IOException;

    boolean writePvtKeyPEM(String path, PrivateKey key) throws IOException;
    
    
    String getPvtKeyPEM(PrivateKey key) throws IOException;
    
    boolean writePvtKeyPKSC8(String path, PrivateKey key, String password)  throws IOException;
    
    boolean writePvtKeyPKCS12(String path) throws IOException;

    boolean writeX509CertificatePEM(String path, X509Certificate certificate) throws IOException;
    
    String  getX509CertificatePEM(X509Certificate certificate) throws IOException;

    String getCertificateRequestPEM(PKCS10CertificationRequest cr)  throws IOException;
    
}
